//
//  DNSFastSnifferTests.swift
//  EchoForge
//
//  Created by Copilot on 2026/01/14.
//

import ForgeBase
import Foundation
import XCTest

@testable import EchoForge

final class DNSFastSnifferTests: XCTestCase {
    // MARK: - Helper Methods

    /// Build a valid DNS query packet
    private func buildValidQuery(
        id: UInt16 = 0x1234,
        flags: UInt16 = 0x0100,
        domain: String = "example.com",
        qtype: DNSType = .a
    ) -> Data {
        var writer = FBPacketBufferWriter()

        // Header
        writer.writeUInt16(id)
        writer.writeUInt16(flags)
        writer.writeUInt16(1) // QDCOUNT = 1
        writer.writeUInt16(0) // ANCOUNT
        writer.writeUInt16(0) // NSCOUNT
        writer.writeUInt16(0) // ARCOUNT

        // Question
        writer.name(domain)
        writer.writeUInt16(qtype.rawValue)
        writer.writeUInt16(DNSClass.internet.rawValue)

        return writer.data
    }

    /// Build a query with compression pointer in QNAME
    private func buildQueryWithCompressionPointer() -> Data {
        var writer = FBPacketBufferWriter()

        // Header
        writer.writeUInt16(0x1234)
        writer.writeUInt16(0x0100) // Query flags
        writer.writeUInt16(1) // QDCOUNT = 1
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)

        // Question with compression pointer
        // Instead of writing a proper domain name, write a compression pointer (0xC0 prefix)
        writer.writeUInt8(0xC0) // Compression pointer prefix
        writer.writeUInt8(0x0C) // Offset
        writer.writeUInt16(DNSType.a.rawValue)
        writer.writeUInt16(DNSClass.internet.rawValue)

        return writer.data
    }

    /// Build a query with multiple questions
    private func buildQueryWithMultipleQuestions() -> Data {
        var writer = FBPacketBufferWriter()

        // Header
        writer.writeUInt16(0x1234)
        writer.writeUInt16(0x0100)
        writer.writeUInt16(2) // QDCOUNT = 2 (multiple questions)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)

        // First question
        writer.name("example.com")
        writer.writeUInt16(DNSType.a.rawValue)
        writer.writeUInt16(DNSClass.internet.rawValue)

        // Second question
        writer.name("example.org")
        writer.writeUInt16(DNSType.aaaa.rawValue)
        writer.writeUInt16(DNSClass.internet.rawValue)

        return writer.data
    }

    /// Build a query with a domain name that has maximum label length
    private func buildQueryWithMaxLabelLength() -> Data {
        // Maximum label length is 63 bytes
        let maxLabel = String(repeating: "a", count: 63)
        let domain = "\(maxLabel).com"
        return buildValidQuery(domain: domain)
    }

    /// Build a query with a very long domain name (multiple max-length labels)
    private func buildQueryWithLongDomain() -> Data {
        let maxLabel = String(repeating: "a", count: 63)
        // Create a domain with multiple 63-char labels
        let domain = "\(maxLabel).\(maxLabel).\(maxLabel).com"
        return buildValidQuery(domain: domain)
    }

    // MARK: - Valid Query Tests

    func testSniffValidAQuery() {
        let data = buildValidQuery(id: 0x1234, domain: "example.com", qtype: .a)
        let buffer = FBDataPacketBuffer(data)

        let result = DNSFastSniffer.sniffQuery(buffer)

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.id, 0x1234)
        XCTAssertEqual(result?.qtype, .a)
        XCTAssertEqual(result?.qclass, .internet)
    }

    func testSniffValidAAAAQuery() {
        let data = buildValidQuery(id: 0x5678, domain: "ipv6.example.com", qtype: .aaaa)
        let buffer = FBDataPacketBuffer(data)

        let result = DNSFastSniffer.sniffQuery(buffer)

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.id, 0x5678)
        XCTAssertEqual(result?.qtype, .aaaa)
        XCTAssertEqual(result?.qclass, .internet)
    }

    func testSniffValidPTRQuery() {
        let data = buildValidQuery(id: 0xABCD, domain: "1.0.0.127.in-addr.arpa", qtype: .ptr)
        let buffer = FBDataPacketBuffer(data)

        let result = DNSFastSniffer.sniffQuery(buffer)

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.id, 0xABCD)
        XCTAssertEqual(result?.qtype, .ptr)
        XCTAssertEqual(result?.qclass, .internet)
    }

    // MARK: - Compression Pointer Rejection Tests

    func testRejectsCompressionPointer() {
        let data = buildQueryWithCompressionPointer()
        let buffer = FBDataPacketBuffer(data)

        let result = DNSFastSniffer.sniffQuery(buffer)

        XCTAssertNil(result, "Should reject queries with compression pointers")
    }

    // MARK: - Multiple Questions Rejection Tests

    func testRejectsMultipleQuestions() {
        let data = buildQueryWithMultipleQuestions()
        let buffer = FBDataPacketBuffer(data)

        let result = DNSFastSniffer.sniffQuery(buffer)

        XCTAssertNil(result, "Should reject queries with multiple questions")
    }

    func testRejectsZeroQuestions() {
        var writer = FBPacketBufferWriter()

        // Header with QDCOUNT = 0
        writer.writeUInt16(0x1234)
        writer.writeUInt16(0x0100)
        writer.writeUInt16(0) // QDCOUNT = 0
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)

        let buffer = FBDataPacketBuffer(writer.data)
        let result = DNSFastSniffer.sniffQuery(buffer)

        XCTAssertNil(result, "Should reject queries with zero questions")
    }

    // MARK: - Truncated Packet Tests

    func testRejectsTruncatedHeader() {
        // Header should be 12 bytes, provide only 10
        let data = Data(repeating: 0, count: 10)
        let buffer = FBDataPacketBuffer(data)

        let result = DNSFastSniffer.sniffQuery(buffer)

        XCTAssertNil(result, "Should reject packets with truncated header")
    }

    func testRejectsTruncatedQuestion() {
        var writer = FBPacketBufferWriter()

        // Valid header
        writer.writeUInt16(0x1234)
        writer.writeUInt16(0x0100)
        writer.writeUInt16(1) // QDCOUNT = 1
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)

        // Start writing domain but truncate it
        writer.writeUInt8(7) // Length byte for "example"
        writer.raw(Data("exa".utf8)) // Only write 3 bytes instead of 7

        let buffer = FBDataPacketBuffer(writer.data)
        let result = DNSFastSniffer.sniffQuery(buffer)

        XCTAssertNil(result, "Should reject queries with truncated question")
    }

    func testRejectsMissingQTypeQClass() {
        var writer = FBPacketBufferWriter()

        // Valid header
        writer.writeUInt16(0x1234)
        writer.writeUInt16(0x0100)
        writer.writeUInt16(1) // QDCOUNT = 1
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)

        // Valid domain name but no QTYPE/QCLASS
        writer.name("example.com")
        // Don't write QTYPE and QCLASS

        let buffer = FBDataPacketBuffer(writer.data)
        let result = DNSFastSniffer.sniffQuery(buffer)

        XCTAssertNil(result, "Should reject queries missing QTYPE/QCLASS")
    }

    // MARK: - Edge Case Tests

    func testMaxLabelLength() {
        let data = buildQueryWithMaxLabelLength()
        let buffer = FBDataPacketBuffer(data)

        let result = DNSFastSniffer.sniffQuery(buffer)

        XCTAssertNotNil(result, "Should accept queries with 63-character labels")
        XCTAssertEqual(result?.qtype, .a)
    }

    func testLongDomainName() {
        let data = buildQueryWithLongDomain()
        let buffer = FBDataPacketBuffer(data)

        let result = DNSFastSniffer.sniffQuery(buffer)

        XCTAssertNotNil(result, "Should accept queries with long domain names")
        XCTAssertEqual(result?.qtype, .a)
    }

    func testRejectsInvalidLabelLength() {
        var writer = FBPacketBufferWriter()

        // Valid header
        writer.writeUInt16(0x1234)
        writer.writeUInt16(0x0100)
        writer.writeUInt16(1)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)

        // Write a label with length 64 (invalid, max is 63)
        writer.writeUInt8(64)
        writer.raw(Data(repeating: 0x61, count: 64)) // 64 'a' characters
        writer.writeUInt8(0) // Null terminator
        writer.writeUInt16(DNSType.a.rawValue)
        writer.writeUInt16(DNSClass.internet.rawValue)

        let buffer = FBDataPacketBuffer(writer.data)
        let result = DNSFastSniffer.sniffQuery(buffer)

        // Labels longer than 63 bytes are invalid per RFC 1035 and should be rejected.
        XCTAssertNil(result, "Should reject labels exceeding 63 bytes")
    }

    func testEmptyDomain() {
        var writer = FBPacketBufferWriter()

        // Valid header
        writer.writeUInt16(0x1234)
        writer.writeUInt16(0x0100)
        writer.writeUInt16(1)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)

        // Empty domain (just null terminator)
        writer.writeUInt8(0)
        writer.writeUInt16(DNSType.a.rawValue)
        writer.writeUInt16(DNSClass.internet.rawValue)

        let buffer = FBDataPacketBuffer(writer.data)
        let result = DNSFastSniffer.sniffQuery(buffer)

        XCTAssertNotNil(result, "Should accept empty domain (root domain)")
        XCTAssertEqual(result?.qtype, .a)
    }

    // MARK: - Response Rejection Tests

    func testRejectsResponsePacket() {
        // Build a response (QR bit set)
        var writer = FBPacketBufferWriter()

        writer.writeUInt16(0x1234)
        writer.writeUInt16(0x8100) // QR=1 (response), RD=1
        writer.writeUInt16(1)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)

        writer.name("example.com")
        writer.writeUInt16(DNSType.a.rawValue)
        writer.writeUInt16(DNSClass.internet.rawValue)

        let buffer = FBDataPacketBuffer(writer.data)
        let result = DNSFastSniffer.sniffQuery(buffer)

        XCTAssertNil(result, "Should reject response packets (QR=1)")
    }

    // MARK: - Invalid Type/Class Tests

    func testRejectsInvalidQType() {
        var writer = FBPacketBufferWriter()

        writer.writeUInt16(0x1234)
        writer.writeUInt16(0x0100)
        writer.writeUInt16(1)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)

        writer.name("example.com")
        writer.writeUInt16(999) // Invalid QTYPE
        writer.writeUInt16(DNSClass.internet.rawValue)

        let buffer = FBDataPacketBuffer(writer.data)
        let result = DNSFastSniffer.sniffQuery(buffer)

        XCTAssertNil(result, "Should reject queries with invalid QTYPE")
    }

    func testRejectsNonInternetClass() {
        var writer = FBPacketBufferWriter()

        writer.writeUInt16(0x1234)
        writer.writeUInt16(0x0100)
        writer.writeUInt16(1)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)

        writer.name("example.com")
        writer.writeUInt16(DNSType.a.rawValue)
        writer.writeUInt16(3) // Class CHAOS (not internet)

        let buffer = FBDataPacketBuffer(writer.data)
        let result = DNSFastSniffer.sniffQuery(buffer)

        XCTAssertNil(result, "Should reject queries with non-Internet class")
    }

    // MARK: - Question Buffer Tests

    func testQuestionBufferContainsValidData() {
        let data = buildValidQuery(domain: "test.example.com", qtype: .a)
        let buffer = FBDataPacketBuffer(data)

        guard let result = DNSFastSniffer.sniffQuery(buffer) else {
            XCTFail("Failed to sniff valid query")
            return
        }

        // Question buffer should contain QNAME + QTYPE + QCLASS
        // QNAME for "test.example.com" encoded as:
        // [4]test[7]example[3]com[0] = 1+4+1+7+1+3+1 = 18 bytes
        // QTYPE = 2 bytes
        // QCLASS = 2 bytes
        // Total = 22 bytes
        XCTAssertEqual(result.question.readableBytes, 22)
    }
}
