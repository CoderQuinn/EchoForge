//
//  MinimalDNSParserTests.swift
//  EchoForgeTests
//
//  Unit + regression coverage for slow-path RFC1035 parsing.
//

import ForgeBase
import Foundation
import Network
import XCTest

@testable import EchoForge

final class MinimalDNSParserTests: XCTestCase {
    // MARK: - Helpers

    private func buildQuery(
        id: UInt16 = 0x1234,
        domain: String,
        type: DNSType = .a,
        qclass: DNSClass = .internet,
        flags: UInt16 = 0x0100,
        qdCount: UInt16 = 1
    ) -> Data {
        var writer = FBPacketBufferWriter(capacity: 128)
        writer.writeUInt16(id)
        writer.writeUInt16(flags)
        writer.writeUInt16(qdCount)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.name(domain)
        writer.writeUInt16(type.rawValue)
        writer.writeUInt16(qclass.rawValue)
        return writer.data
    }

    // MARK: - parseQuery

    func testParseValidAQuery() throws {
        let data = buildQuery(domain: "example.com")
        let query = try MinimalDNSParser.parseQuery(FBDataPacketBuffer(data))

        XCTAssertEqual(query.header.id, 0x1234)
        XCTAssertFalse(query.header.isResponse)
        XCTAssertEqual(query.question.name, "example.com")
        XCTAssertEqual(query.question.type, .a)
        XCTAssertEqual(query.question.qclass, .internet)
    }

    func testParseRejectsTruncatedHeader() {
        let data = Data(repeating: 0, count: 11)
        XCTAssertThrowsError(try MinimalDNSParser.parseQuery(FBDataPacketBuffer(data))) { error in
            XCTAssertEqual(error as? ParseError, .truncated)
        }
    }

    func testParseRejectsResponsePacket() {
        var writer = FBPacketBufferWriter()
        writer.writeUInt16(1)
        writer.writeUInt16(0x8000) // QR=1
        writer.writeUInt16(1)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.name("a.com")
        writer.writeUInt16(DNSType.a.rawValue)
        writer.writeUInt16(DNSClass.internet.rawValue)

        XCTAssertThrowsError(try MinimalDNSParser.parseQuery(FBDataPacketBuffer(writer.data))) {
            error in
            XCTAssertEqual(error as? ParseError, .notQuery)
        }
    }

    func testParseRejectsZeroQuestions() {
        var writer = FBPacketBufferWriter()
        writer.writeUInt16(1)
        writer.writeUInt16(0x0100)
        writer.writeUInt16(0) // QDCOUNT=0
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)

        XCTAssertThrowsError(try MinimalDNSParser.parseQuery(FBDataPacketBuffer(writer.data))) {
            error in
            XCTAssertEqual(error as? ParseError, .noQuestions)
        }
    }

    func testParseRejectsLabelTooLong() {
        var writer = FBPacketBufferWriter()
        writer.writeUInt16(1)
        writer.writeUInt16(0x0100)
        writer.writeUInt16(1)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt8(64) // > 63
        writer.raw(Data(repeating: UInt8(ascii: "a"), count: 64))
        writer.writeUInt8(0)
        writer.writeUInt16(DNSType.a.rawValue)
        writer.writeUInt16(DNSClass.internet.rawValue)

        XCTAssertThrowsError(try MinimalDNSParser.parseQuery(FBDataPacketBuffer(writer.data))) {
            error in
            XCTAssertEqual(error as? ParseError, .invalidName)
        }
    }

    // MARK: - Compression / pointer regressions

    /// Answer NAME compression (pointer to question) must round-trip through extractAnswers.
    func testExtractAnswersResolvesCompressionPointerToQuestion() throws {
        let queryData = buildQuery(domain: "compress.example")
        let query = try MinimalDNSParser.parseQuery(FBDataPacketBuffer(queryData))
        let fake = IPv4Address("198.18.9.9")!
        let response = DNSMessageBuilder.buildAResponse(query: query, fakeIPv4: fake, ttl: 45)

        XCTAssertTrue(
            response.contains(Data([0xC0])),
            "expected compression pointer in answer"
        )

        let (ips, ttls) = MinimalDNSParser.extractAnswers(from: FBDataPacketBuffer(response))
        XCTAssertEqual(ips, [fake])
        XCTAssertEqual(ttls, [45])
    }

    func testParseRejectsPointerLoop() {
        var writer = FBPacketBufferWriter()
        writer.writeUInt16(1)
        writer.writeUInt16(0x0100)
        writer.writeUInt16(1)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        // offset 12: pointer to itself
        writer.writeUInt8(0xC0)
        writer.writeUInt8(12)

        XCTAssertThrowsError(try MinimalDNSParser.parseQuery(FBDataPacketBuffer(writer.data))) {
            error in
            XCTAssertEqual(error as? ParseError, .pointerLoop)
        }
    }

    func testParseRejectsPointerOutOfBounds() {
        var writer = FBPacketBufferWriter()
        writer.writeUInt16(1)
        writer.writeUInt16(0x0100)
        writer.writeUInt16(1)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt8(0xC0)
        writer.writeUInt8(0xFF)

        XCTAssertThrowsError(try MinimalDNSParser.parseQuery(FBDataPacketBuffer(writer.data))) {
            error in
            XCTAssertEqual(error as? ParseError, .truncated)
        }
    }

    func testParseRejectsTwoPointerCycle() {
        var writer = FBPacketBufferWriter()
        writer.writeUInt16(1)
        writer.writeUInt16(0x0100)
        writer.writeUInt16(1)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        // offset 12 → 14, offset 14 → 12
        writer.writeUInt8(0xC0)
        writer.writeUInt8(14)
        writer.writeUInt8(0xC0)
        writer.writeUInt8(12)

        XCTAssertThrowsError(try MinimalDNSParser.parseQuery(FBDataPacketBuffer(writer.data))) {
            error in
            XCTAssertEqual(error as? ParseError, .pointerLoop)
        }
    }

    // MARK: - extractAnswers

    func testExtractAnswersFromBuiltAResponse() throws {
        let queryData = buildQuery(domain: "a.example")
        let query = try MinimalDNSParser.parseQuery(FBDataPacketBuffer(queryData))
        let fake = IPv4Address("198.18.0.10")!
        let response = DNSMessageBuilder.buildAResponse(query: query, fakeIPv4: fake, ttl: 120)

        let (ips, ttls) = MinimalDNSParser.extractAnswers(from: FBDataPacketBuffer(response))
        XCTAssertEqual(ips, [fake])
        XCTAssertEqual(ttls, [120])
    }

    func testExtractAnswersIgnoresNonResponse() {
        let query = buildQuery(domain: "q.example")
        let (ips, ttls) = MinimalDNSParser.extractAnswers(from: FBDataPacketBuffer(query))
        XCTAssertTrue(ips.isEmpty)
        XCTAssertTrue(ttls.isEmpty)
    }

    func testExtractAnswersIgnoresNonZeroRcode() throws {
        let queryData = buildQuery(domain: "fail.example")
        let query = try MinimalDNSParser.parseQuery(FBDataPacketBuffer(queryData))
        let qWire = query.question.materialize()
        let refuse = DNSMessageBuilder.buildRefuseResponse(
            id: query.header.id,
            rcode: .serverFailure,
            originalQuestion: qWire
        )
        let (ips, _) = MinimalDNSParser.extractAnswers(from: FBDataPacketBuffer(refuse))
        XCTAssertTrue(ips.isEmpty)
    }

    func testExtractAnswersTruncatedHeaderReturnsEmpty() {
        let (ips, ttls) = MinimalDNSParser.extractAnswers(from: FBDataPacketBuffer(Data([0, 1, 2])))
        XCTAssertTrue(ips.isEmpty)
        XCTAssertTrue(ttls.isEmpty)
    }

    func testExtractAnswersSkipsNonARecords() {
        var writer = FBPacketBufferWriter()
        writer.writeUInt16(0x1111)
        writer.writeUInt16(0x8180) // QR + RD + RA
        writer.writeUInt16(1) // QD
        writer.writeUInt16(2) // AN
        writer.writeUInt16(0)
        writer.writeUInt16(0)

        let nameOffset = writer.position
        writer.name("multi.example")
        writer.writeUInt16(DNSType.a.rawValue)
        writer.writeUInt16(DNSClass.internet.rawValue)

        // Non-A answer (TYPE=5 CNAME), rdlength=2 dummy
        writer.pointer(to: nameOffset)
        writer.writeUInt16(5) // CNAME
        writer.writeUInt16(DNSClass.internet.rawValue)
        writer.writeUInt32(60)
        writer.writeUInt16(2)
        writer.writeUInt8(0xC0)
        writer.writeUInt8(UInt8(nameOffset))

        // A answer
        writer.pointer(to: nameOffset)
        writer.writeUInt16(DNSType.a.rawValue)
        writer.writeUInt16(DNSClass.internet.rawValue)
        writer.writeUInt32(90)
        writer.writeUInt16(4)
        writer.writeUInt8(1)
        writer.writeUInt8(2)
        writer.writeUInt8(3)
        writer.writeUInt8(4)

        let (ips, ttls) = MinimalDNSParser.extractAnswers(from: FBDataPacketBuffer(writer.data))
        XCTAssertEqual(ips.count, 1)
        XCTAssertEqual(ips.first, IPv4Address("1.2.3.4"))
        XCTAssertEqual(ttls, [90])
    }
}
