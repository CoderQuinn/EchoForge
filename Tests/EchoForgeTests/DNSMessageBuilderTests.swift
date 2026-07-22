//
//  DNSMessageBuilderTests.swift
//  EchoForgeTests
//
//  Wire-format unit tests for DNS response/query builders.
//

import ForgeBase
import Foundation
import Network
import XCTest

@testable import EchoForge

final class DNSMessageBuilderTests: XCTestCase {
    private func makeQuery(id: UInt16, domain: String, type: DNSType) -> DNSQuery {
        DNSQuery(
            header: DNSHeader(
                id: id,
                flags: 0x0100,
                qdCount: 1,
                anCount: 0,
                nsCount: 0,
                arCount: 0
            ),
            question: DNSQuestion(name: domain, type: type, qclass: .internet)
        )
    }

    private func readU16(_ data: Data, at offset: Int) -> UInt16 {
        (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
    }

    func testBuildAQueryRoundTripsThroughParser() throws {
        let data = DNSMessageBuilder.buildAQuery(domain: "builder.example")
        let query = try MinimalDNSParser.parseQuery(FBDataPacketBuffer(data))

        XCTAssertEqual(query.question.name, "builder.example")
        XCTAssertEqual(query.question.type, .a)
        XCTAssertFalse(query.header.isResponse)
        XCTAssertEqual(query.header.qdCount, 1)
    }

    func testBuildAResponseWireLayout() throws {
        let query = makeQuery(id: 0x4242, domain: "a.example", type: .a)
        let fake = IPv4Address("198.18.1.50")!
        let data = DNSMessageBuilder.buildAResponse(query: query, fakeIPv4: fake, ttl: 300)

        XCTAssertGreaterThanOrEqual(data.count, 12)
        XCTAssertEqual(readU16(data, at: 0), 0x4242)
        let flags = readU16(data, at: 2)
        XCTAssertTrue((flags & 0x8000) != 0, "QR")
        XCTAssertEqual(readU16(data, at: 4), 1, "QDCOUNT")
        XCTAssertEqual(readU16(data, at: 6), 1, "ANCOUNT")

        let (ips, ttls) = MinimalDNSParser.extractAnswers(from: FBDataPacketBuffer(data))
        XCTAssertEqual(ips, [fake])
        XCTAssertEqual(ttls, [300])
    }

    func testBuildPTRResponseContainsDomainLabels() {
        let query = makeQuery(
            id: 0x9999,
            domain: "10.0.18.198.in-addr.arpa",
            type: .ptr
        )
        let data = DNSMessageBuilder.builePTRResponse(
            query: query,
            ptrDomain: "ptr.example.com",
            ttl: 60
        )

        XCTAssertEqual(readU16(data, at: 0), 0x9999)
        XCTAssertEqual(readU16(data, at: 6), 1, "ANCOUNT")
        // RDATA should contain the ptr domain bytes
        let haystack = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(haystack.contains("ptr") || data.contains(Data("ptr".utf8)))
        XCTAssertTrue(data.contains(Data("example".utf8)))
    }

    func testBuildRefuseResponseSetsRcode() {
        let q = DNSQuestion(name: "r.example", type: .a, qclass: .internet).materialize()
        let data = DNSMessageBuilder.buildRefuseResponse(
            id: 0x1010,
            rcode: .refused,
            originalQuestion: q
        )

        XCTAssertEqual(readU16(data, at: 0), 0x1010)
        let flags = readU16(data, at: 2)
        XCTAssertTrue((flags & 0x8000) != 0)
        XCTAssertEqual(flags & 0x000F, UInt16(DNSReturnStatus.refused.rawValue))
        XCTAssertEqual(readU16(data, at: 4), 1, "QDCOUNT when question present")
        XCTAssertEqual(readU16(data, at: 6), 0, "ANCOUNT")
    }

    func testBuildRefuseWithEmptyQuestionHasZeroQDCount() {
        let data = DNSMessageBuilder.buildRefuseResponse(
            id: 1,
            rcode: .formatError,
            originalQuestion: Data()
        )
        XCTAssertEqual(readU16(data, at: 4), 0)
        XCTAssertEqual(readU16(data, at: 2) & 0x000F, 1) // FORMERR
    }

    func testBuildNoAnswerIsSuccessWithZeroAnswers() {
        let q = DNSQuestion(name: "aaaa.example", type: .aaaa, qclass: .internet).materialize()
        let data = DNSMessageBuilder.buildNoAnswerResponse(id: 7, originalQuestion: q)
        XCTAssertEqual(readU16(data, at: 2) & 0x000F, 0)
        XCTAssertEqual(readU16(data, at: 6), 0)
    }

    func testBuildServFailResponse() {
        let data = DNSMessageBuilder.buildServFailResponse(id: 3, originalQuestion: Data())
        XCTAssertEqual(readU16(data, at: 2) & 0x000F, 2)
    }
}
