//
//  DNSPolicyEngineTests.swift
//  EchoForgeTests
//
//  Unit tests for fast-path policy routing (and dead `.refuse` surface).
//

import ForgeBase
import Foundation
import XCTest

@testable import EchoForge

final class DNSPolicyEngineTests: XCTestCase {
    private func sniff(_ data: Data) -> SniffedDNSQuery? {
        DNSFastSniffer.sniffQuery(FBDataPacketBuffer(data))
    }

    private func buildQuery(domain: String, type: UInt16) -> Data {
        var writer = FBPacketBufferWriter()
        writer.writeUInt16(0x1111)
        writer.writeUInt16(0x0100)
        writer.writeUInt16(1)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.name(domain)
        writer.writeUInt16(type)
        writer.writeUInt16(1)
        return writer.data
    }

    func testNilFastFallsBackToLocal() {
        if case .handleLocally = DNSPolicyEngine.decide(nil) {
            // expected
        } else {
            XCTFail("nil sniff should handleLocally for slow-path recovery")
        }
    }

    func testAAndAAAAAndPTRAreLocal() {
        for type: UInt16 in [1, 28, 12] {
            let fast = sniff(buildQuery(domain: "p.example", type: type))
            XCTAssertNotNil(fast)
            if case .handleLocally = DNSPolicyEngine.decide(fast) {
                continue
            }
            XCTFail("qtype \(type) should be handleLocally")
        }
    }

    func testAnyTypePassthrough() {
        let fast = sniff(buildQuery(domain: "u.example", type: DNSType.any.rawValue))
        XCTAssertNotNil(fast)
        if case .passthrough = DNSPolicyEngine.decide(fast) {
            return
        }
        XCTFail("ANY should passthrough")
    }

    /// MX/TXT are outside `DNSType` — FastSniffer returns nil, policy falls back to local
    /// (slow path then forwards unknown types upstream). Documents the two-stage gap.
    func testUnknownWireTypesSniffNilThenLocal() {
        for type: UInt16 in [15, 16] { // MX, TXT
            let fast = sniff(buildQuery(domain: "u.example", type: type))
            XCTAssertNil(fast, "qtype \(type) is not in DNSType enum")
            if case .handleLocally = DNSPolicyEngine.decide(fast) {
                continue
            }
            XCTFail("nil sniff must handleLocally for slow-path recovery")
        }
    }

    /// Regression: engine never emits `.refuse` today — refuse branch in DNSService is dead.
    /// Lock this so a future ForgeRuleCore adapter can intentionally change it.
    func testPolicyNeverReturnsRefuseForSniffableQueries() {
        let types: [UInt16] = [
            DNSType.a.rawValue,
            DNSType.ptr.rawValue,
            DNSType.aaaa.rawValue,
            DNSType.any.rawValue,
        ]
        for type in types {
            let decision = DNSPolicyEngine.decide(sniff(buildQuery(domain: "x.example", type: type)))
            if case .refuse = decision {
                XCTFail("unexpected refuse for qtype \(type)")
            }
        }
        if case .refuse = DNSPolicyEngine.decide(nil) {
            XCTFail("nil sniff should not refuse")
        }
    }
}
