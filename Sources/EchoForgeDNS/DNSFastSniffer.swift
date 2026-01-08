//
//  DNSFastSniffer.swift
//  EchoForgeDNS
//
//  Created by MagicianQuinn on 2026/1/3.
//
//  Fast-path validation + minimal question extraction.
//  - "Is this likely a DNS query?"
//  - Extract txid, qtype, qname for policy routing.
//
//  Uses MinimalDNSParser internally but wraps it with cheap guards.
//

import Foundation

public enum DNSFastSniffer {
    public struct Result {
        public let id: UInt16
        public let qname: String
        public let qtype: DNSType
        public let questionRaw: Data // raw bytes of Question section (QNAME+QTYPE+QCLASS)
    }

    public static func sniffQuery(_ payload: Data) -> Result? {
        guard payload.count >= 12 else {
            return nil
        }

        let flags = (UInt16(payload[2]) << 8) | UInt16(payload[3])
        if (flags & 0x8000) != 0 {
            return nil
        }

        let qd = (UInt16(payload[4]) << 8) | UInt16(payload[5])
        guard qd >= 1 else {
            return nil
        }

        guard let query = try? MinimalDNSParser.parse(payload) else {
            return nil
        }

        guard let questionRaw = extractQuestionRaw(payload) else {
            return nil
        }

        return Result(
            id: query.header.id,
            qname: query.question.name,
            qtype: query.question.type,
            questionRaw: questionRaw
        )
    }

    private static func extractQuestionRaw(_ payload: Data) -> Data? {
        var i = 12
        guard i < payload.count else { return nil }

        while true {
            guard i < payload.count else { return nil }
            let len = Int(payload[i])
            i += 1
            if len == 0 { break }
            guard i + len <= payload.count else { return nil }
            i += len
        }

        // QTYPE(2)+QCLASS(2)
        guard i + 4 <= payload.count else { return nil }
        let end = i + 4
        return payload.subdata(in: 12 ..< end)
    }
}
