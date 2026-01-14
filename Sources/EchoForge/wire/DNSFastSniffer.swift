//
//  DNSFastSniffer.swift
//  NetForge
//
//  Created by MagicianQuinn on 2026/1/13.
//

import ForgeBase

public struct SniffedDNSQuery {
    public let id: UInt16
    public let flags: UInt16
    public let qtype: DNSType
    public let qclass: DNSClass

    /// Question slice = [QNAME...0][QTYPE][QCLASS]
    public let question: FBPacketBuffer
}

public enum DNSFastSniffer {
    /// QNAME fast skip. Rejects compression pointers (0b11xxxxxx).
    @inline(__always)
    private static func skipQNameNoPointer(buffer: FBPacketBuffer, offset: inout Int) -> Bool {
        // [length][label bytes][length][label bytes]...[0]
        var len = 0
        repeat {
            guard let len8 = buffer.loadUInt8(at: offset) else { return false }
            len = Int(len8)
            offset += 1

            // reject compression pointer or any non-standard label encoding
            if (len & 0xC0) != 0 {
                return false
            }

            // skip label bytes(if any)
            if len > 0 {
                guard offset + len <= buffer.readableBytes else { return false }
                offset += len
            }
        } while len != 0

        return true
    }

    public static func sniffQuery(_ buffer: FBPacketBuffer) -> SniffedDNSQuery? {
        guard buffer.readableBytes >= 12 else { return nil }

        guard let id = buffer.loadUInt16(at: 0),
              let flags = buffer.loadUInt16(at: 2),
              let qdcount = buffer.loadUInt16(at: 4)
        else {
            return nil
        }

        // query only
        if (flags & 0x8000) != 0 { return nil }

        // only one question
        guard qdcount == 1 else { return nil }

        var i = 12
        let qnameStart = i
        guard skipQNameNoPointer(buffer: buffer, offset: &i) else { return nil }
        let qnameEnd = i
        guard qnameEnd + 4 <= buffer.readableBytes else { return nil }

        guard let qtypeRaw = buffer.loadUInt16(at: qnameEnd),
              let qclassRaw = buffer.loadUInt16(at: qnameEnd + 2)
        else { return nil }

        guard let qtype = DNSType(rawValue: qtypeRaw) else {
            return nil
        }

        guard let qclass = DNSClass(rawValue: qclassRaw),
              qclass == .internet
        else {
            return nil
        }

        let questionLength = (qnameEnd + 4) - qnameStart
        guard let questionSlice = buffer.slice(from: qnameStart, length: questionLength) else {
            return nil
        }
        // Ensure slice is the expected FBPacketBuffer concrete type
        guard let questionBuffer = questionSlice as? FBPacketBuffer else {
            return nil
        }
        return SniffedDNSQuery(
            id: id,
            flags: flags,
            qtype: qtype,
            qclass: qclass,
            question: questionBuffer
        )
    }
}
