//
//  MinimalDNSParser.swift
//  NetForge
//  Created by MagicianQuinn on 2026/1/3.
//
//  Wire-level DNS parser (RFC 1035)
//  - supports name compression (pointer)
//  - parses header + first question only
//

import Foundation

// MARK: - Enums (borrowed / trimmed)

public enum DNSType: UInt16 {
    case invalid = 0

    // --- Core / Common ---
    case a = 1
    case ns = 2
    case cname = 5
    case soa = 6
    case ptr = 12
    case mx = 15
    case txt = 16
    case aaaa = 28
    case srv = 33

    // --- DNS Extensions ---
    case opt = 41 // EDNS(0)
    case ds = 43
    case rrsig = 46
    case nsec = 47
    case dnskey = 48
    case nsec3 = 50
    case nsec3param = 51

    // --- Service Binding / Modern ---
    case svcb = 64
    case https = 65

    // --- Others / Catch-all ---
    case any = 255
}

public enum DNSClass: UInt16 {
    case internet = 1
}

public enum DNSMessageType: UInt8 {
    case query = 0
    case response = 1
}

public enum DNSReturnStatus: UInt8 {
    case success = 0
    case formatError = 1
    case serverFailure = 2
    case nameError = 3
    case notImplemented = 4
    case refused = 5
}

// MARK: - Parsed Models

// public struct DNSHeader {
//    public let id: UInt16
//    public let isResponse: Bool
//    public let opcode: UInt8
//    public let rcode: DNSReturnStatus
//    public let qdCount: UInt16
//    public let anCount: UInt16
// }
public struct DNSHeader {
    public let id: UInt16
    public let flags: UInt16
    public let qdCount: UInt16
    public let anCount: UInt16
    public let nsCount: UInt16
    public let arCount: UInt16

    public var isResponse: Bool { (flags & 0x8000) != 0 }
    public var opcode: UInt8 { UInt8((flags >> 11) & 0x0F) }
    public var rcode: DNSReturnStatus {
        DNSReturnStatus(rawValue: UInt8(flags & 0x000F)) ?? .formatError
    }
}

public struct DNSQuestion {
    public let name: String
    public let type: DNSType
    public let qclass: DNSClass
}

public struct DNSQuery {
    public let header: DNSHeader
    public let question: DNSQuestion
}

// MARK: - Parser

public enum MinimalDNSParser {
    public enum ParseError: Error {
        case truncated
        case invalidName
        case noQuestion
        case notQuery
    }

    public static func parse(_ data: Data) throws -> DNSQuery {
        guard data.count >= 12 else { throw ParseError.truncated }

        var offset = 0
        func readU16() -> UInt16 {
            let v = (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
            offset += 2
            return v
        }

        let id = readU16()
        let flags = readU16()
        let qd = readU16()
        let an = readU16()
        let ns = readU16()
        let ar = readU16()

        let header = DNSHeader(id: id, flags: flags, qdCount: qd, anCount: an, nsCount: ns, arCount: ar)

        guard !header.isResponse else {
            throw ParseError.notQuery
        }
        guard qd >= 1 else { throw ParseError.noQuestion }

        let name = try readName(data: data, offset: &offset)
        let type = DNSType(rawValue: readU16()) ?? .invalid
        let qclass = DNSClass(rawValue: readU16()) ?? .internet

        return DNSQuery(
            header: header,
            question: DNSQuestion(name: name, type: type, qclass: qclass)
        )
    }

    // RFC1035 name parsing with compression pointer.
    private static func readName(data: Data, offset: inout Int) throws -> String {
        var labels: [String] = []
        var jumped = false
        var jumpReturnOffset = 0

        while true {
            guard offset < data.count else { throw ParseError.truncated }
            let len = data[offset]

            // pointer: 11xxxxxx xxxxxxxx
            if (len & 0xC0) == 0xC0 {
                guard offset + 1 < data.count else { throw ParseError.truncated }
                let b2 = data[offset + 1]
                let ptr = Int((UInt16(len & 0x3F) << 8) | UInt16(b2))

                if !jumped { jumpReturnOffset = offset + 2 }
                offset = ptr
                jumped = true
                continue
            }

            offset += 1
            if len == 0 { break }

            guard offset + Int(len) <= data.count else { throw ParseError.truncated }

            let labelData = data.subdata(in: offset ..< offset + Int(len))
            guard let label = String(data: labelData, encoding: .utf8) else { throw ParseError.invalidName }
            labels.append(label)
            offset += Int(len)
        }

        if jumped {
            offset = jumpReturnOffset
        }
        return labels.joined(separator: ".")
    }
}
