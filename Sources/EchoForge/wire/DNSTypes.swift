//
//  DNSTypes.swift
//  NetForge
//
//  Created by MagicianQuinn on 2026/1/13.
//

import ForgeBase
import Foundation

public enum DNSType: UInt16, Sendable {
    case invalid = 0

    case a = 1
    case ptr = 12
    case aaaa = 28

    // --- Others / Catch-all ---
    case any = 255
}

public enum DNSClass: UInt16, Sendable {
    case internet = 1
    case any = 255
}

public enum DNSMessageKind: UInt8, Sendable {
    case query = 0
    case response = 1
}

public enum DNSReturnStatus: Equatable, Sendable {
    case success
    case formatError
    case serverFailure
    case nameError
    case notImplemented
    case refused
    case reserved(raw: UInt8)

    public var rawValue: UInt8 {
        switch self {
        case .success: return 0
        case .formatError: return 1
        case .serverFailure: return 2
        case .nameError: return 3
        case .notImplemented: return 4
        case .refused: return 5
        case let .reserved(raw): return raw & 0x0F
        }
    }

    public init(rawValue: UInt8) {
        switch rawValue & 0x0F {
        case 0: self = .success
        case 1: self = .formatError
        case 2: self = .serverFailure
        case 3: self = .nameError
        case 4: self = .notImplemented
        case 5: self = .refused
        default: self = .reserved(raw: rawValue & 0x0F)
        }
    }
}

public struct DNSQuestion: Sendable {
    public let name: String
    public let type: DNSType
    public let qclass: DNSClass
}

public extension DNSQuestion {
    /// Serialize question to DNS wire format:
    /// [QNAME][QTYPE][QCLASS]
    @available(*, deprecated, renamed: "materialize")
    func toData() -> Data {
        materialize()
    }

    func materialize() -> Data {
        var writer = FBPacketBufferWriter(capacity: 64)
        writer.name(name)
        writer.writeUInt16(type.rawValue)
        writer.writeUInt16(qclass.rawValue)
        return writer.data
    }
}

public struct DNSHeader: Sendable {
    public let id: UInt16
    public let flags: UInt16
    public let qdCount: UInt16
    public let anCount: UInt16
    public let nsCount: UInt16
    public let arCount: UInt16

    public var isResponse: Bool { (flags & 0x8000) != 0 }
    public var opcode: UInt8 { UInt8((flags >> 11) & 0x0F) }
    public var rcode: DNSReturnStatus { DNSReturnStatus(rawValue: UInt8(flags & 0x000F)) }
}

public struct DNSQuery: Sendable {
    public let header: DNSHeader
    public let question: DNSQuestion
}
