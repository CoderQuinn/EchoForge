//
//  MinimalDNSParser.swift
//  NetForge
//
//  Created by MagicianQuinn on 2026/1/13.
//

import ForgeBase
import Network

public enum ParseError: Error {
    case truncated
    case invalidName
    case notQuery
    case noQuestions
    case pointerLoop
    case bufferTypeMismatch
}

private enum RFC1035 {
    static let maxLabelLength = 63
    static let maxNameLength = 255

    static let pointerMask: UInt8 = 0xC0
    static let pointerValue: UInt8 = 0xC0
    static let pointerOffsetMask: UInt8 = 0x3F
}

public enum MinimalDNSParser {
    public static func parseQuery(_ buffer: FBPacketBuffer) throws -> DNSQuery {
        guard buffer.readableBytes >= 12 else {
            throw ParseError.truncated
        }

        var offset = 0
        @inline(__always)
        func readU16() throws -> UInt16 {
            guard let v = buffer.loadUInt16(at: offset) else {
                throw ParseError.truncated
            }
            offset += 2
            return v
        }

        let id = try readU16()
        let flags = try readU16()
        let qd = try readU16()
        let an = try readU16()
        let ns = try readU16()
        let ar = try readU16()

        let header = DNSHeader(
            id: id,
            flags: flags,
            qdCount: qd,
            anCount: an,
            nsCount: ns,
            arCount: ar
        )

        guard !header.isResponse else {
            throw ParseError.notQuery
        }
        guard qd >= 1 else {
            throw ParseError.noQuestions
        }

        let name = try readName(from: buffer, offset: &offset)
        let qtype = try DNSType(rawValue: readU16()) ?? .invalid
        let qclass = try DNSClass(rawValue: readU16()) ?? .any

        return DNSQuery(
            header: header,
            question: DNSQuestion(name: name, type: qtype, qclass: qclass)
        )
    }

    public static func extractAnswers(from buffer: FBPacketBuffer) -> ([IPv4Address], Int) {
        let placeholder: ([IPv4Address], Int) = ([], 0)  // IP and ttl
        guard buffer.readableBytes >= 12 else {
            return placeholder
        }

        var offset = 0
        @inline(__always)
        func readU16() throws -> UInt16 {
            guard let v = buffer.loadUInt16(at: offset) else {
                throw ParseError.truncated
            }
            offset += 2
            return v
        }

        func readU32() throws -> UInt32 {
            guard let v = buffer.loadUInt32(at: offset) else {
                throw ParseError.truncated
            }
            offset += 4
            return v
        }

        let id = try? readU16()  // ID
        let flags = try? readU16()  // Flags
        let qd = try? readU16()
        let an = try? readU16()
        let ns = try? readU16()  // NS
        let ar = try? readU16()  // AR

        guard let id, let flags, let qd, let an, let ns, let ar else {
            return placeholder
        }

        // Skip questions
        for _ in 0..<qd {
            let name = try? readName(from: buffer, offset: &offset)
            guard let name else {
                return placeholder
            }
            guard offset + 4 <= buffer.readableBytes else { return placeholder }
            offset += 4  // QTYPE + QCLASS
        }

        var outputs: [IPv4Address] = []  // ipv4s
        var outTTL = Int.max

        for _ in 0..<an {
            let name = try? readName(from: buffer, offset: &offset)
            guard let name else {
                return placeholder
            }
            guard offset + 10 <= buffer.readableBytes else { return placeholder }

            let type = try? readU16()
            let cls = try? readU16()
            let ttl = try? readU32()
            let rdlength = try? readU16()
            guard let type, let cls, let ttl, let rdlength else {
                return placeholder
            }

            guard offset + Int(rdlength) <= buffer.readableBytes else {
                return placeholder
            }

            if type == DNSType.a.rawValue, cls == DNSClass.internet.rawValue, rdlength == 4,
                let b0 = buffer.loadUInt8(at: offset),
                let b1 = buffer.loadUInt8(at: offset + 1),
                let b2 = buffer.loadUInt8(at: offset + 2),
                let b3 = buffer.loadUInt8(at: offset + 3),
                let ip = FBIPv4(a: b0, b: b1, c: b2, d: b3).asNetworkIPv4Address
            {
                outputs.append(ip)
                outTTL = min(outTTL, Int(ttl))
            }

            offset += Int(rdlength)
        }
        return (outputs, outTTL)
    }

    /// Read a DNS name with RFC1035 compression support.
    /// `offset` will be advanced to the first byte after the NAME.
    private static func readName(from buffer: FBPacketBuffer, offset: inout Int) throws -> String {
        var labels: [String] = []

        // Cursor used to actually read labels (may jump via pointers)
        var cursor = offset
        // Whether we have followed a compression pointer
        var jumped = false
        // Where the outer parser should continue after the name
        var nextOffsetAfterName = 0

        var visitedOffsets: Set<Int> = []
        var totalNameBytes = 0

        while true {
            // Loop / cycle protection
            if !visitedOffsets.insert(cursor).inserted {
                throw ParseError.pointerLoop
            }

            guard let len = buffer.loadUInt8(at: cursor) else {
                throw ParseError.truncated
            }

            // Compression pointer: 11xxxxxx xxxxxxxx
            if (len & RFC1035.pointerMask) == RFC1035.pointerValue {
                guard let second = buffer.loadUInt8(at: cursor + 1) else {
                    throw ParseError.truncated
                }

                let pointerOffset = Int(
                    (UInt16(len & RFC1035.pointerOffsetMask) << 8) | UInt16(second)
                )
                // Pointer must be inside message
                guard pointerOffset < buffer.readableBytes else {
                    throw ParseError.truncated
                }

                // Record NAME end only once
                if !jumped {
                    nextOffsetAfterName = cursor + 2
                    jumped = true
                }

                cursor = pointerOffset
                continue
            }

            // Normal label
            cursor += 1

            // Zero-length label marks end of the name
            if len == 0 {
                break
            }

            // RFC: label length <= 63
            guard len <= RFC1035.maxLabelLength else {
                throw ParseError.invalidName
            }

            let labelLen = Int(len)
            // RFC: total name length <= 255
            totalNameBytes += 1 + labelLen

            guard totalNameBytes <= RFC1035.maxNameLength else {
                throw ParseError.invalidName
            }

            guard let slice = buffer.slice(from: cursor, length: labelLen) else {
                throw ParseError.truncated
            }

            guard let payload = slice as? FBPacketBuffer else {
                throw ParseError.bufferTypeMismatch
            }

            guard let label = String(data: payload.materialize(), encoding: .utf8) else {
                throw ParseError.invalidName
            }

            labels.append(label)
            cursor += labelLen
        }

        offset = jumped ? nextOffsetAfterName : cursor
        return labels.joined(separator: ".")
    }
}
