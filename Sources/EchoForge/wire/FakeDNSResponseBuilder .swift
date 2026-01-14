//
//  DNSMessageBuilder .swift
//  NetForge
//
//  Created by MagicianQuinn on 2026/1/14.
//

import ForgeBase
import Foundation
import Network

public enum DNSMessageBuilder {
    // MARK: - Queries

    // Query for A record
    public static func buildAQuery(domain: String) -> Data {
        var writer = FBPacketBufferWriter()
        let id = UInt16.random(in: 1...UInt16.max)

        // flags: RD=1
        let flags: UInt16 = 0x0100

        writer.writeUInt16(id)
        writer.writeUInt16(flags)
        writer.writeUInt16(1)  // QD
        writer.writeUInt16(0)
        writer.writeUInt16(0)
        writer.writeUInt16(0)

        writer.name(domain)
        writer.writeUInt16(DNSType.a.rawValue)
        writer.writeUInt16(DNSClass.internet.rawValue)
        return writer.data
    }

    // MARK: - Responses

    // Response for A query
    public static func buildAResponse(query: DNSQuery, fakeIPv4: IPv4Address, ttl: UInt32) -> Data {
        var writer = FBPacketBufferWriter()
        let flags: UInt16 =
            0x8000  // QR = 1 (response)
            | 0x0400  // AA = 1
            | 0x0080  // RA = 1
            | 0x0000  // RCODE = 0

        writer.writeUInt16(query.header.id)  // ID
        writer.writeUInt16(flags)  // Flags
        writer.writeUInt16(1)  // QDCOUNT
        writer.writeUInt16(1)  // ANCOUNT
        writer.writeUInt16(0)  // NSCOUNT
        writer.writeUInt16(0)  // ARCOUNT

        let nameOffset = writer.position
        writer.name(query.question.name)
        writer.writeUInt16(DNSType.a.rawValue)  // QUESTION TYPE stays as requested name; ok
        writer.writeUInt16(DNSClass.internet.rawValue)

        // Answer NAME pointer to question name
        writer.pointer(to: nameOffset)
        writer.writeUInt16(DNSType.a.rawValue)  // QUESTION TYPE stays as requested name; ok
        writer.writeUInt16(DNSClass.internet.rawValue)
        writer.writeUInt32(ttl)  // TTL
        writer.writeUInt16(4)  // RDLENGTH
        writer.raw(fakeIPv4.rawValue)  // RDATA

        return writer.data
    }

    // Response for PTR query
    public static func builePTRResponse(query: DNSQuery, ptrDomain: String, ttl: UInt32) -> Data {
        var writer = FBPacketBufferWriter()
        let flags: UInt16 =
            0x8000  // QR = 1 (response)
            | 0x0400  // AA = 1
            | 0x0080  // RA = 1
            | 0x0000  // RCODE = 0

        writer.writeUInt16(query.header.id)  // ID
        writer.writeUInt16(flags)  // Flags
        writer.writeUInt16(1)  // QDCOUNT
        writer.writeUInt16(1)  // ANCOUNT
        writer.writeUInt16(0)  // NSCOUNT
        writer.writeUInt16(0)  // ARCOUNT

        let nameOffset = writer.position
        writer.name(query.question.name)
        writer.writeUInt16(DNSType.ptr.rawValue)  // QUESTION TYPE stays as requested
        writer.writeUInt16(DNSClass.internet.rawValue)

        // Answer NAME pointer to question name
        writer.pointer(to: nameOffset)
        writer.writeUInt16(DNSType.ptr.rawValue)  // TYPE
        writer.writeUInt16(DNSClass.internet.rawValue)  // CLASS
        writer.writeUInt32(ttl)  // TTL

        // RDLENGTH and RDATA
        let rdlenPos = writer.reserve16()
        let start = writer.position
        writer.name(ptrDomain)
        writer.fillUInt16(at: rdlenPos, value: UInt16(writer.position - start))
        return writer.data
    }

    public static func buildNoAnswerResponse(
        id: UInt16,
        originalQuestion: Data
    ) -> Data {
        return buildRefuseResponse(id: id, rcode: .success, originalQuestion: originalQuestion)
    }

    /// FORMERR / NOTIMP / REFUSED / SERVFAIL etc.
    public static func buildRefuseResponse(
        id: UInt16,
        rcode: DNSReturnStatus,
        originalQuestion: Data
    ) -> Data {
        var writer = FBPacketBufferWriter()
        let flags: UInt16 =
            0x8000  // QR = 1 (response)
            | 0x0080  // RA = 1
            | UInt16(rcode.rawValue)  // RCODE

        writer.writeUInt16(id)  // ID
        writer.writeUInt16(flags)  // Flags
        writer.writeUInt16(originalQuestion.isEmpty ? 0 : 1)  // QDCOUNT
        writer.writeUInt16(0)  // ANCOUNT
        writer.writeUInt16(0)  // NSCOUNT
        writer.writeUInt16(0)  // ARCOUNT

        if !originalQuestion.isEmpty {
            writer.raw(originalQuestion)
        }
        return writer.data
    }

    public static func buildServFailResponse(id: UInt16, originalQuestion: Data) -> Data {
        return buildRefuseResponse(
            id: id,
            rcode: .serverFailure,
            originalQuestion: originalQuestion
        )
    }
}
