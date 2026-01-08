//
//  FakeDNSResponseBuilder.swift
//  EchoForgeDNS
//
//  Created by MagicianQuinn on 2026/1/3.
//
//
//  Minimal wire-level DNS response builder.
//  - Only builds Answer for A / PTR (and optional AAAA if you later need passthrough fake).
//  - Does NOT parse upstream; designed for fake responses.
//

import Foundation
import Network

public enum FakeDNSResponseBuilder {
    public static func buildA(
        query: DNSQuery,
        fakeIPv4: IPv4Address,
        ttl: UInt32
    ) -> Data {
        var w = ByteWriter()

        // Header flags:
        // QR=1, RA=1, AA=1, RCODE=0
        let flags: UInt16 = 0x8000 | 0x0080 | 0x0400 | 0

        w.u16(query.header.id)
        w.u16(flags)
        w.u16(1) // QDCOUNT
        w.u16(1) // ANCOUNT
        w.u16(0)
        w.u16(0)

        let nameOffset = w.position
        w.name(query.question.name)
        w.u16(DNSType.a.rawValue)
        w.u16(DNSClass.internet.rawValue)

        // Answer: NAME as pointer to question name
        w.pointer(to: nameOffset)
        w.u16(DNSType.a.rawValue)
        w.u16(DNSClass.internet.rawValue)
        w.u32(ttl)
        w.u16(4)
        w.raw(fakeIPv4.rawValue)

        return w.data
    }

    public static func buildPTR(
        query: DNSQuery,
        ptrDomain: String,
        ttl: UInt32
    ) -> Data {
        var w = ByteWriter()

        let flags: UInt16 = 0x8000 | 0x0080 | 0x0400 | 0

        w.u16(query.header.id)
        w.u16(flags)
        w.u16(1)
        w.u16(1)
        w.u16(0)
        w.u16(0)

        let nameOffset = w.position
        w.name(query.question.name)
        w.u16(DNSType.ptr.rawValue)
        w.u16(DNSClass.internet.rawValue)

        // Answer
        w.pointer(to: nameOffset)
        w.u16(DNSType.ptr.rawValue)
        w.u16(DNSClass.internet.rawValue)
        w.u32(ttl)

        let rdlenPos = w.reserveU16()
        let start = w.position
        w.name(ptrDomain)
        w.fillU16(at: rdlenPos, UInt16(w.position - start))

        return w.data
    }

    public static func buildServFail(id: UInt16, originalQuestion: Data) -> Data {
        // We keep this minimal: header + original question bytes.
        // flags: QR=1, RA=1, RCODE=2(SERVFAIL)
        var w = ByteWriter()
        let flags: UInt16 = 0x8000 | 0x0080 | 0x0002

        w.u16(id)
        w.u16(flags)
        w.u16(1)
        w.u16(0)
        w.u16(0)
        w.u16(0)

        w.raw(originalQuestion)
        return w.data
    }
}

private struct ByteWriter {
    private(set) var data = Data()
    private(set) var position: Int = 0

    mutating func u8(_ v: UInt8) {
        data.append(v); position += 1
    }

    mutating func u16(_ v: UInt16) {
        data.append(UInt8(v >> 8))
        data.append(UInt8(v & 0xFF))
        position += 2
    }

    mutating func u32(_ v: UInt32) {
        u16(UInt16(v >> 16))
        u16(UInt16(v & 0xFFFF))
    }

    mutating func raw<T: Collection>(_ bytes: T) where T.Element == UInt8 {
        data.append(contentsOf: bytes)
        position += bytes.count
    }

    mutating func raw(_ d: Data) {
        data.append(d)
        position += d.count
    }

    mutating func pointer(to offset: Int) {
        let ptr = UInt16(0xC000 | UInt16(offset))
        u16(ptr)
    }

    mutating func reserveU16() -> Int {
        let pos = position
        u16(0)
        return pos
    }

    mutating func fillU16(at pos: Int, _ value: UInt16) {
        data[pos] = UInt8(value >> 8)
        data[pos + 1] = UInt8(value & 0xFF)
    }

    mutating func name(_ name: String) {
        for label in name.split(separator: ".") {
            let bytes = label.utf8
            u8(UInt8(bytes.count))
            raw(bytes)
        }
        u8(0)
    }
}
