//
//  DNSService.swift
//  NetForge
//
//  Created by MagicianQuinn on 2025/12/27.
//  DNSService.swift
//  NetForge
//
//  Policy (final):
//  - Fake ONLY:
//      * A
//      * PTR(fake-ip in in-addr.arpa)  -> returns mapped domain (if exists), else passthrough upstream
//  - All others passthrough upstream (including AAAA, HTTPS/SVCB, ip6.arpa, etc.)
//  - No implicit logic.
//
//  This service operates on wire payload Data, not higher-level DNSClient objects.
//

import ForgeBase
import Foundation
import Network
import NIO

/// DNS fake / dial ready notification
protocol DNSDialReadyObserver: AnyObject {
    func dnsDialReady(fakeIP: IPv4Address)
}

public struct DialDecision {
    public let dialIP: IPv4Address?
    public let dialHost: String?
    public let fromFakeIP: Bool
}

public final class DNSService {
    public let eventLoop: EventLoop

    private let ttl: Int
    private let cache: DNSCache
    private let ipPool: FakeIPPool
    private let upstream: DNSUpstreamUDPRelay

    private var sweepTask: RepeatedTask?

    public init(
        eventLoop: EventLoop,
        ttl: Int = 300,
        upstreamHost: String = "8.8.8.8",
        upstreamPort: Int = 53
    ) {
        self.eventLoop = eventLoop
        self.ttl = ttl
        cache = DNSCache(eventLoop: eventLoop)
        ipPool = FakeIPPool(on: eventLoop)
        upstream = DNSUpstreamUDPRelay(
            eventLoop: eventLoop,
            upstream: .init(host: upstreamHost, port: upstreamPort)
        )

        EFDLog.core(
            "DNSService init ttl=\(ttl)s upstream=\(upstreamHost):\(upstreamPort)"
        )
    }

    // MARK: - Public API (any loop)

    public func handleDNSPayload(_ payload: Data, _ callerLoop: EventLoop) -> EventLoopFuture<Data> {
        EFDLog.core("handle payload len=\(payload.count)")

        return eventLoop.flatSubmit { [weak self] in
            guard let self else {
                return callerLoop.makeSucceededFuture(payload) // best-effort
            }
            self.eventLoop.assertInEventLoop()
            return self.handleInternal(payload)
        }.hop(to: callerLoop)
    }

    public func resolveDialDecision(_ dstIP: IPv4Address, _ callerLoop: EventLoop) -> EventLoopFuture<DialDecision> {
        return eventLoop.flatSubmit { [weak self] in
            let direct = DialDecision(dialIP: dstIP, dialHost: nil, fromFakeIP: false)
            guard let self else { return callerLoop.makeSucceededFuture(direct) }

            self.eventLoop.assertInEventLoop()

            guard self.ipPool.isFakeIP(dstIP) else {
                EFDLog.core("dial direct ip=\(dstIP)")
                return self.eventLoop.makeSucceededFuture(direct)
            }

            guard let domain = self.ipPool.reverseLookup(dstIP) else {
                EFDLog.warn("fakeIP no reverse ip=\(dstIP)")
                return self.eventLoop.makeSucceededFuture(DialDecision(dialIP: nil, dialHost: nil, fromFakeIP: true))
            }

            let key = DNSCacheKey(domain: domain, type: .a)
            if let real = self.cache.lookup(key)?.realIPs?.first {
                EFDLog.core(
                    "dial resolved fakeIP=\(dstIP) realIP=\(real)"
                )
                return self.eventLoop.makeSucceededFuture(DialDecision(dialIP: real, dialHost: nil, fromFakeIP: true))
            }

            EFDLog.core(
                "dial unresolved fakeIP=\(dstIP) host=\(domain)"
            )

            // No realIP yet -> return host to dial (SNI/HTTP proxy path can use it later)
            self.prefetchAIfNeeded(domain: domain)
            return self.eventLoop.makeSucceededFuture(DialDecision(dialIP: nil, dialHost: domain, fromFakeIP: true))
        }.hop(to: callerLoop)
    }

    // MARK: - Sweep

    public func startSweep() {
        eventLoop.execute { [weak self] in
            guard let self else {
                return
            }

            eventLoop.assertInEventLoop()
            let interval = Int64(max(10, ttl / 2))

            sweepTask = eventLoop.scheduleRepeatedTask(
                initialDelay: .seconds(interval),
                delay: .seconds(interval)
            ) { [weak self] _ in
                guard let self else { return }
                self.cache.sweepExpired { removed in
                    if !removed.isEmpty {
                        EFDLog.cache("sweep removed=\(removed.count)")
                    }
                }
            }
        }
    }

    public func stopSweep() {
        eventLoop.execute { [weak self] in
            guard let self else {
                return
            }

            eventLoop.assertInEventLoop()
            EFDLog.core("stop sweep")
            sweepTask?.cancel()
            sweepTask = nil
            upstream.stop()
        }
    }

    // MARK: - Internal (dnsLoop)

    private func handleInternal(_ payload: Data) -> EventLoopFuture<Data> {
        eventLoop.assertInEventLoop()

        guard let sniff = DNSFastSniffer.sniffQuery(payload) else {
            EFDLog.warn("not dns payload len=\(payload.count)")
            // Not DNS query -> upstream passthrough is meaningless here; just return original payload (caller decides).
            return eventLoop.makeSucceededFuture(payload)
        }

        EFDLog.core(
            "query id=\(sniff.id) name=\(sniff.qname) type=\(sniff.qtype)"
        )
        // Parse full first question
        guard let query = try? MinimalDNSParser.parse(payload) else {
            // servfail w/ original question if possible
            return eventLoop.makeSucceededFuture(
                FakeDNSResponseBuilder.buildServFail(id: sniff.id, originalQuestion: sniff.questionRaw)
            )
        }

        switch query.question.type {
        // ✅ Fake A
        case .a:
            EFDLog.core("policy fake-A domain=\(query.question.name)")
            return handleFakeA(query: query)
        case .aaaa:
            fallthrough
        case .https:
            fallthrough
        case .svcb:
            fallthrough
        // ✅ Fake PTR ONLY for fake-ip reverse (in-addr.arpa)
        case .ptr:
            EFDLog.core("policy PTR name=\(query.question.name)")
            if let v4 = parseInAddrArpa(query.question.name),
               ipPool.isFakeIP(v4),
               let domain = ipPool.reverseLookup(v4)
            {
                let resp = FakeDNSResponseBuilder.buildPTR(
                    query: query,
                    ptrDomain: domain,
                    ttl: UInt32(ttl)
                )
                return eventLoop.makeSucceededFuture(resp)
            }

            // PTR not for our fake-ip -> upstream passthrough
            return handleUpstream(payload: payload)
        // ✅ upstream passthrough
        default:
            EFDLog.core("policy upstream type=\(query.question.type)")
            return handleUpstream(payload: payload)
        }
    }

    private func handleFakeA(query: DNSQuery) -> EventLoopFuture<Data> {
        eventLoop.assertInEventLoop()

        let domain = normalize(domain: query.question.name)
        let key = DNSCacheKey(domain: domain, type: .a)

        if let cached = cache.lookup(key) {
            EFDLog.fakeip(
                "reuse fakeIP domain=\(domain) ip=\(cached.fakeIP)"
            )
            let resp = FakeDNSResponseBuilder.buildA(query: query, fakeIPv4: cached.fakeIP, ttl: UInt32(ttl))
            return eventLoop.makeSucceededFuture(resp)
        }

        guard let fakeIP = ipPool.assign(domain: domain) else {
            EFDLog.error("fakeIP pool exhausted domain=\(domain)")
            // pool exhausted
            let qraw = DNSFastSniffer.sniffQuery(Data())?.questionRaw ?? Data()
            return eventLoop.makeSucceededFuture(
                FakeDNSResponseBuilder.buildServFail(id: query.header.id, originalQuestion: qraw)
            )
        }

        EFDLog.fakeip(
            "assign fakeIP domain=\(domain) ip=\(fakeIP)"
        )

        let entry = DNSCacheEntry(
            key: key,
            fakeIP: fakeIP,
            expireAt: .now() + .seconds(Int64(ttl)),
            realIPs: nil
        )
        cache.insert(entry)

        // Prefetch real A (best-effort)
        prefetchAIfNeeded(domain: domain)

        let resp = FakeDNSResponseBuilder.buildA(query: query, fakeIPv4: fakeIP, ttl: UInt32(ttl))
        return eventLoop.makeSucceededFuture(resp)
    }

    private func handleUpstream(payload: Data) -> EventLoopFuture<Data> {
        eventLoop.assertInEventLoop()
        return upstream.query(payload).flatMapError { _ in
            // Return SERVFAIL using best-effort question extraction
            let q = DNSFastSniffer.sniffQuery(payload)

            return self.eventLoop.makeSucceededFuture(
                FakeDNSResponseBuilder.buildServFail(id: q?.id ?? 0, originalQuestion: q?.questionRaw ?? Data())
            )
        }
    }

    // MARK: - Prefetch A (best-effort)

    private func prefetchAIfNeeded(domain: String) {
        eventLoop.assertInEventLoop()

        let key = DNSCacheKey(domain: domain, type: .a)
        if cache.lookup(key)?.realIPs != nil { return }

        // Build a simple A query for domain, using random txid; upstream relay rewrites anyway.
        let payload = buildSimpleAQuery(domain: domain)
        upstream.query(payload, timeout: .seconds(2)).whenSuccess { [weak self] resp in
            guard let self else { return }
            self.eventLoop.execute {
                self.onPrefetchAResult(domain: domain, response: resp)
            }
        }
    }

    private func onPrefetchAResult(domain: String, response: Data) {
        eventLoop.assertInEventLoop()

        let key = DNSCacheKey(domain: domain, type: .a)
        guard var entry = cache.lookup(key) else { return }

        let ips = MinimalAAnswerExtractor.extractAAnswers(response)
        if !ips.isEmpty {
            let fakeIP = entry.fakeIP
            entry.realIPs = ips
            cache.insert(entry)
        }
    }

    // MARK: - Helpers

    @inline(__always)
    private func normalize(domain: String) -> String {
        domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
    }

    /// Parse "x.x.x.x.in-addr.arpa" -> IPv4Address
    private func parseInAddrArpa(_ name: String) -> IPv4Address? {
        let s = name.lowercased()
        guard s.hasSuffix(".in-addr.arpa") else { return nil }

        let body = s.dropLast(".in-addr.arpa".count)
        let parts = body.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }

        let reversed = parts.reversed().joined(separator: ".")

        return FBIPv4Parse.parse(String(reversed))?.asNetworkIPv4Address
    }

    private func buildSimpleAQuery(domain: String) -> Data {
        var w = SimpleDNSQueryWriter()
        return w.buildAQuery(domain: domain)
    }
}

// MARK: - Minimal A-answer extractor (best-effort, RFC1035)

private enum MinimalAAnswerExtractor {
    static func extractAAnswers(_ data: Data) -> [IPv4Address] {
        guard data.count >= 12 else { return [] }
        var offset = 0

        func readU16() -> UInt16 {
            let v = (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
            offset += 2
            return v
        }

        _ = readU16() // id
        _ = readU16() // flags
        let qd = readU16()
        let an = readU16()
        _ = readU16()
        _ = readU16()

        // Skip questions
        for _ in 0 ..< qd {
            if skipName(data, &offset) == false { return [] }
            guard offset + 4 <= data.count else { return [] }
            offset += 4 // qtype+qclass
        }

        var out: [IPv4Address] = []

        // Parse answers
        for _ in 0 ..< an {
            if skipName(data, &offset) == false { return out }
            guard offset + 10 <= data.count else { return out }
            let type = readU16()
            _ = readU16() // class
            _ = readU16() // ttl hi
            _ = readU16() // ttl lo
            let rdlen = readU16()
            guard offset + Int(rdlen) <= data.count else { return out }

            if type == DNSType.a.rawValue, rdlen == 4 {
                let b0 = data[offset]
                let b1 = data[offset + 1]
                let b2 = data[offset + 2]
                let b3 = data[offset + 3]
                guard let ipv4 = FBIPv4(a: b0, b: b1, c: b2, d: b3).asNetworkIPv4Address else {
                    return out
                }
                out.append(ipv4)
            }
            offset += Int(rdlen)
        }

        return out
    }

    private static func skipName(_ data: Data, _ offset: inout Int) -> Bool {
        var jumped = false
        var jumpReturn = 0

        while true {
            guard offset < data.count else { return false }
            let len = data[offset]

            // pointer
            if (len & 0xC0) == 0xC0 {
                guard offset + 1 < data.count else { return false }
                if !jumped { jumpReturn = offset + 2 }
                let b2 = data[offset + 1]
                let ptr = Int((UInt16(len & 0x3F) << 8) | UInt16(b2))
                offset = ptr
                jumped = true
                continue
            }

            offset += 1
            if len == 0 { break }
            guard offset + Int(len) <= data.count else { return false }
            offset += Int(len)
        }

        if jumped { offset = jumpReturn }
        return true
    }
}

// MARK: - Simple A query builder

private struct SimpleDNSQueryWriter {
    mutating func buildAQuery(domain: String) -> Data {
        var w = ByteWriterQ()
        let id = UInt16.random(in: 1 ... UInt16.max)

        // flags: RD=1
        let flags: UInt16 = 0x0100

        w.u16(id)
        w.u16(flags)
        w.u16(1) // QD
        w.u16(0)
        w.u16(0)
        w.u16(0)

        w.name(domain)
        w.u16(DNSType.a.rawValue)
        w.u16(DNSClass.internet.rawValue)
        return w.data
    }
}

private struct ByteWriterQ {
    var data = Data()
    mutating func u16(_ v: UInt16) { data.append(UInt8(v >> 8)); data.append(UInt8(v & 0xFF)) }
    mutating func name(_ name: String) {
        for label in name.split(separator: ".") {
            let bytes = label.utf8
            data.append(UInt8(bytes.count))
            data.append(contentsOf: bytes)
        }
        data.append(0)
    }
}
