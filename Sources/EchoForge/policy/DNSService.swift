//
//  DNSService.swift
//  NetForge
//
//  Created by MagicianQuinn on 2026/1/13.
//

/*
 Design principle:
 DNS queries are processed using a two-stage pipeline.

 1. Fast path:
    - Optimistic parsing with minimal validation.
    - O(n) linear scan, no allocations, no compression pointers.
    - Handles the vast majority of real-world DNS queries.

 2. Slow path:
    - Full RFC1035-compliant parsing.
    - Supports compression pointers and full name decoding.
    - Invoked only when fast path cannot safely classify the query.

 This design prioritizes performance and safety while preserving correctness.
 */

import ForgeBase
import Foundation
import NIO
import Network

public struct DialDecision {
    public let dialIP: IPv4Address?
    public let dialHost: String?
    public let fromFakeIP: Bool
}

public final class DNSService: @unchecked Sendable {
    public let eventLoop: EventLoop

    private let ttl: Int
    private let caches: DNSCache
    private let ipPool: FakeIPPool
    private let upstreams: DNSUpstreamGroup
    private let upstreamTimeout: TimeAmount

    private var inflightPrefetch: Set<String> = []
    private let prefetchCooldown: TimeAmount = .seconds(3)
    private var prefetchCooldownUntils: [String: NIODeadline] = [:]

    private let breaker = DNSUpstreamBreaker()
    private var sweepTask: RepeatedTask?

    private let slowUpstreamDeadline: TimeAmount
    private var upstreamInflight: Int = 0
    private let maxUpstreamInflight: Int = 64

    public init(
        eventLoop: EventLoop,
        ttl: Int = 300,
        slowUpstreamDeadline: TimeAmount = .milliseconds(800),
        hedgeDelay: TimeAmount = .milliseconds(50),
        upstreamTimeout: TimeAmount = .seconds(3),
        primaryUpstream: Upstream = .init(host: "8.8.8.8", port: 53),
        secondaryUpstreams: [Upstream] = [.init(host: "1.1.1.1", port: 53)]
    ) {
        self.eventLoop = eventLoop
        self.ttl = ttl
        self.slowUpstreamDeadline = slowUpstreamDeadline

        caches = DNSCache(eventLoop: eventLoop)
        ipPool = FakeIPPool(on: eventLoop)

        let primary = DNSUpstreamGroup.Entry(
            upstream: DNSUpstreamUDPRelay(eventLoop: eventLoop, upstream: primaryUpstream),
            breaker: DNSUpstreamBreaker()
        )
        let secondary = secondaryUpstreams.map {
            DNSUpstreamGroup.Entry(
                upstream: DNSUpstreamUDPRelay(eventLoop: eventLoop, upstream: $0),
                breaker: DNSUpstreamBreaker()
            )
        }

        upstreams = DNSUpstreamGroup(
            eventLoop: eventLoop,
            primary: primary,
            secondary: secondary,
            hedgeDelay: hedgeDelay,
            slowUpstreamDeadline: slowUpstreamDeadline
        )

        self.upstreamTimeout = upstreamTimeout
    }

    // MARK: - Public API (any loop)

    public func handleDNSPayload(_ buffer: FBPacketBuffer, _ callerLoop: EventLoop)
        -> EventLoopFuture<Data?>
    {
        let fast = DNSFastSniffer.sniffQuery(buffer)
        let decision = DNSPolicyEngine.decide(fast)

        return eventLoop.flatSubmit { [weak self, eventLoop = self.eventLoop] in
            guard let self else {
                return eventLoop.makeSucceededFuture(buffer.materialize())
            }
            eventLoop.assertInEventLoop()
            return self.handlerInternal(buffer, fast: fast, decision: decision)
        }
        .hop(to: callerLoop)
    }

    // MARK: - Internal (eventLoop only)

    private func handlerInternal(
        _ buffer: FBPacketBuffer,
        fast: SniffedDNSQuery?,
        decision: DNSPolicyDecision
    ) -> EventLoopFuture<Data?> {
        switch decision {
        case .handleLocally:
            return handleSlow(buffer: buffer, fast: fast)

        case .refuse(let rcode):
            if fast == nil {
                return handleSlow(buffer: buffer, fast: fast)
            }
            let id = fast?.id ?? 0
            let q = fast?.question.materialize() ?? Data()
            return eventLoop.makeSucceededFuture(
                DNSMessageBuilder.buildRefuseResponse(id: id, rcode: rcode, originalQuestion: q)
            )

        case .passthrough:
            return handleUpstream(buffer: buffer, fast: fast)
        }
    }

    private func handleSlow(buffer: FBPacketBuffer, fast: SniffedDNSQuery?) -> EventLoopFuture<Data?> {
        eventLoop.assertInEventLoop()

        let query: DNSQuery
        do {
            query = try MinimalDNSParser.parseQuery(buffer)
        } catch {
            EFLog.core("DNS slow parse failed: \(error)")
            return makeFormError(fast: fast)
        }

        switch query.question.type {
        case .a:
            return handleAQuery(query: query, buffer: buffer)
        case .aaaa:
            return handleAAAAQueryFallback(query: query)
        case .ptr:
            return handlePTRQuery(query: query, buffer: buffer, fast: fast)
        default:
            return handleUpstream(buffer: buffer, fast: fast)
        }
    }

    private func makeFormError(fast: SniffedDNSQuery?) -> EventLoopFuture<Data?> {
        let id = fast?.id ?? 0
        let q = fast?.question.materialize() ?? Data()
        let resp = DNSMessageBuilder.buildRefuseResponse(
            id: id,
            rcode: .formatError,
            originalQuestion: q
        )
        return eventLoop.makeSucceededFuture(resp)
    }

    // MARK: - Query handlers

    private func handleAQuery(query: DNSQuery, buffer _: FBPacketBuffer) -> EventLoopFuture<Data?> {
        eventLoop.assertInEventLoop()

        let domain = normalize(domain: query.question.name)
        let key = DNSCacheKey(domain: domain, type: .a)

        if let cached = caches.lookup(key) {
            let resp = DNSMessageBuilder.buildAResponse(
                query: query,
                fakeIPv4: cached.fakeIP,
                ttl: UInt32(ttl)
            )
            return eventLoop.makeSucceededFuture(resp)
        }

        guard let fakeIP = ipPool.assign(domain: domain) else {
            let resp = DNSMessageBuilder.buildServFailResponse(
                id: query.header.id,
                originalQuestion: Data()
            )
            return eventLoop.makeSucceededFuture(resp)
        }

        caches.insert(
            DNSCacheEntry(key: key, fakeIP: fakeIP, expireAt: .now() + .seconds(Int64(ttl)))
        )

        prefetchAIfNeeded(domain: domain)
        let resp = DNSMessageBuilder.buildAResponse(query: query, fakeIPv4: fakeIP, ttl: UInt32(ttl))
        return eventLoop.makeSucceededFuture(resp)
    }

    private func handleAAAAQueryFallback(query: DNSQuery) -> EventLoopFuture<Data?> {
        eventLoop.makeSucceededFuture(
            DNSMessageBuilder.buildNoAnswerResponse(
                id: query.header.id,
                originalQuestion: query.question.materialize()
            )
        )
    }

    private func handlePTRQuery(query: DNSQuery, buffer: FBPacketBuffer, fast: SniffedDNSQuery?)
        -> EventLoopFuture<Data?>
    {
        eventLoop.assertInEventLoop()

        if let v4 = parseInAddrArpa(query.question.name),
            ipPool.isFakeIP(v4),
            let domain = ipPool.reverseLookup(v4)
        {
            let resp = DNSMessageBuilder.builePTRResponse(
                query: query,
                ptrDomain: domain,
                ttl: UInt32(ttl)
            )
            return eventLoop.makeSucceededFuture(resp)
        }

        return handleUpstream(buffer: buffer, fast: fast)
    }

    // MARK: - Upstream forwarding

    private func handleUpstream(buffer: FBPacketBuffer, fast _: SniffedDNSQuery?) -> EventLoopFuture<Data?> {
        eventLoop.assertInEventLoop()

        if !breaker.allowRequest() {
            return eventLoop.makeSucceededFuture(nil)
        }

        if upstreamInflight >= maxUpstreamInflight {
            breaker.onFailure()
            return eventLoop.makeSucceededFuture(nil)
        }
        upstreamInflight += 1

        let payload = buffer.materialize()

        let future: EventLoopFuture<Data?> = upstreams.query(payload, timeout: upstreamTimeout)
            .map { [weak self] responseData -> Data? in
                guard let self else { return responseData }
                self.breaker.onSuccess()
                return responseData
            }
            .recover { [weak self] error in
                self?.breaker.onFailure()
                switch error {
                case DNSUpstreamError.timeout:
                    EFLog.upstream("timeout")
                case DNSUpstreamError.notReady:
                    EFLog.upstream("not ready")
                default:
                    EFLog.upstream("error \(error)")
                }
                return nil
            }

        future.whenComplete { [weak self] _ in
            guard let self else { return }
            self.eventLoop.execute {
                self.eventLoop.assertInEventLoop()
                self.upstreamInflight -= 1
            }
        }

        return future
    }

    // MARK: - Dial decision

    public func resolveDialDecision(_ dstIP: IPv4Address, _ callerLoop: EventLoop)
        -> EventLoopFuture<DialDecision>
    {
        eventLoop.flatSubmit { [weak self] in
            let direct = DialDecision(dialIP: dstIP, dialHost: nil, fromFakeIP: false)
            guard let self else {
                return callerLoop.makeSucceededFuture(direct)
            }

            self.eventLoop.assertInEventLoop()
            guard self.ipPool.isFakeIP(dstIP) else {
                return self.eventLoop.makeSucceededFuture(direct)
            }

            guard let domain = self.ipPool.reverseLookup(dstIP) else {
                return self.eventLoop.makeSucceededFuture(
                    DialDecision(dialIP: nil, dialHost: nil, fromFakeIP: true)
                )
            }

            let key = DNSCacheKey(domain: domain, type: .a)
            if let real = self.caches.lookup(key)?.realIPs?.first {
                return self.eventLoop.makeSucceededFuture(
                    DialDecision(dialIP: real, dialHost: nil, fromFakeIP: true)
                )
            }

            self.prefetchAIfNeeded(domain: domain)
            return self.eventLoop.makeSucceededFuture(
                DialDecision(dialIP: nil, dialHost: domain, fromFakeIP: true)
            )
        }
        .hop(to: callerLoop)
    }

    // MARK: - Prefetch

    private func prefetchAIfNeeded(domain: String) {
        eventLoop.assertInEventLoop()

        let key = DNSCacheKey(domain: domain, type: .a)
        if caches.lookup(key)?.realIPs?.first != nil { return }

        let now = NIODeadline.now()
        if let until = prefetchCooldownUntils[domain], until > now { return }
        guard inflightPrefetch.insert(domain).inserted else { return }

        let payload = DNSMessageBuilder.buildAQuery(domain: domain)
        upstreams.query(payload, timeout: upstreamTimeout).whenComplete { [weak self] result in
            guard let self else { return }
            self.eventLoop.execute {
                self.inflightPrefetch.remove(domain)
                switch result {
                case .success(let resp):
                    self.onPrefetchAResult(domain: domain, response: resp)
                case .failure:
                    self.prefetchCooldownUntils[domain] = .now() + self.prefetchCooldown
                }
            }
        }
    }

    private func onPrefetchAResult(domain: String, response: Data) {
        eventLoop.assertInEventLoop()

        let key = DNSCacheKey(domain: domain, type: .a)
        guard var entry = caches.lookup(key) else { return }

        let (ips, ttls) = MinimalDNSParser.extractAnswers(from: FBDataPacketBuffer(response))
        if ips.isEmpty { return }

        var maxTTL = ttls.max() ?? 0
        maxTTL = max(30, maxTTL)
        let cacheTTL = min(maxTTL, ttl)

        entry.realIPs = ips
        entry.expireAt = .now() + .seconds(Int64(cacheTTL))
        caches.insert(entry)
    }

    // MARK: - Sweep

    public func startSweep() {
        eventLoop.execute { [weak self] in
            guard let self else { return }
            self.eventLoop.assertInEventLoop()

            let intervalSeconds = max(10, ttl / 2)
            let interval = Int64(intervalSeconds)

            self.sweepTask = self.eventLoop.scheduleRepeatedTask(
                initialDelay: .seconds(interval),
                delay: .seconds(interval)
            ) { [weak self] _ in
                guard let self else { return }
                self.caches.sweepExpired { _ in }
            }

            _ = self.upstreams.start()
        }
    }

    public func stopSweep() {
        eventLoop.execute { [weak self] in
            guard let self else { return }
            self.eventLoop.assertInEventLoop()
            self.sweepTask?.cancel()
            self.sweepTask = nil
            self.upstreams.stop()
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
        return FBIPv4Parse.parseDottedDecimal(Substring(reversed))?.asNetworkIPv4Address
    }
}
