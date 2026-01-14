//  DNSCache.swift
//  NetForge
//
//  Created by MagicianQuinn on 2025/12/28.
//
//  In-memory cache ONLY (process-lifetime).
//  Key: (domain, type) but in current policy we only cache A (fake-ip mapping).
//

import Foundation
import NIO
import Network

public struct DNSCacheKey: Hashable {
    let domain: String
    let type: DNSType

    init(domain: String, type: DNSType) {
        self.domain = domain
        self.type = type
    }
}

public struct DNSCacheEntry {
    let key: DNSCacheKey
    let fakeIP: IPv4Address
    var expireAt: NIODeadline
    /// Optional: real A results fetched from upstream (prefetch).
    var realIPs: [IPv4Address]?

    init(
        key: DNSCacheKey,
        fakeIP: IPv4Address,
        expireAt: NIODeadline,
        realIPs: [IPv4Address]? = nil
    ) {
        self.key = key
        self.fakeIP = fakeIP
        self.expireAt = expireAt
        self.realIPs = realIPs
    }
}

public final class DNSCache {
    private let eventLoop: EventLoop
    private var caches: [DNSCacheKey: DNSCacheEntry] = [:]

    init(eventLoop: EventLoop) {
        self.eventLoop = eventLoop
    }

    public func lookup(_ key: DNSCacheKey) -> DNSCacheEntry? {
        eventLoop.assertInEventLoop()

        guard let entry: DNSCacheEntry = caches[key] else {
            EFLog.cache("miss domain=\(key.domain) type=\(key.type)")
            return nil
        }

        if entry.expireAt <= .now() {
            caches.removeValue(forKey: key)

            EFLog.cache("expired domain=\(key.domain) fakeIP=\(entry.fakeIP)")
            return nil
        }

        EFLog.cache(
            "hit domain=\(key.domain) fakeIP=\(entry.fakeIP) realIPs=\(entry.realIPs?.count ?? 0)"
        )
        return entry
    }

    public func insert(_ entry: DNSCacheEntry) {
        eventLoop.assertInEventLoop()

        if caches[entry.key] != nil {
            EFLog.cache(
                "overwrite domain=\(entry.key.domain) fakeIP=\(entry.fakeIP)"
            )
        } else {
            EFLog.cache(
                "insert domain=\(entry.key.domain) fakeIP=\(entry.fakeIP)"
            )
        }
        caches[entry.key] = entry
    }

    func sweepExpired(_ now: NIODeadline = .now(), _ handler: ([DNSCacheEntry]) -> Void) {
        eventLoop.assertInEventLoop()

        var expiredEntries: [DNSCacheEntry] = []

        let expiredKeys: [DNSCacheKey] = caches.filter { $0.value.expireAt <= now }.map { $0.key }
        for key: DNSCacheKey in expiredKeys {
            if let entry = caches.removeValue(forKey: key) {
                expiredEntries.append(entry)
                EFLog.cache("sweep expired domain=\(entry.key.domain) fakeIP=\(entry.fakeIP)")
            }
        }

        if !expiredEntries.isEmpty {
            EFLog.cache("swept \(expiredEntries.count) expired DNS cache entries")
        }
        handler(expiredEntries)
    }
}
