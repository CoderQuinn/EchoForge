//
//  DNSCache.swift
//  NetForge
//
//  Created by MagicianQuinn on 2025/12/28.
//
//  In-memory cache ONLY (process-lifetime).
//  Key: (domain, type) but in current policy we only cache A (fake-ip mapping).
//

import Foundation
import Network
import NIO

struct DNSCacheKey: Hashable {
    let domain: String
    let type: DNSType

    init(domain: String, type: DNSType) {
        self.domain = domain
        self.type = type
    }
}

struct DNSCacheEntry {
    let key: DNSCacheKey
    let fakeIP: IPv4Address
    let expireAt: NIODeadline

    /// Optional: real A results fetched from upstream (prefetch).
    var realIPs: [IPv4Address]?

    init(key: DNSCacheKey, fakeIP: IPv4Address, expireAt: NIODeadline, realIPs: [IPv4Address]? = nil) {
        self.key = key
        self.fakeIP = fakeIP
        self.expireAt = expireAt
        self.realIPs = realIPs
    }
}

public final class DNSCache {
    private let eventLoop: EventLoop
    private var table: [DNSCacheKey: DNSCacheEntry] = [:]

    init(eventLoop: EventLoop) {
        self.eventLoop = eventLoop
    }

    func lookup(_ key: DNSCacheKey) -> DNSCacheEntry? {
        eventLoop.assertInEventLoop()

        guard let entry = table[key] else {
            EFDLog.cache("miss domain=\(key.domain) type=\(key.type)")
            return nil
        }

        if entry.expireAt <= .now() {
            table.removeValue(forKey: key)
            EFDLog.cache("expired domain=\(key.domain) fakeIP=\(entry.fakeIP)")
            return nil
        }

        EFDLog.cache(
            "hit domain=\(key.domain) fakeIP=\(entry.fakeIP) realIPs=\(entry.realIPs?.count ?? 0)"
        )
        return entry
    }

    func insert(_ entry: DNSCacheEntry) {
        eventLoop.assertInEventLoop()

        if table[entry.key] != nil {
            EFDLog.cache(
                "overwrite domain=\(entry.key.domain) fakeIP=\(entry.fakeIP)"
            )
        } else {
            EFDLog.cache(
                "insert domain=\(entry.key.domain) fakeIP=\(entry.fakeIP)")
        }
        table[entry.key] = entry
    }

    func sweepExpired(_ now: NIODeadline = .now(), _ handler: ([DNSCacheEntry]) -> Void) {
        eventLoop.assertInEventLoop()

        var removed: [DNSCacheEntry] = []

        let expiredKeys = table.filter { $0.value.expireAt <= now }.map(\.key)
        for key in expiredKeys {
            if let entry = table.removeValue(forKey: key) {
                removed.append(entry)
            }
        }

        if !removed.isEmpty {
            EFDLog.cache("sweep expired count=\(removed.count)")
        }
        handler(removed)
    }
}
