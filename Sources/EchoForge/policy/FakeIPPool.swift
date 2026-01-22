//
//  FakeIPPool.swift
//  EchoForge
//
//  Created by MagicianQuinn on 2025/12/11.
//
//  Fake IPv4 pool + reverse mapping.
//  NOTE: IPv4 only; IPv6 is strategically ignored for now.
//

import ForgeBase
import Foundation
import NIO
import Network

/// Fake IPv4 pool for DNS interception.
///
/// Conventions:
/// - All UInt32 values are NETWORK BYTE ORDER (big-endian)
/// - Only IPs actually allocated by this pool are considered "fake"
/// - Must be accessed from the bound EventLoop
public final class FakeIPPool {
    private let eventLoop: EventLoop

    /// Network base address (UInt32BE)
    private let baseBE: UInt32
    private let prefixLength: Int

    /// Host mask (low bits)
    private let hostMask: UInt32

    /// Maximum usable hosts (excluding network / broadcast)
    private let capacity: UInt32

    /// Current host offset (host bits only)
    /// Range: [2 ..< hostMask)
    private var offset: UInt32 = 2

    /// Forward / reverse maps
    private var ipToDomain: [IPv4Address: String] = [:]
    private var domainToIp: [String: IPv4Address] = [:]

    // MARK: - Init

    public init(
        cidr: String = "198.18.0.0/16",
        on eventLoop: EventLoop
    ) {
        self.eventLoop = eventLoop

        let parsed = FBIPv4Parse.parseCIDR(cidr)

        // Fallback: 198.18.0.0/16 (RFC 2544 benchmarking)
        let fallbackNetworkBE: UInt32 = 0xC612_0000
        let fallbackPrefix = 16

        baseBE = parsed?.networkBE ?? fallbackNetworkBE
        prefixLength = parsed?.prefixLength ?? fallbackPrefix

        let hostBits = UInt32(32 - prefixLength)
        hostMask = (hostBits == 32) ? UInt32.max : ((1 << hostBits) - 1)

        // Exclude network (0), .0.1, broadcast (hostMask)
        let usableHosts =
            hostMask > 2 ? hostMask - 2 : 0

        capacity = usableHosts
    }

    // MARK: - Allocation

    /// Assign (or return existing) fake IP for domain.
    /// Must be called on pool eventLoop.
    public func assign(domain: String) -> IPv4Address? {
        eventLoop.assertInEventLoop()

        let key = normalize(domain: domain)

        if let ip = domainToIp[key] {
            EFLog.fakeip("reuse domain=\(key) ip=\(ip)")
            return ip
        }

        guard capacity > 0 else { return nil }
        guard ipToDomain.count <= capacity else {
            // Pool exhausted
            return nil
        }

        for _ in 0..<capacity {
            let host = offset
            offset += 1
            if offset >= hostMask {
                offset = 2  // wrap back to first usable fake IP
            }

            // Skip:
            // 0 -> network
            // 1 -> local reserved (198.18.0.1)
            // hostMask -> broadcast
            if host <= 1 || host == hostMask {
                continue
            }

            let candidateBE = baseBE | host

            guard let ip = FBIPv4(beValue: candidateBE).asNetworkIPv4Address,
                ipToDomain[ip] == nil
            else {
                continue
            }

            domainToIp[key] = ip
            ipToDomain[ip] = key
            EFLog.fakeip("assign domain=\(key) ip=\(ip)")
            return ip
        }

        // Pool exhausted
        return nil
    }

    // MARK: - Reverse lookup

    /// Reverse lookup fake IP → domain.
    /// Must be called on pool eventLoop.
    public func reverseLookup(_ ip: IPv4Address) -> String? {
        eventLoop.assertInEventLoop()

        let d = ipToDomain[ip]
        if d == nil {
            EFLog.fakeip("reverse miss ip=\(ip)")
        }
        return d
    }

    /// Check if IP was allocated by this pool.
    /// CIDR containment alone is NOT sufficient.
    public func isFakeIP(_ ip: IPv4Address) -> Bool {
        eventLoop.assertInEventLoop()

        return ipToDomain[ip] != nil
    }

    // MARK: - Helpers

    @inline(__always)
    private func normalize(domain: String) -> String {
        domain
            .lowercased()
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
    }
}
