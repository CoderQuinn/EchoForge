import Foundation
import Network
import NIO
import XCTest

@testable import EchoForge

final class FakeIPPoolTests: XCTestCase {
    func testAssignAndReverseLookup() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let pool = FakeIPPool(on: loop)
        loop.execute {
            let domain = "example.com"
            let ip = pool.assign(domain: domain)
            XCTAssertNotNil(ip)
            XCTAssertEqual(pool.reverseLookup(ip!), domain)
            XCTAssertTrue(pool.isFakeIP(ip!))
        }
    }

    func testAssignIsStablePerDomain() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let pool = FakeIPPool(on: loop)
        let exp = expectation(description: "stable assignment")

        loop.execute {
            let domain = "example.org"
            let first = pool.assign(domain: domain)
            let second = pool.assign(domain: domain)
            XCTAssertEqual(first, second)
            exp.fulfill()
        }

        wait(for: [exp], timeout: 1.0)
    }

    func testPoolExhaustionReturnsNil() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let pool = FakeIPPool(cidr: "198.18.0.0/29", on: loop) // 5 usable hosts
        let exp = expectation(description: "exhaustion")

        loop.execute {
            var allocated: [IPv4Address] = []
            for i in 0 ..< 5 {
                let ip = pool.assign(domain: "d\(i).com")
                XCTAssertNotNil(ip)
                allocated.append(ip!)
            }
            let overflow = pool.assign(domain: "overflow.com")
            XCTAssertNil(overflow)
            exp.fulfill()
        }

        wait(for: [exp], timeout: 1.0)
    }

    func testReverseLookupMiss() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let pool = FakeIPPool(on: loop)
        let exp = expectation(description: "reverse miss")

        loop.execute {
            let ip = IPv4Address("198.18.0.42")!
            XCTAssertNil(pool.reverseLookup(ip))
            exp.fulfill()
        }

        wait(for: [exp], timeout: 1.0)
    }

    /// Architecture contract: CIDR membership alone must NOT mark an IP as fake.
    func testIsFakeIPRequiresAllocationNotJustCIDR() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let pool = FakeIPPool(on: loop)
        let exp = expectation(description: "cidr alone not fake")

        loop.execute {
            let inRange = IPv4Address("198.18.0.50")!
            XCTAssertFalse(pool.isFakeIP(inRange))
            let assigned = pool.assign(domain: "alloc.example")!
            XCTAssertTrue(pool.isFakeIP(assigned))
            exp.fulfill()
        }

        wait(for: [exp], timeout: 1.0)
    }

    /// First usable host is .2 — reserved .0 (network) and .1 must never be assigned.
    func testPoolSkipsNetworkAndReservedDotOne() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let pool = FakeIPPool(cidr: "198.18.0.0/16", on: loop)
        let exp = expectation(description: "skip reserved")

        loop.execute {
            let ip = pool.assign(domain: "first.example")!
            XCTAssertNotEqual(ip, IPv4Address("198.18.0.0"))
            XCTAssertNotEqual(ip, IPv4Address("198.18.0.1"))
            XCTAssertEqual(ip, IPv4Address("198.18.0.2"))
            exp.fulfill()
        }

        wait(for: [exp], timeout: 1.0)
    }

    func testDomainNormalizationIsCaseAndDotInsensitive() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let pool = FakeIPPool(on: loop)
        let exp = expectation(description: "normalize")

        loop.execute {
            let a = pool.assign(domain: "Example.COM.")!
            let b = pool.assign(domain: "example.com")!
            XCTAssertEqual(a, b)
            exp.fulfill()
        }

        wait(for: [exp], timeout: 1.0)
    }
}

final class DNSCacheTests: XCTestCase {
    func testInsertAndLookup() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let cache = DNSCache(eventLoop: loop)
        let key = DNSCacheKey(domain: "a.com", type: .a)
        let fake = IPv4Address("198.18.1.2")!
        let entry = DNSCacheEntry(
            key: key,
            fakeIP: fake,
            expireAt: .now() + .seconds(10),
            realIPs: [IPv4Address("1.2.3.4")!]
        )
        loop.execute {
            cache.insert(entry)
            let result = cache.lookup(key)
            XCTAssertNotNil(result)
            XCTAssertEqual(result?.realIPs?.first, IPv4Address("1.2.3.4"))
        }
    }

    func testSweepExpired() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let cache = DNSCache(eventLoop: loop)
        let key = DNSCacheKey(domain: "b.com", type: .a)
        let fake = IPv4Address("198.18.1.3")!
        let entry = DNSCacheEntry(
            key: key,
            fakeIP: fake,
            expireAt: .now() - .seconds(1),
            realIPs: nil
        )
        loop.execute {
            cache.insert(entry)
            cache.sweepExpired { removed in
                XCTAssertEqual(removed.count, 1)
                XCTAssertEqual(removed.first?.key.domain, "b.com")
            }
            XCTAssertNil(cache.lookup(key))
        }
    }

    func testLookupExpiresEntry() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let cache = DNSCache(eventLoop: loop)
        let key = DNSCacheKey(domain: "expired.com", type: .a)
        let entry = DNSCacheEntry(
            key: key,
            fakeIP: IPv4Address("198.18.1.10")!,
            expireAt: .now() - .seconds(1)
        )
        let exp = expectation(description: "lookup expired")

        loop.execute {
            cache.insert(entry)
            XCTAssertNil(cache.lookup(key))
            XCTAssertNil(cache.lookup(key)) // second lookup should also miss
            exp.fulfill()
        }

        wait(for: [exp], timeout: 1.0)
    }

    func testSweepKeepsValidEntries() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let cache = DNSCache(eventLoop: loop)
        let expiredKey = DNSCacheKey(domain: "old.com", type: .a)
        let liveKey = DNSCacheKey(domain: "live.com", type: .a)
        let expiredEntry = DNSCacheEntry(
            key: expiredKey,
            fakeIP: IPv4Address("198.18.1.11")!,
            expireAt: .now() - .seconds(1)
        )
        let liveEntry = DNSCacheEntry(
            key: liveKey,
            fakeIP: IPv4Address("198.18.1.12")!,
            expireAt: .now() + .seconds(30)
        )
        let exp = expectation(description: "sweep mixed")

        loop.execute {
            cache.insert(expiredEntry)
            cache.insert(liveEntry)
            cache.sweepExpired { removed in
                XCTAssertEqual(removed.count, 1)
                XCTAssertEqual(removed.first?.key.domain, "old.com")
            }
            XCTAssertNotNil(cache.lookup(liveKey))
            exp.fulfill()
        }

        wait(for: [exp], timeout: 1.0)
    }

    /// Architecture regression: cache expiry does NOT free FakeIP mappings.
    /// Sweep removes the cache entry but reverse lookup on the pool still succeeds —
    /// documenting the lifetime coupling that can permanently exhaust the pool.
    func testCacheExpiryDoesNotReleaseFakeIPMapping() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let cache = DNSCache(eventLoop: loop)
        let pool = FakeIPPool(on: loop)
        let exp = expectation(description: "lifetime coupling")

        loop.execute {
            let domain = "leak.example"
            let fake = pool.assign(domain: domain)!
            let key = DNSCacheKey(domain: domain, type: .a)
            cache.insert(
                DNSCacheEntry(key: key, fakeIP: fake, expireAt: .now() - .seconds(1))
            )

            var swept: [DNSCacheEntry] = []
            cache.sweepExpired { swept = $0 }
            XCTAssertEqual(swept.count, 1)
            XCTAssertNil(cache.lookup(key), "cache entry must be gone")

            // Pool mapping survives — this is the architectural smell under test
            XCTAssertEqual(pool.reverseLookup(fake), domain)
            XCTAssertTrue(pool.isFakeIP(fake))
            XCTAssertEqual(pool.assign(domain: domain), fake, "same domain still reuses mapping")
            exp.fulfill()
        }

        wait(for: [exp], timeout: 1.0)
    }

    func testCacheOverwritePreservesLatestRealIPs() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let cache = DNSCache(eventLoop: loop)
        let key = DNSCacheKey(domain: "overwrite.example", type: .a)
        let fake = IPv4Address("198.18.2.2")!
        let exp = expectation(description: "overwrite")

        loop.execute {
            cache.insert(
                DNSCacheEntry(key: key, fakeIP: fake, expireAt: .now() + .seconds(30))
            )
            var updated = cache.lookup(key)!
            updated.realIPs = [IPv4Address("9.9.9.9")!]
            cache.insert(updated)
            XCTAssertEqual(cache.lookup(key)?.realIPs?.first, IPv4Address("9.9.9.9"))
            exp.fulfill()
        }

        wait(for: [exp], timeout: 1.0)
    }
}

final class DNSUpstreamUDPRelayTests: XCTestCase {
    func testUpstreamQueryTimeouts() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let relay = DNSUpstreamUDPRelay(
            eventLoop: loop,
            upstream: Upstream(host: "127.0.0.1", port: 9)
        )
        let exp = expectation(description: "timeout")

        loop.execute {
            let payload = Data(repeating: 0, count: 12)
            relay.query(payload, timeout: .milliseconds(50)).whenComplete { result in
                switch result {
                case let .failure(error):
                    XCTAssertEqual(error as? DNSUpstreamError, .timeout)
                    exp.fulfill()
                case .success:
                    XCTFail("Expected timeout, got success")
                }
            }
        }

        wait(for: [exp], timeout: 1.0)
    }

    func testMaxPendingLimitRejectsNewQueries() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let relay = DNSUpstreamUDPRelay(
            eventLoop: loop,
            upstream: Upstream(host: "127.0.0.1", port: 9)
        )
        let exp = expectation(description: "max pending limit")

        loop.execute {
            // Start the relay to ensure channel is ready
            relay.start().whenComplete { _ in
                // Fill up the pending map with 4096 queries (maxPending limit)
                // Note: 4096 matches the private maxPending constant in DNSUpstreamUDPRelay
                // We use a long timeout to keep queries pending while we test the limit
                var payload = Data(repeating: 0, count: 12)
                for i in 0 ..< 4096 {
                    // Create unique transaction IDs to avoid collisions
                    let txid = UInt16(i)
                    payload[0] = UInt8(txid >> 8)
                    payload[1] = UInt8(txid & 0xFF)
                    _ = relay.query(payload, timeout: .seconds(10))
                }

                // Try to add one more query - this should fail with notReady
                let overflowPayload = Data(repeating: 0xFF, count: 12)
                relay.query(overflowPayload, timeout: .seconds(1)).whenComplete { result in
                    switch result {
                    case let .failure(error):
                        XCTAssertEqual(
                            error as? DNSUpstreamError,
                            .notReady,
                            "Expected .notReady error when pending map is full"
                        )
                        exp.fulfill()
                    case .success:
                        XCTFail("Expected .notReady error, but query succeeded")
                    }

                    // Clean up: stop the relay to cancel all pending queries
                    relay.stop()
                }
            }
        }

        wait(for: [exp], timeout: 1.0)
    }

    /// Regression: payloads shorter than DNS header must fail fast with invalidPayload.
    func testInvalidPayloadRejected() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let relay = DNSUpstreamUDPRelay(
            eventLoop: loop,
            upstream: Upstream(host: "127.0.0.1", port: 9)
        )
        let exp = expectation(description: "invalid payload")

        loop.execute {
            relay.query(Data(repeating: 0, count: 11), timeout: .milliseconds(50)).whenComplete {
                result in
                switch result {
                case let .failure(error):
                    XCTAssertEqual(error as? DNSUpstreamError, .invalidPayload)
                    exp.fulfill()
                case .success:
                    XCTFail("expected invalidPayload")
                }
            }
        }

        wait(for: [exp], timeout: 1.0)
    }

    /// Regression: stop() fails in-flight queries with .stopped and clears pending.
    func testStopFailsPendingQueries() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let relay = DNSUpstreamUDPRelay(
            eventLoop: loop,
            upstream: Upstream(host: "127.0.0.1", port: 9)
        )
        let exp = expectation(description: "stopped")

        loop.execute {
            relay.start().whenComplete { _ in
                let payload = Data(repeating: 0, count: 12)
                relay.query(payload, timeout: .seconds(10)).whenComplete { result in
                    switch result {
                    case let .failure(error):
                        XCTAssertEqual(error as? DNSUpstreamError, .stopped)
                        exp.fulfill()
                    case .success:
                        XCTFail("expected stopped after relay.stop()")
                    }
                }
                relay.stop()
            }
        }

        wait(for: [exp], timeout: 2.0)
    }
}
