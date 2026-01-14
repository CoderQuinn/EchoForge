@testable import EchoForge
import Foundation
import Network
import NIO
import XCTest

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
        let pool = FakeIPPool(cidr: "198.18.0.0/29", on: loop) // 4 usable hosts
        let exp = expectation(description: "exhaustion")

        loop.execute {
            var allocated: [IPv4Address] = []
            for i in 0..<4 {
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
}

final class DNSCacheTests: XCTestCase {
    func testInsertAndLookup() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let cache = DNSCache(eventLoop: loop)
        let key = DNSCacheKey(domain: "a.com", type: .a)
        let fake = IPv4Address("198.18.1.2")!
        let entry = DNSCacheEntry(key: key, fakeIP: fake, expireAt: .now() + .seconds(10), realIPs: [IPv4Address("1.2.3.4")!])
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
        let entry = DNSCacheEntry(key: key, fakeIP: fake, expireAt: .now() - .seconds(1), realIPs: nil)
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
        let entry = DNSCacheEntry(key: key, fakeIP: IPv4Address("198.18.1.10")!, expireAt: .now() - .seconds(1))
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
        let expiredEntry = DNSCacheEntry(key: expiredKey, fakeIP: IPv4Address("198.18.1.11")!, expireAt: .now() - .seconds(1))
        let liveEntry = DNSCacheEntry(key: liveKey, fakeIP: IPv4Address("198.18.1.12")!, expireAt: .now() + .seconds(30))
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
}

final class DNSUpstreamUDPRelayTests: XCTestCase {
    func testUpstreamQueryTimeouts() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let relay = DNSUpstreamUDPRelay(eventLoop: loop, upstream: Upstream(host: "127.0.0.1", port: 9))
        let exp = expectation(description: "timeout")

        loop.execute {
            let payload = Data(repeating: 0, count: 12)
            relay.query(payload, timeout: .milliseconds(50)).whenComplete { result in
                switch result {
                case .failure(let error):
                    XCTAssertEqual(error as? DNSUpstreamError, .timeout)
                    exp.fulfill()
                case .success:
                    XCTFail("Expected timeout, got success")
                }
            }
        }

        wait(for: [exp], timeout: 1.0)
    }
}
