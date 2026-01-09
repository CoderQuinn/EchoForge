@testable import EchoForgeDNS
import NIO
import XCTest

final class FakeIPPoolTests: XCTestCase {
    func testAssignAndReverseLookup() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let pool = FakeIPPool(on: loop)
        try! loop.submit {
            let domain = "example.com"
            let ip = pool.assign(domain: domain)
            XCTAssertNotNil(ip)
            XCTAssertEqual(pool.reverseLookup(ip!), domain)
            XCTAssertTrue(pool.isFakeIP(ip!))
        }.wait()
    }
}

final class DNSCacheTests: XCTestCase {
    func testInsertAndLookup() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let cache = DNSCache(eventLoop: loop)
        let key = DNSCacheKey(domain: "a.com", type: .a)
        let entry = DNSCacheEntry(key: key, answers: [], expireAt: .now() + .seconds(10), realIPs: [IPv4Address("1.2.3.4")!])
        try! loop.submit {
            cache.insert(entry)
            let result = cache.lookup(key)
            XCTAssertNotNil(result)
            XCTAssertEqual(result?.realIPs?.first, IPv4Address("1.2.3.4"))
        }.wait()
    }

    func testSweepExpired() {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let cache = DNSCache(eventLoop: loop)
        let key = DNSCacheKey(domain: "b.com", type: .a)
        let entry = DNSCacheEntry(key: key, answers: [], expireAt: .now() - .seconds(1), realIPs: nil)
        try! loop.submit {
            cache.insert(entry)
            cache.sweepExpired { removed in
                XCTAssertEqual(removed.count, 1)
                XCTAssertEqual(removed.first?.key.domain, "b.com")
            }
            XCTAssertNil(cache.lookup(key))
        }.wait()
    }
}
