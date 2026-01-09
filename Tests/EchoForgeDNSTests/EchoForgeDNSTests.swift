@testable import EchoForgeDNS
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
    
    func testSmallNetworkCapacity() {
        // Test /30 network (hostMask = 3)
        // Should have 2 usable hosts: addresses 1 and 2
        // (0 = network, 3 = broadcast)
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let pool = FakeIPPool(cidr: "192.168.1.0/30", on: loop)
        loop.execute {
            let domain1 = "test1.com"
            let domain2 = "test2.com"
            let domain3 = "test3.com"
            
            let ip1 = pool.assign(domain: domain1)
            XCTAssertNotNil(ip1, "First allocation should succeed")
            
            let ip2 = pool.assign(domain: domain2)
            XCTAssertNotNil(ip2, "Second allocation should succeed")
            
            // Third allocation should fail as pool is exhausted
            let ip3 = pool.assign(domain: domain3)
            XCTAssertNil(ip3, "Third allocation should fail - pool exhausted")
            
            // Verify IPs are different
            XCTAssertNotEqual(ip1, ip2, "Allocated IPs should be different")
        }
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
        let entry = DNSCacheEntry(key: key, answers: [], expireAt: .now() - .seconds(1), realIPs: nil)
        loop.execute {
            cache.insert(entry)
            cache.sweepExpired { removed in
                XCTAssertEqual(removed.count, 1)
                XCTAssertEqual(removed.first?.key.domain, "b.com")
            }
            XCTAssertNil(cache.lookup(key))
        }
    }
}
