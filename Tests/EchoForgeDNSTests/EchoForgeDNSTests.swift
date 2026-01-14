import DNSClient
@testable import EchoForgeDNS
import Network
import NIO
import Testing

@Suite("EchoForgeDNS")
struct EchoForgeDNSSuite {
    /// Mock upstream resolver
    final class MockDNSResolver: DNSResolverProtocol {
        var responses: [String: UInt32] = [:] // stores host -> IPv4 host byte order
        func resolveMessage(forHost host: String, type _: DNSResourceType, on eventLoop: EventLoop) -> EventLoopFuture<Message> {
            // Build a raw DNS response packet and parse it using DNSDecoder
            do {
                let ip = responses[host]
                let message = try makeResponseMessage(domain: host, ip: ip, id: UInt16.random(in: 0 ... UInt16.max))
                return eventLoop.makeSucceededFuture(message)
            } catch {
                return eventLoop.makeFailedFuture(error)
            }
        }
    }

    @Test("Fake IP assignment for A queries")
    func fakeIPAssignment() async throws {
        let ipPool = FakeIPPool()
        let router = DNSRouter(upstream: nil, ipPool: ipPool)
        let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let eventLoop = eventLoopGroup.next()

        let message = try makeQueryMessage(domain: "local.com")
        let response = try await router.handleInboundFuture(message, on: eventLoop).get()
        #expect(response.answers.count == 1)
        if case let .a(record)? = response.answers.first {
            let assignedIP = await ipPool.assign(domain: "local.com")
            #expect(assignedIP != nil)
            if let assignedIP = assignedIP {
                #expect(record.resource.address == assignedIP.uint32Value)
            }
        } else {
            Issue.record("Expected A record")
        }
        try? await eventLoopGroup.shutdownGracefully()
    }

    @Test("Reverse lookup returns original domain")
    func reverseLookup() async throws {
        let ipPool = FakeIPPool()
        let router = DNSRouter(upstream: nil, ipPool: ipPool)
        let assignedIP = await ipPool.assign(domain: "reverse.com")
        #expect(assignedIP != nil)
        if let assignedIP = assignedIP {
            let domain = await router.reverseLookupFakeIP(for: assignedIP)
            #expect(domain == "reverse.com")
        }
    }

    @Test("Non-A queries forwarded to upstream")
    func upstreamResolution() async throws {
        let mockResolver = MockDNSResolver()
        mockResolver.responses["upstream.com"] = IPUtils.ipv4ToUInt32("1.2.3.4")

        let router = DNSRouter(upstream: mockResolver, ipPool: FakeIPPool())
        let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let eventLoop = eventLoopGroup.next()

        // Request a non-A type to ensure the router forwards to upstream (A queries are served locally)
        let message = try makeQueryMessage(domain: "upstream.com", type: .ns)
        let response = try await router.handleInboundFuture(message, on: eventLoop).get()
        #expect(response.answers.count == 1)
        if case let .a(record)? = response.answers.first {
            #expect(record.resource.stringAddress == "1.2.3.4")
        } else {
            Issue.record("Expected A record from upstream")
        }
        try? await eventLoopGroup.shutdownGracefully()
    }

    @Test("SERVFAIL when FakeIPPool assignment fails")
    func servfailOnPoolExhaustion() async throws {
        // Use a /31 network which has 2 addresses (network+broadcast), yielding 0 usable hosts.
        // This makes FakeIPPool return nil immediately, simulating exhaustion.
        let ipPool = FakeIPPool(cidr: "198.18.0.0/31")
        let router = DNSRouter(upstream: nil, ipPool: ipPool)
        let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let eventLoop = eventLoopGroup.next()

        let message = try makeQueryMessage(domain: "exhausted.example", type: .a)
        let response = try await router.handleInboundFuture(message, on: eventLoop).get()

        // When pool is exhausted, router should return empty answers and RCODE == 2 (SERVFAIL)
        #expect(response.answers.count == 0)
        let rcode = response.header.options.rawValue & 0x000F
        #expect(rcode == 2, "Expected RCODE=2 (SERVFAIL) when FakeIPPool assignment fails")
        try? await eventLoopGroup.shutdownGracefully()
    }

    @Test("Two different hosts get distinct fake IPs")
    func twoHostsGetDistinctFakeIPs() async throws {
        let ipPool = FakeIPPool()
        let router = DNSRouter(upstream: nil, ipPool: ipPool)
        let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let eventLoop = eventLoopGroup.next()

        let msg1 = try makeQueryMessage(domain: "host1.local")
        let resp1 = try await router.handleInboundFuture(msg1, on: eventLoop).get()
        #expect(resp1.answers.count == 1)
        var ip1: UInt32 = 0
        if case let .a(record)? = resp1.answers.first {
            ip1 = record.resource.address
        } else {
            Issue.record("Expected A record for host1.local")
            return
        }

        let msg2 = try makeQueryMessage(domain: "host2.local")
        let resp2 = try await router.handleInboundFuture(msg2, on: eventLoop).get()
        #expect(resp2.answers.count == 1)
        var ip2: UInt32 = 0
        if case let .a(record)? = resp2.answers.first {
            ip2 = record.resource.address
        } else {
            Issue.record("Expected A record for host2.local")
            return
        }

        #expect(ip1 != ip2, "Two different hosts should receive different fake IPs")
        try? await eventLoopGroup.shutdownGracefully()
    }

    @Test("Clearing pool removes reverse mappings")
    func testClearFakeIPPool() async throws {
        let ipPool = FakeIPPool()
        let router = DNSRouter(upstream: nil, ipPool: ipPool)
        let oldIP = await ipPool.assign(domain: "clear.com")
        #expect(oldIP != nil)
        if let oldIP = oldIP {
            #expect(await router.reverseLookupFakeIP(for: oldIP) == "clear.com")
        }
        await router.clearFakeIPPool()

        _ = await ipPool.assign(domain: "clear.com1")
        // Reassigning the same domain will generate a new IP
        let newIP = await ipPool.assign(domain: "clear.com")
        // old mapping should be cleared
        if let oldIP = oldIP {
            #expect(await router.reverseLookupFakeIP(for: oldIP) == nil) // previous mapping has been cleared
        }
        // new mapping exists for the new IP
        #expect(newIP != nil)
        if let newIP = newIP {
            #expect(await router.reverseLookupFakeIP(for: newIP) == "clear.com")
        }
    }
}
