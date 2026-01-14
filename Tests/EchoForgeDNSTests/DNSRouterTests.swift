import DNSClient
@testable import EchoForgeDNS
import NIO
import Testing

@Suite("DNSRouter")
struct DNSRouterTests {
    final class MockDNSResolver: DNSResolverProtocol {
        var responses: [String: UInt32] = [:]

        func resolveMessage(forHost host: String, type _: DNSResourceType, on eventLoop: EventLoop) -> EventLoopFuture<Message> {
            do {
                let msg = try makeResponseMessage(domain: host, ip: responses[host], id: UInt16.random(in: 0 ... UInt16.max))
                return eventLoop.makeSucceededFuture(msg)
            } catch {
                return eventLoop.makeFailedFuture(error)
            }
        }
    }

    @Test("Local A resolution from pool")
    func localAResolution() async throws {
        let ipPool = FakeIPPool()
        let router = DNSRouter(upstream: nil, ipPool: ipPool)
        let eventLoop = EmbeddedEventLoop()

        let message = try makeQueryMessage(domain: "local.test")

        let response = try router.handleInboundFuture(message, on: eventLoop).wait()
        #expect(response.answers.count == 1)
        if case let .a(record)? = response.answers.first {
            let assigned = await ipPool.assign(domain: "local.test")
            #expect(assigned != nil)
            if let assigned = assigned {
                #expect(record.resource.address == assigned.uint32Value)
            }
        } else {
            Issue.record("Expected A record")
        }
    }

    @Test("Upstream resolution for non-A type")
    func upstreamResolution() throws {
        let mock = MockDNSResolver()
        mock.responses["upstream.test"] = IPUtils.ipv4ToUInt32("5.6.7.8")

        let router = DNSRouter(upstream: mock, ipPool: FakeIPPool())
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let eventLoop = group.next()

        // Request a non-A type so the router will forward to upstream (A queries are handled locally)
        let message = try makeQueryMessage(domain: "upstream.test", type: .ns)

        let response = try router.handleInboundFuture(message, on: eventLoop).wait()
        #expect(response.answers.count == 1)
        if case let .a(record)? = response.answers.first {
            #expect(record.resource.stringAddress == "5.6.7.8")
        } else {
            Issue.record("Expected A record from upstream")
        }
    }
}
