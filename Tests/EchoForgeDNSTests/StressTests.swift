import DNSClient
@testable import EchoForgeDNS
import Foundation
import Network
import NIO
import Testing

@Suite("Stress")
struct StressTests {
    /// Sequential stress test: issue many queries on a single event loop.
    @Test("Sequential stress allocations are unique")
    func sequentialStressAllocationsAreUnique() async throws {
        let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let eventLoop = eventLoopGroup.next()
        let router = DNSRouter(ipPool: FakeIPPool())

        let total = 500
        var seen = Set<UInt32>()

        for i in 0 ..< total {
            let domain = "seq\(i).local"
            let msg = try makeQueryMessage(domain: domain)
            let resp = try await router.handleInboundFuture(msg, on: eventLoop).get()
            #expect(resp.answers.count == 1)
            if case let .a(record)? = resp.answers.first {
                let ip = record.resource.address
                #expect(!seen.contains(ip))
                seen.insert(ip)
            } else {
                Issue.record("Expected A record in response")
            }
        }

        #expect(seen.count == total)
        try? await eventLoopGroup.shutdownGracefully()
    }

    /// Concurrent stress test using TaskGroup and an actor to track uniqueness.
    @Test("Concurrent stress allocations are unique")
    func concurrentStressAllocationsAreUnique() async throws {
        let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        let eventLoop = eventLoopGroup.next()
        let router = DNSRouter(ipPool: FakeIPPool())

        let concurrency = max(4, System.coreCount)
        let perWorker = 100
        let total = concurrency * perWorker

        actor Results {
            private var seen = Set<UInt32>()
            private(set) var errors: [String] = []
            func record(ip: UInt32, for domain: String) {
                if seen.contains(ip) {
                    errors.append("Duplicate IP \(ip) for domain \(domain)")
                } else {
                    seen.insert(ip)
                }
            }

            func addError(_ message: String) { errors.append(message) }
            func count() -> Int { seen.count }
        }
        let results = Results()

        await withTaskGroup(of: Void.self) { group in
            for t in 0 ..< concurrency {
                group.addTask {
                    for i in 0 ..< perWorker {
                        let idx = t * perWorker + i
                        let domain = "concurrent\(idx).local"
                        do {
                            let msg = try makeQueryMessage(domain: domain)
                            let resp = try await router.handleInboundFuture(msg, on: eventLoop).get()
                            if resp.answers.count != 1 {
                                await results.addError("Expected one A answer for \(domain)")
                                continue
                            }
                            if case let .a(record)? = resp.answers.first {
                                await results.record(ip: record.resource.address, for: domain)
                            } else {
                                await results.addError("Expected A record for \(domain)")
                            }
                        } catch {
                            await results.addError("Error for \(domain): \(error)")
                        }
                    }
                }
            }
        }

        let errors = await results.errors
        let uniqueCount = await results.count()
        #expect(errors.isEmpty, "Errors during concurrent allocations: \(errors)")
        #expect(uniqueCount == total, "Expected \(total) unique IPs assigned")
        try? await eventLoopGroup.shutdownGracefully()
    }
}
