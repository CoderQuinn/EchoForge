//
//  DNSUpstreamGroupTests.swift
//  EchoForge
//
//  Created by GitHub Copilot on 2026/2/2.
//

import Foundation
import NIO
import XCTest

@testable import EchoForge

final class DNSUpstreamGroupTests: XCTestCase {
    var group: MultiThreadedEventLoopGroup!
    var loop: EventLoop!

    override func setUp() {
        super.setUp()
        group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        loop = group.next()
    }

    override func tearDown() {
        try? group.syncShutdownGracefully()
        super.tearDown()
    }

    // MARK: - Mock DNSUpstream

    final class MockDNSUpstream: DNSUpstream, @unchecked Sendable {
        let eventLoop: EventLoop
        let delay: TimeAmount
        let shouldFail: Bool
        let responseData: Data
        var queryCount = 0
        var startCalled = false
        var stopCalled = false

        init(
            eventLoop: EventLoop,
            delay: TimeAmount = .milliseconds(0),
            shouldFail: Bool = false,
            responseData: Data = Data([0x12, 0x34])
        ) {
            self.eventLoop = eventLoop
            self.delay = delay
            self.shouldFail = shouldFail
            self.responseData = responseData
        }

        func query(_: Data, timeout _: TimeAmount) -> EventLoopFuture<Data> {
            eventLoop.assertInEventLoop()
            queryCount += 1

            let promise = eventLoop.makePromise(of: Data.self)

            eventLoop.scheduleTask(in: delay) {
                if self.shouldFail {
                    promise.fail(DNSUpstreamError.notReady)
                } else {
                    promise.succeed(self.responseData)
                }
            }

            return promise.futureResult
        }

        func start() -> EventLoopFuture<Void> {
            eventLoop.assertInEventLoop()
            startCalled = true
            return eventLoop.makeSucceededFuture(())
        }

        func stop() {
            eventLoop.assertInEventLoop()
            stopCalled = true
        }
    }

    // MARK: - Test: Primary Succeeds Before Hedge Delay

    func testPrimarySucceedsBeforeHedgeDelay() {
        let exp = expectation(description: "Primary succeeds before hedge")

        let primary = MockDNSUpstream(eventLoop: loop, delay: .milliseconds(10))
        let secondary = MockDNSUpstream(eventLoop: loop, delay: .milliseconds(100))

        let primaryBreaker = DNSUpstreamBreaker()
        let secondaryBreaker = DNSUpstreamBreaker()

        let upstreamGroup = DNSUpstreamGroup(
            eventLoop: loop,
            primary: .init(upstream: primary, breaker: primaryBreaker),
            secondary: [.init(upstream: secondary, breaker: secondaryBreaker)],
            hedgeDelay: .milliseconds(50),
            slowUpstreamDeadline: .milliseconds(200)
        )

        loop.execute {
            upstreamGroup.query(Data([0x00, 0x01]), timeout: .seconds(1)).whenComplete { result in
                switch result {
                case let .success(data):
                    XCTAssertEqual(data, Data([0x12, 0x34]), "Should get primary response")
                    XCTAssertEqual(primary.queryCount, 1, "Primary should be queried once")
                    XCTAssertEqual(
                        secondary.queryCount,
                        0,
                        "Secondary should not be queried (hedge delay not reached)"
                    )
                case let .failure(error):
                    XCTFail("Query should succeed: \(error)")
                }
                exp.fulfill()
            }
        }

        wait(for: [exp], timeout: 2.0)
    }

    // MARK: - Test: Secondary Responds Faster Than Primary

    func testSecondaryRespondsBeforePrimary() {
        let exp = expectation(description: "Secondary responds faster")

        let primary = MockDNSUpstream(
            eventLoop: loop,
            delay: .milliseconds(200),
            responseData: Data([0xAA, 0xBB])
        )
        let secondary = MockDNSUpstream(
            eventLoop: loop,
            delay: .milliseconds(10),
            responseData: Data([0xCC, 0xDD])
        )

        let primaryBreaker = DNSUpstreamBreaker()
        let secondaryBreaker = DNSUpstreamBreaker()

        let upstreamGroup = DNSUpstreamGroup(
            eventLoop: loop,
            primary: .init(upstream: primary, breaker: primaryBreaker),
            secondary: [.init(upstream: secondary, breaker: secondaryBreaker)],
            hedgeDelay: .milliseconds(50),
            slowUpstreamDeadline: .milliseconds(100)
        )

        loop.execute {
            upstreamGroup.query(Data([0x00, 0x01]), timeout: .seconds(1)).whenComplete { result in
                switch result {
                case let .success(data):
                    XCTAssertEqual(data, Data([0xCC, 0xDD]), "Should get secondary response")
                    XCTAssertEqual(primary.queryCount, 1, "Primary should be queried")
                    XCTAssertEqual(secondary.queryCount, 1, "Secondary should be queried")
                case let .failure(error):
                    XCTFail("Query should succeed: \(error)")
                }
                exp.fulfill()
            }
        }

        wait(for: [exp], timeout: 2.0)
    }

    // MARK: - Test: All Upstreams Fail

    func testAllUpstreamsFail() {
        let exp = expectation(description: "All upstreams fail")

        let primary = MockDNSUpstream(eventLoop: loop, delay: .milliseconds(10), shouldFail: true)
        let secondary1 = MockDNSUpstream(
            eventLoop: loop,
            delay: .milliseconds(10),
            shouldFail: true
        )
        let secondary2 = MockDNSUpstream(
            eventLoop: loop,
            delay: .milliseconds(10),
            shouldFail: true
        )

        let primaryBreaker = DNSUpstreamBreaker()
        let secondaryBreaker1 = DNSUpstreamBreaker()
        let secondaryBreaker2 = DNSUpstreamBreaker()

        let upstreamGroup = DNSUpstreamGroup(
            eventLoop: loop,
            primary: .init(upstream: primary, breaker: primaryBreaker),
            secondary: [
                .init(upstream: secondary1, breaker: secondaryBreaker1),
                .init(upstream: secondary2, breaker: secondaryBreaker2),
            ],
            hedgeDelay: .milliseconds(50),
            slowUpstreamDeadline: .milliseconds(100)
        )

        loop.execute {
            upstreamGroup.query(Data([0x00, 0x01]), timeout: .seconds(1)).whenComplete { result in
                switch result {
                case .success:
                    XCTFail("Query should fail when all upstreams fail")
                case let .failure(error):
                    XCTAssertEqual(
                        error as? DNSUpstreamError,
                        .notReady,
                        "Should fail with notReady error"
                    )
                    XCTAssertEqual(primary.queryCount, 1, "Primary should be queried")
                    XCTAssertEqual(secondary1.queryCount, 1, "Secondary1 should be queried")
                    XCTAssertEqual(secondary2.queryCount, 1, "Secondary2 should be queried")
                }
                exp.fulfill()
            }
        }

        wait(for: [exp], timeout: 2.0)
    }

    // MARK: - Test: Timeout Occurs

    func testTimeoutOccurs() {
        let exp = expectation(description: "Timeout occurs")

        // All upstreams are very slow
        let primary = MockDNSUpstream(eventLoop: loop, delay: .seconds(10))
        let secondary = MockDNSUpstream(eventLoop: loop, delay: .seconds(10))

        let primaryBreaker = DNSUpstreamBreaker()
        let secondaryBreaker = DNSUpstreamBreaker()

        let upstreamGroup = DNSUpstreamGroup(
            eventLoop: loop,
            primary: .init(upstream: primary, breaker: primaryBreaker),
            secondary: [.init(upstream: secondary, breaker: secondaryBreaker)],
            hedgeDelay: .milliseconds(50),
            slowUpstreamDeadline: .milliseconds(200)
        )

        loop.execute {
            upstreamGroup.query(Data([0x00, 0x01]), timeout: .milliseconds(100)).whenComplete {
                result in
                switch result {
                case .success:
                    XCTFail("Query should timeout")
                case let .failure(error):
                    XCTAssertEqual(
                        error as? DNSUpstreamError,
                        .timeout,
                        "Should fail with timeout error"
                    )
                }
                exp.fulfill()
            }
        }

        wait(for: [exp], timeout: 2.0)
    }

    // MARK: - Test: Circuit Breaker Prevents Requests

    func testCircuitBreakerPreventsRequests() {
        let exp = expectation(description: "Circuit breaker prevents requests")

        let primary = MockDNSUpstream(eventLoop: loop)
        let secondary = MockDNSUpstream(eventLoop: loop)

        let primaryBreaker = DNSUpstreamBreaker(failThreshold: 1, degradeDuration: .seconds(10))
        let secondaryBreaker = DNSUpstreamBreaker(failThreshold: 1, degradeDuration: .seconds(10))

        // Degrade both breakers
        primaryBreaker.onFailure()
        secondaryBreaker.onFailure()

        let upstreamGroup = DNSUpstreamGroup(
            eventLoop: loop,
            primary: .init(upstream: primary, breaker: primaryBreaker),
            secondary: [.init(upstream: secondary, breaker: secondaryBreaker)],
            hedgeDelay: .milliseconds(50),
            slowUpstreamDeadline: .milliseconds(100)
        )

        loop.execute {
            upstreamGroup.query(Data([0x00, 0x01]), timeout: .seconds(1)).whenComplete { result in
                switch result {
                case .success:
                    XCTFail("Query should fail when all breakers are open")
                case let .failure(error):
                    XCTAssertEqual(
                        error as? DNSUpstreamError,
                        .notReady,
                        "Should fail with notReady error"
                    )
                    XCTAssertEqual(
                        primary.queryCount,
                        0,
                        "Primary should not be queried (blocked by breaker)"
                    )
                    XCTAssertEqual(
                        secondary.queryCount,
                        0,
                        "Secondary should not be queried (blocked by breaker)"
                    )
                }
                exp.fulfill()
            }
        }

        wait(for: [exp], timeout: 2.0)
    }

    // MARK: - Test: Circuit Breaker with Partial Availability

    func testCircuitBreakerPartialAvailability() {
        let exp = expectation(description: "Circuit breaker partial availability")

        let primary = MockDNSUpstream(eventLoop: loop, delay: .milliseconds(10))
        let secondary = MockDNSUpstream(
            eventLoop: loop,
            delay: .milliseconds(10),
            responseData: Data([0xFF, 0xEE])
        )

        let primaryBreaker = DNSUpstreamBreaker(failThreshold: 1, degradeDuration: .seconds(10))
        let secondaryBreaker = DNSUpstreamBreaker()

        // Degrade only primary breaker
        primaryBreaker.onFailure()

        let upstreamGroup = DNSUpstreamGroup(
            eventLoop: loop,
            primary: .init(upstream: primary, breaker: primaryBreaker),
            secondary: [.init(upstream: secondary, breaker: secondaryBreaker)],
            hedgeDelay: .milliseconds(50),
            slowUpstreamDeadline: .milliseconds(100)
        )

        loop.execute {
            upstreamGroup.query(Data([0x00, 0x01]), timeout: .seconds(1)).whenComplete { result in
                switch result {
                case let .success(data):
                    XCTAssertEqual(data, Data([0xFF, 0xEE]), "Should get secondary response")
                    XCTAssertEqual(
                        primary.queryCount,
                        0,
                        "Primary should not be queried (blocked by breaker)"
                    )
                    XCTAssertEqual(secondary.queryCount, 1, "Secondary should be queried")
                case let .failure(error):
                    XCTFail("Query should succeed via secondary: \(error)")
                }
                exp.fulfill()
            }
        }

        wait(for: [exp], timeout: 2.0)
    }

    // MARK: - Test: RTT-Based Slow Upstream Detection

    func testRTTBasedSlowUpstreamDetection() {
        let exp = expectation(description: "RTT-based slow upstream detection")

        let slowPrimary = MockDNSUpstream(
            eventLoop: loop,
            delay: .milliseconds(250) // Slower than slowUpstreamDeadline (200ms)
        )

        let primaryBreaker = DNSUpstreamBreaker(failThreshold: 1, degradeDuration: .seconds(10))
        let secondaryBreaker = DNSUpstreamBreaker()

        let upstreamGroup = DNSUpstreamGroup(
            eventLoop: loop,
            primary: .init(upstream: slowPrimary, breaker: primaryBreaker),
            secondary: [],
            hedgeDelay: .milliseconds(50),
            slowUpstreamDeadline: .milliseconds(200) // Threshold for "slow" response
        )

        loop.execute {
            // First query - primary is slow but succeeds
            upstreamGroup.query(Data([0x00, 0x01]), timeout: .seconds(1)).whenComplete { result in
                switch result {
                case .success:
                    // The breaker should have been triggered due to slow RTT
                    XCTAssertTrue(
                        primaryBreaker.isOpen(),
                        "Breaker should be open after slow response"
                    )

                    // Try another query - should fail because breaker is open
                    upstreamGroup.query(Data([0x00, 0x02]), timeout: .seconds(1)).whenComplete {
                        secondResult in
                        switch secondResult {
                        case .success:
                            XCTFail("Second query should fail when breaker is open")
                        case let .failure(error):
                            XCTAssertEqual(
                                error as? DNSUpstreamError,
                                .notReady,
                                "Should fail with notReady error"
                            )
                            XCTAssertEqual(
                                slowPrimary.queryCount,
                                1,
                                "Primary should only be queried once (blocked second time)"
                            )
                        }
                        exp.fulfill()
                    }
                case let .failure(error):
                    XCTFail("First query should succeed: \(error)")
                    exp.fulfill()
                }
            }
        }

        wait(for: [exp], timeout: 3.0)
    }

    // MARK: - Test: Fast RTT Does Not Trigger Breaker

    func testFastRTTDoesNotTriggerBreaker() {
        let exp = expectation(description: "Fast RTT does not trigger breaker")

        let fastPrimary = MockDNSUpstream(
            eventLoop: loop,
            delay: .milliseconds(50) // Faster than slowUpstreamDeadline (200ms)
        )

        let primaryBreaker = DNSUpstreamBreaker(failThreshold: 1, degradeDuration: .seconds(10))

        let upstreamGroup = DNSUpstreamGroup(
            eventLoop: loop,
            primary: .init(upstream: fastPrimary, breaker: primaryBreaker),
            secondary: [],
            hedgeDelay: .milliseconds(100),
            slowUpstreamDeadline: .milliseconds(200)
        )

        loop.execute {
            upstreamGroup.query(Data([0x00, 0x01]), timeout: .seconds(1)).whenComplete { result in
                switch result {
                case .success:
                    // The breaker should NOT be triggered
                    XCTAssertFalse(
                        primaryBreaker.isOpen(),
                        "Breaker should not be open after fast response"
                    )

                    // Try another query - should succeed
                    upstreamGroup.query(Data([0x00, 0x02]), timeout: .seconds(1)).whenComplete {
                        secondResult in
                        switch secondResult {
                        case .success:
                            XCTAssertEqual(
                                fastPrimary.queryCount,
                                2,
                                "Primary should be queried twice"
                            )
                        case let .failure(error):
                            XCTFail("Second query should succeed: \(error)")
                        }
                        exp.fulfill()
                    }
                case let .failure(error):
                    XCTFail("First query should succeed: \(error)")
                    exp.fulfill()
                }
            }
        }

        wait(for: [exp], timeout: 3.0)
    }

    // MARK: - Test: Lifecycle - Start

    func testLifecycleStart() {
        let exp = expectation(description: "Start lifecycle")

        let primary = MockDNSUpstream(eventLoop: loop)
        let secondary1 = MockDNSUpstream(eventLoop: loop)
        let secondary2 = MockDNSUpstream(eventLoop: loop)

        let primaryBreaker = DNSUpstreamBreaker()
        let secondaryBreaker1 = DNSUpstreamBreaker()
        let secondaryBreaker2 = DNSUpstreamBreaker()

        let upstreamGroup = DNSUpstreamGroup(
            eventLoop: loop,
            primary: .init(upstream: primary, breaker: primaryBreaker),
            secondary: [
                .init(upstream: secondary1, breaker: secondaryBreaker1),
                .init(upstream: secondary2, breaker: secondaryBreaker2),
            ],
            hedgeDelay: .milliseconds(50),
            slowUpstreamDeadline: .milliseconds(100)
        )

        loop.execute {
            upstreamGroup.start().whenComplete { result in
                switch result {
                case .success:
                    XCTAssertTrue(primary.startCalled, "Primary start should be called")
                    XCTAssertTrue(secondary1.startCalled, "Secondary1 start should be called")
                    XCTAssertTrue(secondary2.startCalled, "Secondary2 start should be called")
                case let .failure(error):
                    XCTFail("Start should succeed: \(error)")
                }
                exp.fulfill()
            }
        }

        wait(for: [exp], timeout: 2.0)
    }

    // MARK: - Test: Lifecycle - Stop

    func testLifecycleStop() {
        let primary = MockDNSUpstream(eventLoop: loop)
        let secondary = MockDNSUpstream(eventLoop: loop)

        let primaryBreaker = DNSUpstreamBreaker()
        let secondaryBreaker = DNSUpstreamBreaker()

        let upstreamGroup = DNSUpstreamGroup(
            eventLoop: loop,
            primary: .init(upstream: primary, breaker: primaryBreaker),
            secondary: [.init(upstream: secondary, breaker: secondaryBreaker)],
            hedgeDelay: .milliseconds(50),
            slowUpstreamDeadline: .milliseconds(100)
        )

        upstreamGroup.stop()

        // Give the event loop time to execute
        let exp = expectation(description: "Stop lifecycle")
        loop.execute {
            XCTAssertTrue(primary.stopCalled, "Primary stop should be called")
            XCTAssertTrue(secondary.stopCalled, "Secondary stop should be called")
            exp.fulfill()
        }

        wait(for: [exp], timeout: 1.0)
    }

    // MARK: - Test: Multiple Secondary Upstreams

    func testMultipleSecondaryUpstreams() {
        let exp = expectation(description: "Multiple secondary upstreams")

        let primary = MockDNSUpstream(eventLoop: loop, delay: .seconds(10)) // Very slow
        let secondary1 = MockDNSUpstream(eventLoop: loop, delay: .milliseconds(100))
        let secondary2 = MockDNSUpstream(
            eventLoop: loop,
            delay: .milliseconds(20),
            responseData: Data([0x11, 0x22])
        ) // Fastest

        let primaryBreaker = DNSUpstreamBreaker()
        let secondaryBreaker1 = DNSUpstreamBreaker()
        let secondaryBreaker2 = DNSUpstreamBreaker()

        let upstreamGroup = DNSUpstreamGroup(
            eventLoop: loop,
            primary: .init(upstream: primary, breaker: primaryBreaker),
            secondary: [
                .init(upstream: secondary1, breaker: secondaryBreaker1),
                .init(upstream: secondary2, breaker: secondaryBreaker2),
            ],
            hedgeDelay: .milliseconds(50),
            slowUpstreamDeadline: .milliseconds(100)
        )

        loop.execute {
            upstreamGroup.query(Data([0x00, 0x01]), timeout: .seconds(1)).whenComplete { result in
                switch result {
                case let .success(data):
                    XCTAssertEqual(
                        data,
                        Data([0x11, 0x22]),
                        "Should get fastest secondary response"
                    )
                    XCTAssertEqual(primary.queryCount, 1, "Primary should be queried")
                    XCTAssertEqual(secondary1.queryCount, 1, "Secondary1 should be queried")
                    XCTAssertEqual(secondary2.queryCount, 1, "Secondary2 should be queried")
                case let .failure(error):
                    XCTFail("Query should succeed: \(error)")
                }
                exp.fulfill()
            }
        }

        wait(for: [exp], timeout: 2.0)
    }

    // MARK: - Test: Hedge Query Cancellation After Primary Success

    func testHedgeQueryCancellationAfterPrimarySuccess() {
        let exp = expectation(description: "Hedge cancellation after primary success")

        let primary = MockDNSUpstream(eventLoop: loop, delay: .milliseconds(10))
        let secondary = MockDNSUpstream(eventLoop: loop, delay: .milliseconds(200))

        let primaryBreaker = DNSUpstreamBreaker()
        let secondaryBreaker = DNSUpstreamBreaker()

        let upstreamGroup = DNSUpstreamGroup(
            eventLoop: loop,
            primary: .init(upstream: primary, breaker: primaryBreaker),
            secondary: [.init(upstream: secondary, breaker: secondaryBreaker)],
            hedgeDelay: .milliseconds(50),
            slowUpstreamDeadline: .milliseconds(300)
        )

        loop.execute {
            upstreamGroup.query(Data([0x00, 0x01]), timeout: .seconds(1)).whenComplete { result in
                switch result {
                case .success:
                    XCTAssertEqual(primary.queryCount, 1, "Primary should be queried")
                    // Give time for hedge to potentially fire
                    self.loop.scheduleTask(in: .milliseconds(100)) {
                        // Secondary might have been started by the hedge, but result should be ignored
                        // We just verify that the primary succeeded and the query completed
                        exp.fulfill()
                    }
                case let .failure(error):
                    XCTFail("Query should succeed: \(error)")
                    exp.fulfill()
                }
            }
        }

        wait(for: [exp], timeout: 2.0)
    }

    // MARK: - Test: Race Condition - Responses After Timeout

    func testResponsesAfterTimeout() {
        let exp = expectation(description: "Responses after timeout")

        let primary = MockDNSUpstream(eventLoop: loop, delay: .milliseconds(500))
        let secondary = MockDNSUpstream(eventLoop: loop, delay: .milliseconds(500))

        let primaryBreaker = DNSUpstreamBreaker()
        let secondaryBreaker = DNSUpstreamBreaker()

        let upstreamGroup = DNSUpstreamGroup(
            eventLoop: loop,
            primary: .init(upstream: primary, breaker: primaryBreaker),
            secondary: [.init(upstream: secondary, breaker: secondaryBreaker)],
            hedgeDelay: .milliseconds(50),
            slowUpstreamDeadline: .milliseconds(100)
        )

        loop.execute {
            upstreamGroup.query(Data([0x00, 0x01]), timeout: .milliseconds(100)).whenComplete {
                result in
                switch result {
                case .success:
                    XCTFail("Query should timeout")
                case let .failure(error):
                    XCTAssertEqual(
                        error as? DNSUpstreamError,
                        .timeout,
                        "Should fail with timeout error"
                    )

                    // Wait a bit to ensure late responses don't cause issues
                    self.loop.scheduleTask(in: .seconds(1)) {
                        // If we get here without crashes, the race condition is handled
                        exp.fulfill()
                    }
                }
            }
        }

        wait(for: [exp], timeout: 3.0)
    }

    // MARK: - Test: Breaker Integration with Success

    func testBreakerIntegrationWithSuccess() {
        let exp = expectation(description: "Breaker integration with success")

        let primary = MockDNSUpstream(eventLoop: loop, delay: .milliseconds(10))

        let primaryBreaker = DNSUpstreamBreaker(failThreshold: 2, degradeDuration: .seconds(10))

        let upstreamGroup = DNSUpstreamGroup(
            eventLoop: loop,
            primary: .init(upstream: primary, breaker: primaryBreaker),
            secondary: [],
            hedgeDelay: .milliseconds(50),
            slowUpstreamDeadline: .milliseconds(100)
        )

        loop.execute {
            // Successful query should call onSuccess on the breaker
            upstreamGroup.query(Data([0x00, 0x01]), timeout: .seconds(1)).whenComplete { result in
                switch result {
                case .success:
                    // Verify breaker is not degraded
                    XCTAssertFalse(
                        primaryBreaker.isOpen(),
                        "Breaker should not be open after successful query"
                    )
                case let .failure(error):
                    XCTFail("Query should succeed: \(error)")
                }
                exp.fulfill()
            }
        }

        wait(for: [exp], timeout: 2.0)
    }

    // MARK: - Test: Breaker Integration with Failure

    func testBreakerIntegrationWithFailure() {
        let exp = expectation(description: "Breaker integration with failure")

        let primary = MockDNSUpstream(eventLoop: loop, delay: .milliseconds(10), shouldFail: true)

        let primaryBreaker = DNSUpstreamBreaker(failThreshold: 1, degradeDuration: .seconds(10))

        let upstreamGroup = DNSUpstreamGroup(
            eventLoop: loop,
            primary: .init(upstream: primary, breaker: primaryBreaker),
            secondary: [],
            hedgeDelay: .milliseconds(50),
            slowUpstreamDeadline: .milliseconds(100)
        )

        loop.execute {
            // Failed query should call onFailure on the breaker
            upstreamGroup.query(Data([0x00, 0x01]), timeout: .seconds(1)).whenComplete { result in
                switch result {
                case .success:
                    XCTFail("Query should fail")
                case .failure:
                    // Verify breaker is now degraded
                    XCTAssertTrue(
                        primaryBreaker.isOpen(),
                        "Breaker should be open after failed query"
                    )
                }
                exp.fulfill()
            }
        }

        wait(for: [exp], timeout: 2.0)
    }
}
