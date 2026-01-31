//
//  DNSUpstreamBreakerTests.swift
//  EchoForge
//
//  Created by GitHub Copilot on 2026/1/22.
//

import NIO
import XCTest

@testable import EchoForge

final class DNSUpstreamBreakerTests: XCTestCase {
    // MARK: - Basic Behavior Tests

    func testAllowRequestWhenNotDegraded() {
        let breaker = DNSUpstreamBreaker(failThreshold: 3, degradeDuration: .seconds(5))

        // Initially, breaker should allow requests
        XCTAssertTrue(breaker.allowRequest(), "Breaker should allow requests when not degraded")
    }

    func testAllowRequestWithExplicitNow() {
        let breaker = DNSUpstreamBreaker(failThreshold: 3, degradeDuration: .seconds(5))
        let now = NIODeadline.now()

        XCTAssertTrue(
            breaker.allowRequest(now: now),
            "Breaker should allow requests with explicit now"
        )
    }

    // MARK: - Failure Streak and Threshold Tests

    func testFailuresBelowThresholdDoNotDegrade() {
        let breaker = DNSUpstreamBreaker(failThreshold: 3, degradeDuration: .seconds(5))

        // Record failures below threshold
        breaker.onFailure()
        XCTAssertTrue(breaker.allowRequest(), "Breaker should allow after 1 failure (threshold 3)")

        breaker.onFailure()
        XCTAssertTrue(breaker.allowRequest(), "Breaker should allow after 2 failures (threshold 3)")
    }

    func testThresholdTriggersDegradation() {
        let breaker = DNSUpstreamBreaker(failThreshold: 3, degradeDuration: .seconds(5))

        // Record failures to reach threshold
        breaker.onFailure()
        breaker.onFailure()
        breaker.onFailure()

        // Should now be degraded
        XCTAssertFalse(
            breaker.allowRequest(),
            "Breaker should block requests after reaching threshold"
        )
    }

    func testCustomThreshold() {
        let breaker = DNSUpstreamBreaker(failThreshold: 5, degradeDuration: .seconds(10))

        // Record 4 failures (below threshold of 5)
        for _ in 0 ..< 4 {
            breaker.onFailure()
        }
        XCTAssertTrue(breaker.allowRequest(), "Breaker should allow after 4 failures (threshold 5)")

        // 5th failure should trigger degradation
        breaker.onFailure()
        XCTAssertFalse(
            breaker.allowRequest(),
            "Breaker should block after 5th failure (threshold 5)"
        )
    }

    func testFailureStreakResetsAfterThreshold() {
        let breaker = DNSUpstreamBreaker(failThreshold: 3, degradeDuration: .seconds(1))

        // Trigger degradation
        breaker.onFailure()
        breaker.onFailure()
        breaker.onFailure()

        let now = NIODeadline.now()
        XCTAssertFalse(breaker.allowRequest(now: now), "Should be degraded after threshold")

        // Test with future time after degradation period expires
        let afterExpiry = now + .seconds(2)
        XCTAssertTrue(
            breaker.allowRequest(now: afterExpiry),
            "Should allow after degradation period"
        )

        // New failures should not immediately degrade (streak was reset)
        breaker.onFailure()
        XCTAssertTrue(breaker.allowRequest(), "Should allow after 1 new failure (streak was reset)")
    }

    // MARK: - Success Resets Tests

    func testSuccessResetsFailureStreak() {
        let breaker = DNSUpstreamBreaker(failThreshold: 3, degradeDuration: .seconds(5))

        // Record some failures
        breaker.onFailure()
        breaker.onFailure()

        // Success should reset the streak
        breaker.onSuccess()

        // Now we need 3 more failures to trigger degradation, not 1
        breaker.onFailure()
        XCTAssertTrue(breaker.allowRequest(), "Should allow after 1 failure (streak was reset)")

        breaker.onFailure()
        XCTAssertTrue(breaker.allowRequest(), "Should allow after 2 failures (streak was reset)")

        breaker.onFailure()
        XCTAssertFalse(breaker.allowRequest(), "Should block after 3 failures (new streak)")
    }

    func testSuccessClearsDegradation() {
        let breaker = DNSUpstreamBreaker(failThreshold: 3, degradeDuration: .seconds(10))

        // Trigger degradation
        breaker.onFailure()
        breaker.onFailure()
        breaker.onFailure()

        XCTAssertFalse(breaker.allowRequest(), "Should be degraded")

        // Success should immediately clear degradation
        breaker.onSuccess()

        XCTAssertTrue(breaker.allowRequest(), "Should allow immediately after success")
    }

    // MARK: - Degradation Period Tests

    func testDegradationPeriodDuration() {
        let degradeDuration: Int64 = 2 // 2 seconds
        let breaker = DNSUpstreamBreaker(
            failThreshold: 2,
            degradeDuration: .seconds(degradeDuration)
        )

        // Trigger degradation and capture the time
        let degradeTime = NIODeadline.now()
        breaker.onFailure()
        breaker.onFailure()

        XCTAssertFalse(breaker.allowRequest(now: degradeTime), "Should be degraded immediately")

        // Check at half duration
        let halfDuration = degradeTime + .seconds(degradeDuration / 2)
        XCTAssertFalse(
            breaker.allowRequest(now: halfDuration),
            "Should still be degraded at half duration"
        )

        // Check after full duration expires
        let afterExpiry = degradeTime + .seconds(degradeDuration + 1)
        XCTAssertTrue(
            breaker.allowRequest(now: afterExpiry),
            "Should allow after degradation period expires"
        )
    }

    func testCustomDegradationDuration() {
        let breaker = DNSUpstreamBreaker(failThreshold: 1, degradeDuration: .seconds(3))

        // Trigger degradation
        let degradeTime = NIODeadline.now()
        breaker.onFailure()

        XCTAssertFalse(breaker.allowRequest(now: degradeTime), "Should be degraded")

        // Check after degradation expires
        let afterExpiry = degradeTime + .seconds(4)
        XCTAssertTrue(
            breaker.allowRequest(now: afterExpiry),
            "Should allow after 3 second degradation period"
        )
    }

    func testDegradationWithExplicitTimeChecks() {
        let breaker = DNSUpstreamBreaker(failThreshold: 2, degradeDuration: .seconds(10))

        // Trigger degradation
        breaker.onFailure()
        breaker.onFailure()

        let now = NIODeadline.now()

        // Should be degraded at current time
        XCTAssertFalse(breaker.allowRequest(now: now), "Should be degraded at current time")

        // Should be degraded shortly after
        let soon = now + .seconds(5)
        XCTAssertFalse(breaker.allowRequest(now: soon), "Should still be degraded after 5 seconds")

        // Should be allowed after degradation period
        let later = now + .seconds(11)
        XCTAssertTrue(breaker.allowRequest(now: later), "Should allow after 11 seconds")
    }

    // MARK: - Edge Cases

    func testMinimalThreshold() {
        let breaker = DNSUpstreamBreaker(failThreshold: 1, degradeDuration: .seconds(1))

        // Single failure should trigger degradation
        breaker.onFailure()
        XCTAssertFalse(breaker.allowRequest(), "Should degrade after 1 failure with threshold 1")
    }

    func testMultipleSuccessCallsDoNotCauseIssues() {
        let breaker = DNSUpstreamBreaker(failThreshold: 3, degradeDuration: .seconds(5))

        // Multiple successes should be safe
        breaker.onSuccess()
        breaker.onSuccess()
        breaker.onSuccess()

        XCTAssertTrue(breaker.allowRequest(), "Multiple successes should not cause issues")

        // Should still track failures correctly
        breaker.onFailure()
        breaker.onFailure()
        breaker.onFailure()

        XCTAssertFalse(breaker.allowRequest(), "Should still degrade after threshold")
    }

    func testConcurrentFailuresAndSuccesses() {
        let breaker = DNSUpstreamBreaker(failThreshold: 3, degradeDuration: .seconds(2))

        // Alternating failures and successes
        breaker.onFailure()
        breaker.onSuccess()
        breaker.onFailure()
        breaker.onSuccess()
        breaker.onFailure()

        // Should not be degraded since successes reset the streak
        XCTAssertTrue(breaker.allowRequest(), "Successes should prevent degradation")

        // But consecutive failures should trigger it
        breaker.onFailure()
        breaker.onFailure()
        breaker.onFailure()

        XCTAssertFalse(breaker.allowRequest(), "Consecutive failures should degrade")
    }

    func testRecoveryAndReDegradation() {
        let breaker = DNSUpstreamBreaker(failThreshold: 2, degradeDuration: .seconds(1))

        // First degradation cycle
        let firstDegradeTime = NIODeadline.now()
        breaker.onFailure()
        breaker.onFailure()
        XCTAssertFalse(breaker.allowRequest(now: firstDegradeTime), "Should be degraded")

        // Check recovery after period
        let afterFirstExpiry = firstDegradeTime + .seconds(2)
        XCTAssertTrue(breaker.allowRequest(now: afterFirstExpiry), "Should recover after period")

        // Second degradation cycle
        breaker.onFailure()
        breaker.onFailure()
        XCTAssertFalse(breaker.allowRequest(), "Should be degraded again")

        // Recovery via success
        breaker.onSuccess()
        XCTAssertTrue(breaker.allowRequest(), "Should recover via success")
    }

    // MARK: - Integration Scenario Tests

    func testTypicalUpstreamFailureScenario() {
        let breaker = DNSUpstreamBreaker(failThreshold: 3, degradeDuration: .seconds(5))

        // Simulate successful queries
        XCTAssertTrue(breaker.allowRequest(), "Should allow initial request")
        breaker.onSuccess()

        XCTAssertTrue(breaker.allowRequest(), "Should allow after success")
        breaker.onSuccess()

        // Upstream starts failing
        XCTAssertTrue(breaker.allowRequest(), "Should allow request")
        breaker.onFailure()

        XCTAssertTrue(breaker.allowRequest(), "Should allow request")
        breaker.onFailure()

        XCTAssertTrue(breaker.allowRequest(), "Should allow request")
        let degradeTime = NIODeadline.now()
        breaker.onFailure()

        // Now degraded - requests should be blocked
        XCTAssertFalse(
            breaker.allowRequest(now: degradeTime),
            "Should block after threshold failures"
        )
        XCTAssertFalse(breaker.allowRequest(now: degradeTime), "Should continue blocking")

        // Check retry after degradation period
        let afterExpiry = degradeTime + .seconds(6)
        XCTAssertTrue(
            breaker.allowRequest(now: afterExpiry),
            "Should allow retry after degradation"
        )

        // Upstream recovered
        breaker.onSuccess()
        XCTAssertTrue(breaker.allowRequest(), "Should allow after recovery")
    }

    func testProtocolConformance() {
        // Verify that DNSUpstreamBreaker conforms to DNSBreaker protocol
        let breaker: DNSBreaker = DNSUpstreamBreaker(failThreshold: 3, degradeDuration: .seconds(5))

        let now = NIODeadline.now()
        XCTAssertTrue(breaker.allowRequest(now: now), "Protocol methods should work")
        breaker.onSuccess()
        breaker.onFailure()
        XCTAssertTrue(breaker.allowRequest(now: now), "Protocol methods should work after calls")
    }
}
