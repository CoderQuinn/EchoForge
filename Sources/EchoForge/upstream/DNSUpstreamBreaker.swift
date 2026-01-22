//
//  DNSUpstreamBreaker.swift
//  EchoForge
//
//  Created by MagicianQuinn on 2026/1/22.
//

import NIO

/// Circuit breaker protocol for DNS upstream requests.
///
/// Implements the circuit breaker pattern to prevent cascading failures when upstream DNS servers
/// become unresponsive or unreliable. The breaker monitors request outcomes and temporarily blocks
/// requests when failure rates exceed acceptable thresholds.
protocol DNSBreaker: AnyObject {
    /// Determines whether a new upstream request should be allowed at the given time.
    ///
    /// - Parameter now: The current time to check against any degradation period.
    /// - Returns: `true` if the request should proceed, `false` if it should be blocked.
    func allowRequest(now: NIODeadline) -> Bool
    
    /// Records a successful upstream response.
    ///
    /// Resets failure tracking when requests complete successfully.
    func onSuccess()
    
    /// Records a failed upstream request.
    ///
    /// A failure includes timeouts, connection errors, or any upstream unavailability.
    /// Consecutive failures may trigger the breaker to enter a degraded state.
    func onFailure()
}

/// DNS upstream circuit breaker implementation.
///
/// This circuit breaker prevents excessive load on failing DNS upstreams by tracking consecutive
/// failures and temporarily blocking new requests when failures exceed the configured threshold.
///
/// ## Circuit Breaker States
/// - **Closed (Normal)**: Requests are allowed through. Failures are tracked.
/// - **Open (Degraded)**: Requests are blocked for a configured duration after exceeding the failure threshold.
///
/// ## Failure Definition
/// A failure is any upstream request that:
/// - Times out without a response
/// - Returns a connection error
/// - Indicates the upstream is not ready
///
/// ## Degradation Period
/// When consecutive failures reach `failThreshold`, the breaker enters a degraded state for
/// `degradeDuration`. During this period, all requests are blocked to give the upstream time
/// to recover. After the degradation period expires, the breaker automatically resets and
/// allows new requests.
///
/// ## Thread Safety
/// This implementation is NOT thread-safe and must be called from a single EventLoop.
final class DNSUpstreamBreaker: DNSBreaker {
    /// Number of consecutive failures required to trigger degradation.
    private let failThreshold: Int
    
    /// Duration to block requests once degraded.
    private let degradeDuration: TimeAmount
    
    /// Current count of consecutive failures.
    private var failureStreak: Int = 0
    
    /// Deadline until which requests are blocked, or `nil` if not degraded.
    private var degradedUntil: NIODeadline?

    /// Creates a new circuit breaker with the specified thresholds.
    ///
    /// - Parameters:
    ///   - failThreshold: Number of consecutive failures before entering degraded state. Default is 3.
    ///   - degradeDuration: How long to block requests once degraded. Default is 5 seconds.
    init(failThreshold: Int = 3, degradeDuration: TimeAmount = .seconds(5)) {
        self.failThreshold = failThreshold
        self.degradeDuration = degradeDuration
    }

    /// Checks whether a new upstream request is allowed at the current time.
    ///
    /// - Parameter now: The current time. Defaults to the current deadline.
    /// - Returns: `false` if currently in degraded state, `true` otherwise.
    func allowRequest(now: NIODeadline = .now()) -> Bool {
        if let until = degradedUntil, now < until {
            return false
        }
        return true
    }

    /// Records a successful upstream response.
    ///
    /// Resets the failure streak counter and clears any degraded state, allowing
    /// new requests to proceed immediately.
    func onSuccess() {
        failureStreak = 0
        degradedUntil = nil
    }

    /// Records a failed upstream request.
    ///
    /// Increments the failure streak. If consecutive failures reach `failThreshold`,
    /// the breaker enters degraded state and blocks requests for `degradeDuration`.
    ///
    /// Call this for any failure condition including:
    /// - Request timeouts
    /// - Connection errors
    /// - Upstream not ready errors
    func onFailure() {
        failureStreak += 1

        if failureStreak >= failThreshold {
            degradedUntil = NIODeadline.now() + degradeDuration
            failureStreak = 0
        }
    }
}
