//
//  DNSUpstreamBreaker.swift
//  EchoForge
//
//  Created by MagicianQuinn on 2026/1/22.
//

import NIO

protocol DNSBreaker: AnyObject {
    func allowRequest(now: NIODeadline) -> Bool
    func isOpen(now: NIODeadline) -> Bool
    func onSuccess()
    func onFailure()
}

final class DNSUpstreamBreaker: DNSBreaker {
    private let failThreshold: Int
    private let degradeDuration: TimeAmount
    private var failureStreak: Int = 0
    private var degradedUntil: NIODeadline?

    init(failThreshold: Int = 3, degradeDuration: TimeAmount = .seconds(3)) {
        self.failThreshold = failThreshold
        self.degradeDuration = degradeDuration
    }

    /// Whether a new upstream request is allowed *now*
    func allowRequest(now: NIODeadline = .now()) -> Bool {
        guard let until = degradedUntil else {
            return true
        }
        if now < until {
            return false
        }
        degradedUntil = nil
        return true
    }

    func isOpen(now: NIODeadline = .now()) -> Bool {
        guard let until = degradedUntil else { return false }
        return now < until
    }

    func onSuccess() {
        failureStreak = 0
        if degradedUntil != nil {
            EFLog.info("upstream breaker recovered")
        }
        degradedUntil = nil
    }

    /// Call on timeout / notReady / error
    func onFailure() {
        failureStreak += 1

        if failureStreak >= failThreshold {
            degradedUntil = NIODeadline.now() + degradeDuration
            failureStreak = 0
            EFLog.warn("upstream breaker degraded for \(degradeDuration)")
        }
    }
}
