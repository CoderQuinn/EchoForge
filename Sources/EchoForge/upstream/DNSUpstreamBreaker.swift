//
//  DNSUpstreamBreaker.swift
//  EchoForge
//
//  Created by MagicianQuinn on 2026/1/22.
//

import NIO

protocol DNSBreaker: AnyObject {
    func allowRequest(now: NIODeadline) -> Bool
    func onSuccess()
    func onFailure()
}

final class DNSUpstreamBreaker: DNSBreaker {
    private let failThreshold: Int
    private let degradeDuration: TimeAmount
    private var failureStreak: Int = 0
    private var degradedUntil: NIODeadline?

    init(failThreshold: Int = 3, degradeDuration: TimeAmount = .seconds(5)) {
        self.failThreshold = failThreshold
        self.degradeDuration = degradeDuration
    }

    /// Whether a new upstream request is allowed *now*
    func allowRequest(now _: NIODeadline = .now()) -> Bool {
        if let until = degradedUntil, NIODeadline.now() < until {
            return false
        }
        return true
    }

    /// Call on any successful upstream response
    func onSuccess() {
        failureStreak = 0
        degradedUntil = nil
    }

    /// Call on timeout / notReady / error
    func onFailure() {
        failureStreak += 1

        if failureStreak >= failThreshold {
            degradedUntil = NIODeadline.now() + degradeDuration
            failureStreak = 0
        }
    }
}
