//
//  DNSUpstream.swift
//  EchoForge
//
//  Created by MagicianQuinn on 2026/1/14.
//

import Foundation
import NIO

public protocol DNSUpstream {
    /// Query DNS upstream with raw DNS payload.
    /// Must be called on the upstream's bound EventLoop.
    func query(
        _ payload: Data,
        timeout: TimeAmount
    ) -> EventLoopFuture<Data>

    /// Ensure upstream transport is ready.
    func start() -> EventLoopFuture<Void>

    /// Stop upstream and fail all pending queries.
    func stop()
}

public enum DNSUpstreamError: Error, Equatable {
    /// Payload is invalid or too small to be a DNS message
    case invalidPayload

    /// Transport not ready or channel unavailable
    case notReady

    /// Query timed out
    case timeout

    /// Upstream stopped while query pending
    case stopped

    /// Internal unexpected state
    case internalError
}
