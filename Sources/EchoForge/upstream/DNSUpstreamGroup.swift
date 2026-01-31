//
//  DNSUpstreamGroup.swift
//  EchoForge
//
//  Created by MagicianQuinn on 2026/2/1.
//

import Foundation
import NIO

final class DNSUpstreamGroup {
    struct Entry {
        let upstream: DNSUpstream
        let breaker: DNSUpstreamBreaker
    }

    let eventLoop: EventLoop
    let hedgeDelay: TimeAmount

    private let entries: [Entry]
    private let slowUpstreamDeadline: TimeAmount

    init(
        eventLoop: EventLoop,
        entries: [Entry],
        hedgeDelay: TimeAmount = .milliseconds(50),
        slowUpstreamDeadline: TimeAmount
    ) {
        self.eventLoop = eventLoop
        self.entries = entries
        self.hedgeDelay = hedgeDelay
        self.slowUpstreamDeadline = slowUpstreamDeadline
    }

    func query(_ payload: Data, timeout: TimeAmount) -> EventLoopFuture<Data> {
        eventLoop.assertInEventLoop()

        let promise = eventLoop.makePromise(of: Data.self)
        var finished = false

        let overallTimeout = eventLoop.scheduleTask(in: timeout) {
            guard !finished else { return }
            finished = true
            promise.fail(DNSUpstreamError.timeout)
        }

        func trySend(_ entry: Entry) {
            guard !finished else { return }
            guard entry.breaker.allowRequest() else { return }

            let start = NIODeadline.now()
            entry.upstream.query(payload, timeout: timeout).whenComplete { [weak self] result in
                guard let self else {
                    return
                }
                self.eventLoop.execute {
                    guard !finished else { return }

                    let rtt = NIODeadline.now() - start
                    switch result {
                    case .success(let data):
                        finished = true
                        overallTimeout.cancel()
                        if rtt > self.slowUpstreamDeadline {
                            entry.breaker.onFailure()
                        } else {
                            entry.breaker.onSuccess()
                        }
                        promise.succeed(data)

                    case .failure:
                        entry.breaker.onFailure()
                    }
                }
            }
        }

        // 1️⃣ primary
        if let first = entries.first {
            trySend(first)
        }

        // 2️⃣ hedge
        eventLoop.scheduleTask(in: hedgeDelay) {
            for entry in self.entries.dropFirst() {
                trySend(entry)
            }
        }

        return promise.futureResult
    }

    // MARK: - Lifecycle

    func stop() {
        if eventLoop.inEventLoop {
            stopOnEventLoop()
        } else {
            eventLoop.execute { [weak self] in
                self?.stopOnEventLoop()
            }
        }
    }

    private func stopOnEventLoop() {
        eventLoop.assertInEventLoop()

        for entry in entries {
            entry.upstream.stop()
        }
    }
}
