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
    let slowUpstreamDeadline: TimeAmount

    private let primary: Entry
    private let secondary: [Entry]

    init(
        eventLoop: EventLoop,
        primary: Entry,
        secondary: [Entry],
        hedgeDelay: TimeAmount = .milliseconds(50),
        slowUpstreamDeadline: TimeAmount
    ) {
        self.eventLoop = eventLoop
        self.primary = primary
        self.secondary = secondary
        self.hedgeDelay = hedgeDelay
        self.slowUpstreamDeadline = slowUpstreamDeadline
    }

    func start() -> EventLoopFuture<Void> {
        eventLoop.assertInEventLoop()
        let all = [primary] + secondary
        let futures = all.map { $0.upstream.start() }
        return EventLoopFuture.andAllSucceed(futures, on: eventLoop)
    }

    func query(_ payload: Data, timeout: TimeAmount) -> EventLoopFuture<Data> {
        eventLoop.assertInEventLoop()

        let promise = eventLoop.makePromise(of: Data.self)
        var finished = false
        var remaining = 1 + secondary.count

        let overallTask = eventLoop.scheduleTask(in: timeout) {
            if finished { return }
            finished = true
            promise.fail(DNSUpstreamError.timeout)
        }

        func finish(_ result: Result<Data, Error>, rtt: TimeAmount?, entry: Entry?) {
            guard !finished else { return }
            finished = true
            overallTask.cancel()

            if let entry, let rtt {
                if case .success = result {
                    if rtt > slowUpstreamDeadline {
                        entry.breaker.onFailure()
                    } else {
                        entry.breaker.onSuccess()
                    }
                } else {
                    entry.breaker.onFailure()
                }
            }

            switch result {
            case let .success(data):
                promise.succeed(data)
            case let .failure(err):
                promise.fail(err)
            }
        }

        func onFailure() {
            remaining -= 1
            if remaining == 0 && !finished {
                finish(.failure(DNSUpstreamError.notReady), rtt: nil, entry: nil)
            }
        }

        func trySend(_ entry: Entry) {
            guard !finished else { return }
            guard entry.breaker.allowRequest() else {
                onFailure()
                return
            }

            let start = NIODeadline.now()
            entry.upstream.query(payload, timeout: timeout).whenComplete { [weak self] res in
                guard let self else { return }
                self.eventLoop.execute {
                    guard !finished else { return }
                    let rtt = NIODeadline.now() - start

                    switch res {
                    case let .success(data):
                        finish(.success(data), rtt: rtt, entry: entry)
                    case let .failure(err):
                        entry.breaker.onFailure()
                        onFailure()
                        _ = err
                    }
                }
            }
        }

        // 1) primary
        trySend(primary)

        // 2) hedge to secondary
        eventLoop.scheduleTask(in: hedgeDelay) {
            for e in self.secondary {
                trySend(e)
            }
        }

        return promise.futureResult
    }

    // MARK: - Lifecycle

    func stop() {
        if eventLoop.inEventLoop {
            stopOnEventLoop()
        } else {
            eventLoop.execute { [weak self] in self?.stopOnEventLoop() }
        }
    }

    private func stopOnEventLoop() {
        eventLoop.assertInEventLoop()
        primary.upstream.stop()
        for e in secondary {
            e.upstream.stop()
        }
    }
}
