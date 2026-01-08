//
//  DNSUpstreamUDPRelay.swift
//  EchoForgeDNS
//
//  Created by MagicianQuinn on 2026/1/3.
//
//  SwiftNIO UDP relay to an upstream DNS server (classic UDP/53).
//  Key feature:
//  - Rewrites transaction ID (txid) to avoid collisions across clients/flows.
//  - Restores original txid in returned response.
//

import Foundation
import NIO
import NIOCore

public final class DNSUpstreamUDPRelay {
    public struct Upstream {
        public let host: String
        public let port: Int
        public init(host: String, port: Int = 53) { self.host = host; self.port = port }
    }

    private let eventLoop: EventLoop
    private let upstream: Upstream

    private var channel: Channel?
    private var remoteAddress: SocketAddress?

    private var nextID: UInt16 = 1

    private struct Pending {
        let originalID: UInt16
        let promise: EventLoopPromise<Data>
        let deadline: NIODeadline
    }

    // rewrittenID -> Pending
    private var pending: [UInt16: Pending] = [:]

    public init(eventLoop: EventLoop, upstream: Upstream) {
        self.eventLoop = eventLoop
        self.upstream = upstream
    }

    public func start() -> EventLoopFuture<Void> {
        eventLoop.assertInEventLoop()

        if channel != nil {
            EFDLog.upstream("relay already started")
            return eventLoop.makeSucceededVoidFuture()
        }

        EFDLog.upstream("relay start upstream=\(upstream.host):\(upstream.port)")

        do {
            remoteAddress = try SocketAddress.makeAddressResolvingHost(upstream.host, port: upstream.port)
        } catch {
            return eventLoop.makeFailedFuture(error)
        }

        let bootstrap = DatagramBootstrap(group: eventLoop)
            .channelInitializer { channel in
                channel.pipeline.addHandler(UDPRelayInbound { [weak self] env in
                    self?.onRead(env)
                })
            }

        return bootstrap.bind(host: "0.0.0.0", port: 0).map { ch in
            self.channel = ch
        }
    }

    public func stop() {
        eventLoop.assertInEventLoop()

        EFDLog.upstream("relay stop pending=\(pending.count)")

        channel?.close(promise: nil)
        channel = nil
        remoteAddress = nil

        // Fail all pending
        let err = NSError(domain: "DNSUpstreamUDPRelay", code: -1, userInfo: [NSLocalizedDescriptionKey: "relay stopped"])
        for (_, p) in pending {
            p.promise.fail(err)
        }
        pending.removeAll()
    }

    public func query(_ originalPayload: Data, timeout: TimeAmount = .seconds(3)) -> EventLoopFuture<Data> {
        eventLoop.assertInEventLoop()

        guard originalPayload.count >= 12 else {
            return eventLoop.makeFailedFuture(NSError(domain: "DNSUpstreamUDPRelay", code: 1, userInfo: [NSLocalizedDescriptionKey: "payload too small"]))
        }

        let startF = start()
        return startF.flatMap { [unowned self] in
            guard let ch = self.channel, let ra = self.remoteAddress else {
                return self.eventLoop.makeFailedFuture(
                    NSError(domain: "DNSUpstreamUDPRelay", code: 3,
                            userInfo: [NSLocalizedDescriptionKey: "relay not ready"])
                )
            }

            let promise = self.eventLoop.makePromise(of: Data.self)

            let originalID = (UInt16(originalPayload[0]) << 8) | UInt16(originalPayload[1])
            let rewrittenID = self.allocateID()

            var payload = originalPayload
            payload[0] = UInt8(rewrittenID >> 8)
            payload[1] = UInt8(rewrittenID & 0xFF)

            let deadline = NIODeadline.now() + timeout
            self.pending[rewrittenID] = Pending(
                originalID: originalID,
                promise: promise,
                deadline: deadline
            )

            // timeout task
            self.eventLoop.scheduleTask(in: timeout) { [weak self] in
                guard let self else { return }
                self.eventLoop.assertInEventLoop()

                EFDLog.upstream(
                    "send query rewrittenID=\(rewrittenID) origID=\(originalID)"
                )

                if let p = self.pending.removeValue(forKey: rewrittenID) {
                    p.promise.fail(NSError(domain: "DNSUpstreamUDPRelay", code: 408, userInfo: [NSLocalizedDescriptionKey: "upstream timeout"]))
                }
            }

            var buf = ByteBufferAllocator().buffer(capacity: payload.count)
            buf.writeBytes(payload)

            let env = AddressedEnvelope(remoteAddress: ra, data: buf)
            ch.writeAndFlush(env, promise: nil)

            return promise.futureResult
        }
    }

    private func allocateID() -> UInt16 {
        // Ensure no collision with currently pending rewritten IDs
        for _ in 0 ..< UInt16.max {
            let id = nextID
            nextID &+= 1
            if nextID == 0 { nextID = 1 }
            if pending[id] == nil {
                return id
            }
        }
        // Extremely unlikely: pending table full
        return UInt16.random(in: 1 ... UInt16.max)
    }

    private func onRead(_ env: AddressedEnvelope<ByteBuffer>) {
        eventLoop.assertInEventLoop()

        var buf = env.data
        guard let bytes = buf.readBytes(length: buf.readableBytes) else {
            return
        }
        let data = Data(bytes)

        guard data.count >= 2 else { return }

        let rewrittenID = (UInt16(data[0]) << 8) | UInt16(data[1])
        guard let p = pending.removeValue(forKey: rewrittenID) else {
            EFDLog.upstream("unsolicited response id=\(rewrittenID)")
            return
        }

        EFDLog.upstream(
            "recv response rewrittenID=\(rewrittenID) restoreID=\(p.originalID)"
        )

        // restore original txid
        var restored = data
        restored[0] = UInt8(p.originalID >> 8)
        restored[1] = UInt8(p.originalID & 0xFF)

        p.promise.succeed(restored)
    }
}

private final class UDPRelayInbound: ChannelInboundHandler {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    private let onRead: (AddressedEnvelope<ByteBuffer>) -> Void
    init(_ onRead: @escaping (AddressedEnvelope<ByteBuffer>) -> Void) {
        self.onRead = onRead
    }

    func channelRead(context _: ChannelHandlerContext, data: NIOAny) {
        onRead(unwrapInboundIn(data))
    }
}
