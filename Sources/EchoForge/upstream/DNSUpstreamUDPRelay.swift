//  EchoForge
//
//  Created by MagicianQuinn on 2026/1/3.
//
//  SwiftNIO UDP relay to an upstream DNS server (classic UDP/53).
//  Key feature:
//  - Rewrites transaction ID (txid) to avoid collisions across clients/flows.
//  - Restores original txid in returned response.
//

import ForgeBase
import Foundation
import NIO
import NIOCore

public struct Upstream {
    public let host: String
    public let port: UInt16

    public init(host: String, port: UInt16 = 53) {
        self.host = host
        self.port = port
    }
}

private struct PendingQuery {
    let originalID: UInt16
    let promise: EventLoopPromise<Data>
    let timeoutTask: Scheduled<Void>
}

/// UDP/53 DNS upstream relay with TXID rewrite.
public final class DNSUpstreamUDPRelay: DNSUpstream, @unchecked Sendable {
    private let eventLoop: EventLoop
    private let upstream: Upstream
    private var channel: Channel?
    private var remoteAddress: SocketAddress?

    private var nextID: UInt16 = 1
    private var pendingMap: [UInt16: PendingQuery] = [:]
    private let maxPending: Int = 4096

    public init(eventLoop: EventLoop, upstream: Upstream) {
        self.eventLoop = eventLoop
        self.upstream = upstream
    }

    public func start() -> EventLoopFuture<Void> {
        eventLoop.assertInEventLoop()

        if channel != nil {
            EFLog.debug("upstream relay start: already started")
            return eventLoop.makeSucceededVoidFuture()
        }
        do {
            remoteAddress = try SocketAddress.makeAddressResolvingHost(
                upstream.host,
                port: Int(upstream.port)
            )
        } catch {
            EFLog.error("upstream relay resolve failed host=\(upstream.host) port=\(upstream.port)")
            return eventLoop.makeFailedFuture(error)
        }

        let bootstrap = DatagramBootstrap(group: eventLoop)
            .channelInitializer { channel in
                channel.pipeline.addHandler(
                    UDPRelayInbound { [weak self] envelope in
                        self?.onRead(envelope)
                    }
                )
            }
        return bootstrap.bind(host: "0.0.0.0", port: 0).map { [weak self] ch in
            self?.channel = ch
            EFLog.info("upstream relay started -> \(self?.upstream.host ?? "-"):\(self?.upstream.port ?? 0)")
        }
    }

    public func stop() {
        eventLoop.assertInEventLoop()

        if channel != nil {
            EFLog.info("upstream relay stopping")
        }
        channel?.close(promise: nil)
        channel = nil
        remoteAddress = nil

        for (_, pending) in pendingMap {
            pending.timeoutTask.cancel()
            pending.promise.fail(DNSUpstreamError.stopped)
        }

        pendingMap.removeAll()
    }

    public func query(_ originalPayload: Data, timeout: TimeAmount = .seconds(3))
        -> EventLoopFuture<Data>
    {
        eventLoop.assertInEventLoop()

        guard originalPayload.count >= 12 else {
            EFLog.warn("upstream relay query: invalid payload size=\(originalPayload.count)")
            return eventLoop.makeFailedFuture(DNSUpstreamError.invalidPayload)
        }

        if pendingMap.count >= maxPending {
            EFLog.warn("upstream relay query: pending full count=\(pendingMap.count)")
            return eventLoop.makeFailedFuture(DNSUpstreamError.notReady)
        }

        return start().flatMap { [weak self, eventLoop = self.eventLoop] in
            guard let self = self else {
                return eventLoop.makeFailedFuture(DNSUpstreamError.internalError)
            }
            guard let ch = self.channel, let remoteAddress = self.remoteAddress else {
                EFLog.warn("upstream relay query: not ready")
                return self.eventLoop.makeFailedFuture(DNSUpstreamError.notReady)
            }

            let promise = self.eventLoop.makePromise(of: Data.self)
            let originalID = (UInt16(originalPayload[0]) << 8) | UInt16(originalPayload[1])
            let rewrittedID = self.allocateID()

            var payload = originalPayload
            payload[0] = UInt8(rewrittedID >> 8)
            payload[1] = UInt8(rewrittedID & 0xFF)

            let task = self.eventLoop.scheduleTask(in: timeout) { [weak self] in
                guard let self else { return }
                self.eventLoop.assertInEventLoop()

                if let pending = self.pendingMap.removeValue(forKey: rewrittedID) {
                    EFLog.warn("upstream relay timeout id=\(rewrittedID)")
                    pending.promise.fail(DNSUpstreamError.timeout)
                }
            }
            self.pendingMap[rewrittedID] = PendingQuery(
                originalID: originalID,
                promise: promise,
                timeoutTask: task
            )

            var buf = ByteBufferAllocator().buffer(capacity: payload.count)
            buf.writeBytes(payload)

            ch.writeAndFlush(
                AddressedEnvelope(remoteAddress: remoteAddress, data: buf),
                promise: nil
            )
            return promise.futureResult
        }
    }

    private func allocateID() -> UInt16 {
        eventLoop.assertInEventLoop()

        // Ensure no collision with currently pending rewritten IDs
        for _ in 0 ..< UInt16.max {
            let id = nextID
            nextID &+= 1
            if nextID == 0 { nextID = 1 }
            if pendingMap[id] == nil {
                return id
            }
        }
        // Extremely unlikely: pending table full
        return UInt16.random(in: 1 ... UInt16.max)
    }

    private func onRead(_ envelope: AddressedEnvelope<ByteBuffer>) {
        eventLoop.assertInEventLoop()

        guard channel != nil else { return }

        // Security: Validate that the datagram is from the configured upstream server
        // to prevent DNS spoofing attacks from unauthorized sources
        guard let expectedRemote = remoteAddress,
              envelope.remoteAddress == expectedRemote
        else {
            EFLog.warn("upstream relay dropped packet from unexpected remote")
            return
        }

        var buf = envelope.data
        guard let bytes = buf.readBytes(length: buf.readableBytes),
              bytes.count >= 2
        else {
            EFLog.debug("upstream relay dropped empty response")
            return
        }
        var data = Data(bytes)

        let rewrittenID = (UInt16(data[0]) << 8) | UInt16(data[1])
        guard let pending = pendingMap.removeValue(forKey: rewrittenID) else {
            EFLog.debug("upstream relay response unmatched id=\(rewrittenID)")
            return
        }

        // restore original txid
        data[0] = UInt8(pending.originalID >> 8)
        data[1] = UInt8(pending.originalID & 0xFF)
        pending.timeoutTask.cancel()

        pending.promise.succeed(data)
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
