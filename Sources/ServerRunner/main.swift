import EchoForgeDNS
import Foundation
import NIO

let group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)

do {
    let server = try DNSServerUDP(group: group, upstreamHost: "8.8.8.8", upstreamPort: 53)
    try server.start()
    print("Server started. Listening on UDP port 53. Press Ctrl+C to stop.")
    RunLoop.current.run()
} catch {
    print("Failed to start server: \(error)")
    try? group.syncShutdownGracefully()
    exit(1)
}
