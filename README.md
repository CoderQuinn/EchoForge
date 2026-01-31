
# EchoForge


[![CI](https://github.com/CoderQuinn/EchoForge/actions/workflows/ci.yml/badge.svg)](
https://github.com/CoderQuinn/EchoForge/actions/workflows/ci.yml
)
![Status](https://img.shields.io/badge/status-core_stable_(pre--1.0)-blue)
![Coverage](https://img.shields.io/badge/Coverage-83.50%25-brightgreen)
![Swift](https://img.shields.io/badge/Swift-6.1-orange?logo=swift)
![Platform](https://img.shields.io/badge/Platform-iOS%2013%2B%20%7C%20macOS%2011%2B-blue)
![SPM](https://img.shields.io/badge/SPM-compatible-brightgreen)
![License](https://img.shields.io/github/license/CoderQuinn/EchoForge)


**EchoForge** is a lightweight, embeddable DNS component written in Swift.
It provides a fast path DNS classifier, a minimal RFC1035 parser, a fake IPv4 pool, caching, and an upstream UDP relay to integrate DNS interception into larger networking tools.


## Features

- **Fast Path Sniffer**: quickly classifies common queries (A/AAAA/PTR) without allocations.
- **Minimal RFC1035 Parser**: slow path ensures correctness and pointer handling.
- **Fake IPv4 Pool**: RFC 6890 `198.18.0.0/16` with reverse mapping.
- **TTL-Aware Cache**: in-memory cache for A responses with sweeping.
- **Multi-Upstream DNS**: parallel upstreams with hedge queries to reduce tail latency.
- **UDP Upstream Relay**: SwiftNIO-based UDP/53 relay with txid rewrite/restore.
- **Bounded DNS Execution**: all DNS queries are guaranteed to complete within a fixed time window.
- **SwiftNIO** for non-blocking performance.
- **Policy Engine**: routes queries to local handling, upstream passthrough, or refusal.


## Installation

Add the package to your `Package.swift` dependencies:

```swift
dependencies: [
    .package(url: "https://github.com/CoderQuinn/EchoForge.git", from: "0.5.0")
]
```

Then add the `EchoForge` library product to your target dependencies:

```swift
targets: [
    .target(
        name: "YourTarget",
        dependencies: [
            .product(name: "EchoForge", package: "EchoForge")
        ]
    ),
]
```


## Usage Example

```swift
import EchoForge
import NIO
import ForgeBase

// Create an EventLoop (example only; integrate with your app's loop)
let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
let loop = group.next()

// Initialize DNS service (defaults: ttl=300, upstream=8.8.8.8:53)
let service = DNSService(eventLoop: loop)
service.startSweep() // optional: enable periodic cache sweep

// Handle an incoming DNS UDP payload (Data) on any loop
// FBDataPacketBuffer is provided by ForgeBase
let incoming: Data = /* UDP payload */ Data()
let buf = FBDataPacketBuffer(incoming)

// Dispatch to service; result hops back to caller's loop
let future = service.handleDNSPayload(buf, loop)
future.whenSuccess { response in
    // response is Data? to send back to client
}
```

## Testing

The test suite lives under `Tests/EchoForgeTests` and can be run with SwiftPM (e.g. run `swift test` from the package root).
Current unit test coverage: **83.50%**.

## Design Notes

- Two-stage pipeline: fast sniff (optimistic) then minimal parser (correctness).
- Fake-IP pool uses `198.18.0.0/16` (RFC 6890 reserved block) to avoid collisions.
- Policy engine keeps the fast path lightweight and defers correctness to the parser.
- DNS upstream handling is strictly bounded to prevent slow or broken upstreams from stalling the system.


## Roadmap / TODO

- [ ] TCP, DoT (DNS over TLS), DoH (DNS over HTTPS)
- [ ] IPv6 support for fake addresses
- [ ] LRU recycling algorithm for Fake-IP reuse
- [x] Built-in caching with TTL awareness


## Contributing

Patches, tests, and documentation improvements are welcome! Please open a PR against this repository.

## Credits

- SwiftNIO: https://github.com/apple/swift-nio
- ForgeBase / ForgeLogKit: https://github.com/CoderQuinn

## License
Apache 2.0 License.
