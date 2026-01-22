# Changelog

All notable changes to this project will be documented in this file.

## [0.4.0] - 2026-01-22
### Added
- Prefetch in-flight tracking and cooldown protection.
- Per-domain prefetch cooldown deadlines.
- Upstream breaker protection via `DNSUpstreamBreaker`.
- Pending request upper bound to prevent unbounded growth.
### Changed
- Fixed SwiftPM test target path and dependencies so tests resolve correctly.
- README updated with testing guidance and current version.

## [0.3.1] - 2026-01-14
### Changed
- Translated remaining inline comments to English.
- README updated to describe the DNS policy engine.

## [0.3.0] - 2026-01-14
### Added
- `DNSService` two-stage pipeline (fast sniff + minimal RFC1035 parser).
- `DNSFastSniffer` for low-overhead classification of common queries (A/AAAA/PTR).
- `MinimalDNSParser` with compression pointer support and answer extraction.
- `DNSUpstreamUDPRelay` (UDP/53) with txid rewrite/restore and timeout handling.
- `FakeIPPool` with reverse mapping and RFC 6890 `198.18.0.0/16` default.
- `DNSCache` with TTL-aware entries and periodic sweeping.
- `DNSMessageBuilder` utilities for building A/PTR/refuse responses and simple queries.

### Changed
- Documentation updated to reflect new architecture and usage.

### Known Issues
- `FakeDNSResponseBuilder .swift` filename contains a trailing space; consider renaming to `DNSMessageBuilder.swift`.
- Debug logging disable flag mismatch: `Package.swift` defines `NFDLOG_DISABLED` while `EFLog.swift` checks `FORGELOG_DISABLED`.
- `DNSUpstreamUDPRelay` bootstraps `DatagramBootstrap` with an `EventLoop` instead of an `EventLoopGroup`; review for NIO compatibility.

## [0.2.0] - 2026-01-03
### Added
- Initial cache and fake-ip pool components.
- Basic tests for `FakeIPPool` and `DNSCache`.
