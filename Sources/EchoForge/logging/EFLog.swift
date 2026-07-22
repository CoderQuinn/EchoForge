//
//
//  EFLog.swift
//  EchoForge
//
//  Created by MagicianQuinn on 2025/12/31.
//

import ForgeLogKit

/*
 echodns.core         // DNSService / policy
 echodns.cache        // DNSCache
 echodns.fakeip       // FakeIPPool
 echodns.upstream     // DNSUpstreamUDPRelay
 */

public enum EFLog {
    public enum Level: Int, Sendable {
        case debug = 0
        case info = 1
        case warn = 2
        case error = 3
    }

    public nonisolated(unsafe) static var minimumLevel: Level = .warn

    @inline(__always)
    private static func log(_ category: String) -> FLLog {
        FLLog(category: category)
    }

    @inline(__always)
    private static func shouldLog(_ level: Level) -> Bool {
        level.rawValue >= minimumLevel.rawValue
    }

    #if FORGELOG_DISABLED
        // cache
        public static func cache(_: String) {}

        // fake-ip
        public static func fakeip(_: String) {}

        // upstream
        public static func upstream(_: String) {}

        // core policy
        public static func core(_: String) {}

        public static func debug(_: String) {}

        public static func info(_: String) {}

        public static func warn(_: String) {}

        public static func error(_: String) {}

    #else
        // cache
        public static func cache(_ m: String) {
            guard shouldLog(.debug) else { return }
            log("echodns.cache").debug(m)
        }

        // fake-ip
        public static func fakeip(_ m: String) {
            guard shouldLog(.debug) else { return }
            log("echodns.fakeip").debug(m)
        }

        // upstream
        public static func upstream(_ m: String) {
            guard shouldLog(.debug) else { return }
            log("echodns.upstream").debug(m)
        }

        // core policy
        public static func core(_ m: String) {
            guard shouldLog(.info) else { return }
            log("echodns.core").info(m)
        }

        public static func debug(_ m: String) {
            guard shouldLog(.debug) else { return }
            log("echodns.core").debug(m)
        }

        public static func info(_ m: String) {
            guard shouldLog(.info) else { return }
            log("echodns.core").info(m)
        }

        public static func warn(_ m: String) {
            guard shouldLog(.warn) else { return }
            log("echodns.core").warn(m)
        }

        public static func error(_ m: String) {
            guard shouldLog(.error) else { return }
            log("echodns.core").error(m)
        }

    #endif
}
