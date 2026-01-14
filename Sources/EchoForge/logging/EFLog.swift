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
    #if FORGELOG_DISABLED

        @inline(__always) public static func info(_: String) {}
        @inline(__always) public static func debug(_: String) {}
        @inline(__always) public static func warn(_: String) {}
        @inline(__always) public static func error(_: String) {}

    #else

        @inline(__always)
        private static func log(_ category: String) -> FLLog {
            FLLog(category: category)
        }

        // cache
        public static func cache(_ m: String) {
            log("echodns.cache").debug(m)
        }

        // fake-ip
        public static func fakeip(_ m: String) {
            log("echodns.fakeip").debug(m)
        }

        // upstream
        public static func upstream(_ m: String) {
            log("echodns.upstream").debug(m)
        }

        // core policy
        public static func core(_ m: String) {
            log("echodns.core").info(m)
        }

        public static func debug(_ m: String) {
            log("echodns.core").info(m)
        }

        public static func warn(_ m: String) {
            log("echodns.core").warn(m)
        }

        public static func error(_ m: String) {
            log("echodns.core").error(m)
        }

    #endif
}
