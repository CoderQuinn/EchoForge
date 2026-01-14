//
//  DNSPolicyEngine.swift
//  NetForge
//
//  Created by MagicianQuinn on 2026/1/13.
//

import ForgeBase

public enum DNSPolicyDecision {
    case handleLocally // A / AAAA / PTR(fake)
    case passthrough // Valid but unsupported → sent upstream
    case refuse(DNSReturnStatus) // Invalid or explicitly refused
}

public enum DNSPolicyEngine {
    /// Decide DNS handling policy based on fast sniff result.
    ///
    /// Design contract:
    /// - FastSniffer **never** guarantees correctness
    /// - FastSniffer **only** filters obvious cases
    /// - Final correctness is enforced in slow path
    ///
    static func decide(_ fast: SniffedDNSQuery?) -> DNSPolicyDecision {
        guard let fast = fast else {
            return .handleLocally
        }

        switch fast.qtype {
        case .a, .aaaa, .ptr:
            return .handleLocally
        default:
            return .passthrough
        }
    }
}
