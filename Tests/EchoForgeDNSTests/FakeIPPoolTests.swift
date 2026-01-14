import DNSClient
@testable import EchoForgeDNS
import Testing

@Suite("FakeIPPool")
struct FakeIPPoolTests {
    @Test("Duplicate allocation returns same IP; reverse & clear")
    func allocationDuplicateReverseClear() async throws {
        let ipPool = FakeIPPool()
        let a = await ipPool.assign(domain: "dup.com")
        #expect(a != nil)
        let b = await ipPool.assign(domain: "dup.com")
        #expect(b != nil)
        #expect(a == b)
        if let a = a {
            #expect(await ipPool.reverseLookup(a) == "dup.com")
        }
        await ipPool.clear()
        if let a = a {
            #expect(await ipPool.reverseLookup(a) == nil)
        }
    }
}
