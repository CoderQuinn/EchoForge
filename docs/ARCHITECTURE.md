# EchoForge 架构与迭代

> **角色**：**FakeDNS** + DNS 上游、缓存、熔断  
> **QuantumLink 中的位置**：L3 DNS — 在 **TCPStack 之前**（DNS 阶段）与 **TCP accept 之后**（dial 决策）  
> **最后更新**：2026-07-22  
> **架构审查**：[ARCHITECTURE_REVIEW.md](./ARCHITECTURE_REVIEW.md)（问题清单、优先级、测试对照）

---

## 1. 职责边界

| 做 | 不做 |
|----|------|
| DNS 查询处理、FakeIP 分配 | TUN 读写（NetForge） |
| `resolveDialDecision`（FakeIP→域名） | TCP 连接（TunForge） |
| 上游 DNS 组、breaker、cache | 路由规则匹配（ForgeRuleCore） |

---

## 2. 核心类型

| 模块 | 类型 |
|------|------|
| policy | `DNSService`, `DNSPolicyEngine`, `FakeIPPool`, `DNSCache` |
| upstream | `DNSUpstreamGroup`, `DNSUpstreamBreaker` |
| wire | `MinimalDNSParser`, `DNSMessageBuilder` |

NetForge 封装：`DNSRouter`（实现 `DialDecisionProvider`）。

---

## 3. 在数据流中的两阶段

**阶段 A — FakeDNS（先于 TCP）**

```
UDPStack → FlowController.didReceiveUDP
  → DNSClassifier.isDNS
  → DNSRouter.ingestDNSPacket
  → DNSService.handleDNSPayload
  → writeOutbound (DNS 应答)
```

**阶段 B — Dial 决策（TCP accept 后）**

```
DataPlaneController
  → dialDecisionProvider.resolveDialDecision(dstIP)
  → DNSService.resolveDialDecision
  → DialDecision (dialHost / dialIP / fromFakeIP)
  → 再交 ForgeRuleCore（规划）
```

---

## 4. 依赖

- ForgeBase, ForgeLogKit, swift-nio, NIOTransportServices  
- 无 TunForge / NetworkExtension

---

## 5. 测试

`EchoForgeTests`（XCTest，`swift test`）：

| 套件 | 焦点 |
|------|------|
| `DNSFastSnifferTests` | 快路径分类 / 拒绝压缩 |
| `MinimalDNSParserTests` | 慢路径、指针环、extractAnswers |
| `DNSMessageBuilderTests` | A/PTR/refuse 线格式 |
| `DNSPolicyEngineTests` | local / passthrough / 死 refuse |
| `DNSServiceTests` | A/AAAA/PTR、dial、prefetch、生命周期回归 |
| `EchoForgeDNSTests` | FakeIPPool、DNSCache、UDP relay |
| `DNSUpstreamGroupTests` / `DNSUpstreamBreakerTests` | hedge、熔断 |

架构问题与用例对照见 [ARCHITECTURE_REVIEW.md §6](./ARCHITECTURE_REVIEW.md#6-问题--测试对照表)。

---

## 6. 迭代记录

| 日期 | 变更 |
|------|------|
| 2026-01 | DNSService + FakeIPPool 初始 |
| 2026-02 | DNSRouter 接入 NetForge FlowController |
| 2026-02 | Upstream breaker / group |
| 2026-04-30 | 文档化；与 ForgeRuleCore 策略对齐列入 MVP |
| 2026-07-22 | 架构审查文档 + parser/builder/policy/FakeIP 生命周期回归测试 |

### Next（MVP）

- [ ] `DNSPolicyEngine` 与 ForgeRuleCore 统一域名策略（adapter）
- [ ] 扩展内 upstream DNS 从 runtime.json 配置（Phase 1）
- [ ] FakeIP 池与 PacketTunnel `198.18.0.0/16` 文档化一致
- [ ] Cache 过期时回收 FakeIP（或 LRU）— 见审查 A1
- [ ] Prefetch 纳入 inflight 限额 + cooldown sweep — 见审查 A2/A3

---

## 7. 链接

- [QuantumLink Architecture-Evolution](../../QuantumLink/docs/Architecture-Evolution.md)
- [NetForge ARCHITECTURE.md](../NetForge/docs/ARCHITECTURE.md)
- [ForgeRuleCore ARCHITECTURE.md](../../ForgeRuleCore/ForgeRuleCore/docs/ARCHITECTURE.md)
