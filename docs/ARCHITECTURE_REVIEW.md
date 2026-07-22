# EchoForge 架构审查报告

> **范围**：`Sources/EchoForge`（约 2k LOC 生产代码）+ `Tests/EchoForgeTests`  
> **角色**：嵌入式 FakeDNS（QuantumLink L3）— 查询拦截、FakeIP、上游 relay、dial 决策  
> **审查日期**：2026-07-22  
> **状态**：问题已文档化；对应单元/回归测试已落地（见 §7）。**本报告不修改生产行为**，仅锁定现状以便后续有意修复。

---

## 1. 系统定位与边界

EchoForge 是 SwiftPM 单模块库，不做 TUN/TCP/规则匹配：

| 负责 | 不负责（上游生态） |
|------|-------------------|
| DNS 查询处理、FakeIP 分配 | TUN I/O（NetForge） |
| `resolveDialDecision` | TCP 连接（TunForge） |
| 上游 DNS 组、breaker、cache | 域名规则（ForgeRuleCore） |

两阶段数据流：

```
阶段 A — FakeDNS（TCP 之前）
  UDP → DNSRouter → DNSService.handleDNSPayload → DNS 应答

阶段 B — Dial（TCP accept 之后）
  dstIP → DNSService.resolveDialDecision → DialDecision
       →（规划）ForgeRuleCore
```

逻辑分区：`wire/`（解析/构造）→ `policy/`（编排）→ `upstream/`（UDP/hedge/breaker）→ `logging/`。

---

## 2. 关键数据路径

### 2.1 查询路径

```
任意 EventLoop
  → DNSFastSniffer.sniffQuery          // 乐观、尽量无分配；拒压缩指针
  → DNSPolicyEngine.decide             // local / passthrough / refuse
  → hop 到 service.eventLoop
  → handleLocally  → MinimalDNSParser → A / AAAA / PTR / default→upstream
  → passthrough    → DNSUpstreamGroup
  → refuse         → buildRefuseResponse   // 引擎当前永不返回此分支
  → hop 回 callerLoop
```

### 2.2 Dial 路径

```
dstIP ∈ FakeIPPool？
  否 → DialDecision(dialIP: dstIP, fromFakeIP: false)
  是 → reverse domain
         cache.realIPs 有值 → dialIP = real
         否则 → dialHost = domain + prefetch
```

### 2.3 存储

| 存储 | 生命周期 | 回收 |
|------|----------|------|
| `DNSCache` | 进程内，按 TTL | lookup 过期删除 + `sweepExpired` |
| `FakeIPPool` | 进程内，双向 map | **无回收** |
| UDP `pendingMap` | 单次查询 | 超时/完成；上限 4096 |

---

## 3. 架构问题清单（按优先级）

### P0 — 正确性 / 资源耗尽

#### A1. Cache 与 FakeIP 生命周期解耦

**现象**：`DNSCache` 条目过期或被 sweep 后，`FakeIPPool` 中 domain↔IP 映射仍保留。  
**后果**：长期运行下 FakeIP 只分配不释放，最终耗尽 `198.18.0.0/16`（或更小 CIDR），`assign` 返回 nil → SERVFAIL。  
**期望**：sweep/expire 时回收或 LRU 淘汰 FakeIP（与 roadmap 一致）。  
**回归锁**：`testCacheExpiryDoesNotReleaseFakeIPMapping`、`testExpiredCacheStillReusesSameFakeIP`、`testDialDecisionSurvivesCacheExpiry`。

#### A2. Prefetch 绕过 `upstreamInflight` 限额

**现象**：业务上游走 `handleUpstream`（`maxUpstreamInflight = 64`），prefetch 直接调 `upstreams.query`，不计入 inflight。  
**后果**：突发域名解析时可额外打穿上游与 pending 表。  
**期望**：prefetch 与业务查询共享同一限额或独立更小限额。

#### A3. `prefetchCooldownUntils` / `inflightPrefetch` 无界增长

**现象**：失败域名写入 cooldown map；成功路径清理 inflight，但 cooldown 条目无周期性清理。  
**后果**：高基数域名场景下字典膨胀。  
**期望**：与 cache sweep 同周期清理过期 cooldown。

---

### P1 — 策略与 API 语义

#### B1. `DNSPolicyEngine` 为桩实现

**现状**：

| sniff 结果 | 决策 |
|------------|------|
| A / AAAA / PTR | `.handleLocally` |
| 其它已知 `DNSType`（如 ANY） | `.passthrough` |
| `nil` | `.handleLocally`（交给 slow path） |
| `.refuse` | **从不返回** |

ForgeRuleCore adapter 仍为 TODO（见 `ARCHITECTURE.md`）。  
`DNSService.handlerInternal` 的 `.refuse` 分支是死代码。  
**回归锁**：`DNSPolicyEngineTests.testPolicyNeverReturnsRefuseForSniffableQueries`。

#### B2. FastSniffer 与 Policy 的两阶段缝隙

**现象**：MX(15)/TXT(16) 等不在 `DNSType` enum → FastSniffer 返回 `nil` → Policy 判 local → Slow path `default` 再 upstream。  
**后果**：策略层日志/指标显示 “local”，实际行为是上游转发；后续接 ForgeRuleCore 时易误配。  
**回归锁**：`testUnknownWireTypesSniffNilThenLocal`、`testUnknownQTypeStillForwardsViaSlowPath`。

#### B3. 上游失败常变为 `nil`

**现象**：超时、熔断拒绝、inflight 过载 → `EventLoopFuture` success(`nil`)，而非 SERVFAIL/REFUSED。  
**后果**：调用方（NetForge）必须把 `nil` 当丢弃；客户端可能重试风暴，无明确 RCODE。  
**相关**：service 已释放时 `handleDNSPayload` 亦返回 `nil`（不再回显原包）。

---

### P2 — 结构与可维护性

#### C1. `DNSService` 编排过重

约 450 LOC，同时拥有 cache、pool、policy、prefetch、service-level breaker、sweep、dial。  
**后果**：无法注入小 CIDR 的 `FakeIPPool` 做 SERVFAIL 集成测；单测必须经完整服务。  
**期望**：拆 `PrefetchController` / 可注入依赖；或至少暴露 test hook。

#### C2. 双层 Circuit Breaker

- Service 级：`DNSService.breaker`（过载/超时累计）  
- Upstream 级：`DNSUpstreamGroup.Entry.breaker`（失败 streak + 慢 RTT）  

语义重叠，排障时需同时看两层；文档未澄清优先级。

#### C3. `startSweep` 职责混杂

`startSweep()` 同时：调度 cache sweep **并** `upstreams.start()`。  
启动失败仅 `print(...)`，不经 `EFLog`、不向上抛。  
**期望**：拆 `start()` / `startSweep()`；失败走日志与 Future。

#### C4. 硬编码配置

TTL 300、上游 8.8.8.8 / 1.1.1.1、hedge 50ms、timeout 3s、inflight 64 — 无 `runtime.json` / Config 类型（Phase 1 TODO）。

#### C5. 依赖与 API 卫生

- `NIOTransportServices` 在 `Package.swift` 声明但未使用  
- 公开 API 拼写：`builePTRResponse`  
- 源文件头仍写 `NetForge`  
- CI 有 coverage badge，但 workflow 未强制上传覆盖率

---

### P3 — 并发模型（需遵守的契约）

可变状态通过 `@unchecked Sendable` + **单一 EventLoop 亲和** 保护。  
公共 API 用 `flatSubmit` / `.hop(to:)` 跨 loop。  
**风险**：调用方若绕过公共 API 直接摸内部类型，无编译期防护。  
当前模型在契约遵守时正确；脆弱点在纪律而非算法。

---

## 4. Wire 层安全面

| 组件 | 行为 | 测试覆盖 |
|------|------|----------|
| `DNSFastSniffer` | 拒压缩指针、多问题、非 IN | 已有 `DNSFastSnifferTests` |
| `MinimalDNSParser` | 支持压缩；检测 pointer loop / OOB | **新增** `MinimalDNSParserTests` |
| `DNSMessageBuilder` | A/PTR/refuse/servfail | **新增** `DNSMessageBuilderTests` |
| `DNSUpstreamUDPRelay` | 校验 `remoteAddress` 防伪；txid 改写还原 | 超时/pending 满已测；成功路径与 spoof drop 仍薄 |

---

## 5. 推荐修复顺序（未在本 PR 实施）

1. **FakeIP 回收**：`sweepExpired` 回调释放 pool 映射，或 LRU + 容量告警  
2. **Prefetch 纳入 inflight / cooldown sweep**  
3. **Policy adapter**：ForgeRuleCore；启用或删除 `.refuse`  
4. **扩展 `DNSType` 或 FastSniffer**：使 MX/TXT 在策略层显式 passthrough  
5. **统一错误面**：上游失败返回 SERVFAIL（可配置）而非裸 `nil`  
6. **拆分生命周期 API** 与 Config 对象；去掉未用依赖；修正 `builePTRResponse`

---

## 6. 问题 ↔ 测试对照表

| ID | 问题摘要 | 测试 |
|----|----------|------|
| A1 | Cache 过期不释放 FakeIP | `DNSCacheTests.testCacheExpiryDoesNotReleaseFakeIPMapping` |
| A1 | 服务层过期后 FakeIP 仍复用 | `DNSServiceTests.testExpiredCacheStillReusesSameFakeIP` |
| A1 | Dial 在 cache 过期后仍反查域名 | `DNSServiceTests.testDialDecisionSurvivesCacheExpiry` |
| B1 | Policy 永不 refuse | `DNSPolicyEngineTests.testPolicyNeverReturnsRefuseForSniffableQueries` |
| B2 | 未知 qtype sniff nil → local | `DNSPolicyEngineTests.testUnknownWireTypesSniffNilThenLocal` |
| B2 | 未知 qtype 经 slow path 上游 | `DNSServiceTests.testUnknownQTypeStillForwardsViaSlowPath` |
| — | FakeIP 仅认已分配，非 CIDR 包含 | `FakeIPPoolTests.testIsFakeIPRequiresAllocationNotJustCIDR` |
| — | 跳过 network / `.1` | `FakeIPPoolTests.testPoolSkipsNetworkAndReservedDotOne` |
| — | 域名大小写/尾点归一化 | `FakeIPPoolTests.testDomainNormalizationIsCaseAndDotInsensitive` |
| — | Parser 指针环 / 压缩 answer | `MinimalDNSParserTests` |
| — | Builder 线格式 | `DNSMessageBuilderTests` |
| — | Relay 非法 payload / stop 取消 | `DNSUpstreamUDPRelayTests`（见新增用例） |

---

## 7. 本变更交付物

- 本文档：`docs/ARCHITECTURE_REVIEW.md`  
- 更新：`docs/ARCHITECTURE.md`（链接与测试说明）  
- 新增测试：  
  - `Tests/EchoForgeTests/MinimalDNSParserTests.swift`  
  - `Tests/EchoForgeTests/DNSMessageBuilderTests.swift`  
  - `Tests/EchoForgeTests/DNSPolicyEngineTests.swift`  
  - `EchoForgeDNSTests.swift` / `DNSServiceTests.swift` 增量回归  
- 验证：`swift test`（全量 XCTest）

---

## 8. 相关链接

- [ARCHITECTURE.md](./ARCHITECTURE.md) — 职责边界与生态位置  
- [README.md](../README.md) — 功能与集成示例  
- QuantumLink / NetForge / ForgeRuleCore 架构文档（见 `ARCHITECTURE.md` §7）
