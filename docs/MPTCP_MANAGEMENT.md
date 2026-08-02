# TH 对 MPTCP 基础设施的管理设计（可选特性，默认关闭）

本文档是 TH 管理 MPTCP（Multipath TCP）基础设施的实现规格，供实现者（含 AI
agent）直接照做。核心立场：**TH 管理“多路径基础设施”，不替应用决定是否使用
MPTCP**。默认关闭，能力检测失败时优雅降级，不影响 Babel 和隧道本身。

## 1. 背景与目标

### 1.1 现状

TH 已经具备：

- 隧道生命周期管理（创建/删除/启停、地址、路由、ownership）；
- Babel 加权 ECMP：无量纲 bandwidth/RTT/jitter/confidence score 写入内核
  nexthop weight；
- 一套“desired state + reconcile”的 daemon 架构（`/var/lib/th` 为唯一事实源）。

MPTCP 单流聚合（应用单线程同时使用多条隧道）依赖三层配合：

1. **应用层**：socket 设置 `IPPROTO_MPTCP`/`MPTCP_ENABLED`（或 mptcpize 强制）；
2. **内核 path manager**：按“本地 endpoint × 对端宣告地址”自动创建 subflow；
3. **路由层**：每个 subflow 是独立四元组，被 ECMP 按权重哈希到不同隧道。

目前第 3 层由 TH 的 Babel 权重天然提供，但第 2 层的 endpoint 注册（`ip mptcp
endpoint add …`）是手工活，与隧道生命周期脱节：隧道删了 endpoint 还在、权重算了两
条路 endpoint 只注册一条、内核没开 MPTCP 时无人提示。

### 1.2 目标

- TH 在隧道生命周期内自动维护 MPTCP endpoint 集合（增/删/重建），保证
  **endpoint 集合 == 有地址的启用隧道集合**；
- 能力检测：内核无 MPTCP（版本 < 5.6、`CONFIG_MPTCP` 未开、`mptcp_pm` genl
  family 缺失）时明确报告，Babel 与隧道功能不受影响；
- 可选管理节点级 `net.mptcp.scheduler`（默认不动系统设置）；
- 所有权纪律：只清理“地址属于 TH 自建接口”的 endpoint，其他一律不动；
- 满足 ROADMAP 不可变约束 1/4：**不执行外部命令**（不用 `ip mptcp`），endpoint
  管理走 generic netlink family `mptcp_pm`（与 `ip mptcp` 同一套内核 API）。

### 1.3 非目标（v1 明确不做）

- 不强制任何应用使用 MPTCP（不做全局 LD_PRELOAD/mptcpize）；
- 不实现 userspace path manager（`pm_type=1`），不实现“每地址对 N 条 subflow”
  （N-diffports）——这决定 subflow 数量上限，见 §6；
- 不做逐包/逐字节分摊（内核 weight 是流级哈希，比例是统计近似）；
- 不管理除 scheduler 之外的全部 MPTCP sysctl；
- 不支持 netns 内隧道（v1 只处理 root netns；隧道若在 netns 中，endpoint 需按
  netns 分别管理，列入 v2）。

## 2. 职责边界：谁管什么

| 层 | 谁 | 管什么 | TH 是否介入 |
|---|---|---|---|
| 应用 | 应用进程 | 是否开启 MPTCP（socket option） | 否（文档提示） |
| subflow 创建 | 内核 path manager | 按地址对自动建 subflow、数量上限 | 否（v1） |
| endpoint 集合 | TH（本文档） | 地址注册/注销、生命周期、重建 | 是 |
| 路由分发 | 内核 ECMP / TH Babel 权重 | subflow 落哪条隧道 | 是（已有） |
| scheduler | 系统/TH（可选） | subflow 间字节分配 | 可选（§3.3） |
| 能力检测 | TH | 内核是否可用、降级报告 | 是 |

一句话：**TH 管“基础设施一致性”，内核管 subflow，应用管选择。**

## 3. 配置面设计

### 3.1 daemon settings（`/etc/th/thd.json`）

新增顶层 `mptcp` 段，默认关闭：

```json
{
  "mptcp": {
    "enabled": false,
    "scheduler": ""
  }
}
```

- `enabled`：总开关。`false`（默认）时 TH 不注册任何 endpoint、不改任何 sysctl；
- `scheduler`：可选，`""` 表示不动系统默认；非空时必须是内核 `available_schedulers`
  中的名字（如 `default`、`roundrobin`），写入 `net.mptcp.scheduler`。写入失败只
  告警不失败（见 §5）。

### 3.2 per-tunnel 开关

每个隧道可显式覆盖（`nil` = 跟随全局）：

```json
{
  "spec": {
    "mptcp": { "endpoint": true }
  }
}
```

- `endpoint: null`（默认）→ 跟随 `mptcp.enabled`；
- `endpoint: false` → 即使全局开启也不为该隧道注册 endpoint（例如不想让某条
  隧道被 MPTCP subflow 使用）；
- SRv6 无接口地址，不允许参与（校验拒绝，类比 Babel 对 SRv6 的处理）。

### 3.3 scheduler 的可选管理

- 只在 `scheduler` 显式非空时写入 sysctl；
- 写 sysctl 失败 → `th health` 与 observation 中告警，endpoint 功能继续；
- 文档需说明：scheduler 是节点全局的，影响该主机**所有** MPTCP 流量，不只是 TH
  隧道，因此默认不动。

## 4. endpoint 生命周期

### 4.1 触发点

endpoint 状态完全从隧道记录推导，reconcile 逻辑：

```
期望集 = { (隧道地址, subflow|signal 标志) }
         for 隧道 in 隧道记录
         where 隧道.enabled && 有接口地址
         && (spec.mptcp.endpoint != false)
         && (spec.mptcp.endpoint != nil || mptcp.enabled)

当前集 = genl dump mptcp_pm endpoints（按地址匹配）

缺 → MPTCP_PM_ADD_ADDR（SUBFLOW 标志，可选 SIGNAL）
多 → MPTCP_PM_DEL_ADDR，仅当该地址属于 TH 自建接口（§4.3）
```

挂点：

| 事件 | 动作 |
|---|---|
| 隧道 Apply（链路+地址就绪后） | upsert endpoint |
| 隧道禁用/删除/地址变更 | 删除旧 endpoint，按新状态 upsert |
| daemon 启动 | 从隧道记录重建期望集，校正差异 |
| 周期性 reconcile（30s） | 对账，自愈手工漂移 |

注意顺序：endpoint 注册必须在**地址就绪之后**（类似 Babel speaker 需要在链路存在
后构建；见 §5 的已知排序问题）。

### 4.2 标志位策略

- 发起侧注册 `MPTCP_PM_ADDR_FLAG_SUBFLOW`：允许以该地址为源向对端地址发起
  subflow；
- `SIGNAL` 标志（通过 ADD_ADDR 向对端宣告）v1 提供配置位，默认与 SUBFLOW 同开，
  便于对端发起反向 subflow；
- 每个隧道地址注册一条 endpoint；重复地址（同隧道多地址）逐条注册。

### 4.3 所有权与清理

遵循 ROADMAP 不变式 9（只删可证明属于 TH 的对象）：

- endpoint 的 ownership 判据 = **该地址属于某个 TH 自建接口**（接口名与隧道
  记录匹配 + 地址在隧道 `spec.addresses` 中）；
- 启动清理：dump 现有 endpoints，仅删除“地址属于 TH 接口但不在期望集”的孤儿；
- 非 TH 地址的 endpoint（用户手工配置给别的用途）**一律不动**，即使 `mptcp.enabled`
  已开启；
- 隧道删除 → 先删 endpoint 再删链路（顺序避免地址消失后无法反查所有权）。

## 5. 能力检测与降级

### 5.1 检测项

1. 内核版本 ≥ 5.6（`CONFIG_MPTCP=y/m`）；
2. generic netlink family `mptcp_pm` 存在（genl 查询）；
3. （可选）`net.mptcp.scheduler` 可读，`available_schedulers` 含请求值。

### 5.2 降级行为

- 检测失败 → observation/health 标记 `mptcp: unsupported (原因)`；
- `mptcp.enabled=true` 但不可用 → **不注册 endpoint、不报错阻断**，Babel 和隧道
  照常；health 明确提示“MPTCP 不可用，多路径基础设施未生效”；
- scheduler 写入失败 → warning，不改变 endpoint 行为；
- 检测在 daemon 启动和每次设置更新时进行。

### 5.3 已知排序问题（实现时一并处理）

当前 `Backend.Apply` 中 Babel reconcile 在链路创建**之前**执行（
`internal/backend/linux/backend.go` 的 `babel.reconcile()` 位于 switch 之前），新
隧道第一次 Apply 时 speaker 看不到接口。MPTCP endpoint 注册必须避免同样的坑：

- endpoint 注册放在链路/地址 apply **之后**（同一 Apply 内）；
- 若当次 Apply 因故无法注册（地址未就绪），标记 pending 并依赖 30s 周期性
  reconcile 完成——与 Babel speaker 的最终一致策略一致；
- 建议顺手把 Babel reconcile 的调用点移到隧道 apply 之后（独立小改动，需回归
  测试），否则两条链路永远差一个周期。

## 6. 与 Babel 权重的一致性：预期管理

这是本文档最重要的“不承诺”条款：

1. **endpoint 集合与隧道集合一致**是 TH 的硬保证；
2. **subflow 落点与权重比例一致**只是统计保证：内核按 weight 分配哈希桶，每条
   subflow 独立以 p:(1-p) 概率落路。subflow 数量 N 时，少数派路径（权重 p）一条都
   没有的概率是 `p^N`：3:1 权重、N=6 时约 18%，N=12 时约 3%；
3. **默认内核 path manager 每地址对最多一条 subflow**，双隧道双地址拓扑通常只有
   2~4 条——统计保证很弱。v1 不解决（userspace PM/N-diffports 列入 v3），文档和
   TUI 需要如实提示“聚合利用率取决于 subflow 数量”，不承诺单流必然聚合；
4. **字节分配 ≠ subflow 分配**：scheduler（默认 min_rtt）决定每个 subflow 搬多少
   字节；只有 `roundrobin` + coupled CC 时才接近按权重利用。TH 管 endpoint，不替
   scheduler 背书；
5. **共享 underlay 不可知**：两条隧道同一条物理链路时瓶颈相同，MPTCP 无法凭空
   聚合，TH 不承诺探测该信息。

## 7. 可选 v2：源地址路由钉扎

当需要确定性（放弃统计保证）时：

- 为每条隧道建独立路由表 + rule：`src=<隧道地址>` → 对应隧道表（TH 已管理
  rules/tables，直接扩展）；
- 每个 subflow 以隧道地址为源 → 被 rule 钉死在该隧道，ECMP 权重不再参与；
- 代价：subflow 落点确定，但**字节分配完全交给 MPTCP scheduler**，TH 权重对
  MPTCP 流量失效（普通 TCP 多流仍走权重）。
- 设计决策：v1 不实现，保持“权重统计分发”为默认。

## 8. 风险清单

- **全局 sysctl 副作用**：scheduler 影响非 TH 流量 → 默认不写、显式才写；
- **endpoint 孤儿**：daemon 崩溃后残留 → 启动按所有权判据清理（§4.3）；
- **应用不 opt-in**：配好 endpoint 但应用不用 MPTCP → 无任何效果，TUI 提示而非
  报错；
- **netns**：v1 只支持 root netns，文档明示；
- **地址漂移**：隧道地址变更时 endpoint 未同步 → 靠对账自愈（§4.1）。

## 9. 实现顺序（文件级清单）

1. **genl 层**：`internal/backend/linux/mptcp.go` —— 新建 `mptcpControl`：
   - 探测 family `mptcp_pm`；
   - `AddEndpoint(addr, flags)` / `DelEndpoint(addr)` / `ListEndpoints()`
     （`MPTCP_PM_CMD_ADD_ADDR/DEL_ADDR/GET_ADDR`）；
   - 版本/`CONFIG_MPTCP` 探测（`/proc`/uname + genl 结果交叉验证）；
   单测：fake genl、地址/标志编解码。
2. **settings 层**：`internal/config/settings.go` 加 `Mptcp MptcpSettings`
   （`enabled`、`scheduler`）+ `Validate()` + `Defaults()`（enabled=false）；
   单测：默认值、scheduler 白名单、非法值。
3. **model 层**：`internal/model/types.go` 加 per-tunnel `Mptcp *MptcpTunnelConfig`
   （`endpoint *bool`）+ `validateTunnelMptcp`（SRv6 拒绝、布尔三态）；
   单测：三态语义、SRv6 拒绝。
4. **backend 挂点**：`internal/backend/linux/backend.go` 的 Apply/Remove/Delete
   中，在链路/地址就绪后调用 `mptcp.reconcile()`；把 Babel reconcile 移到隧道
   apply 之后（修复 §5.3 排序问题，需回归 Babel 测试）。
5. **启动/周期对账**：daemon 启动与 30s 周期 reconcile 调用 §4.1 对账逻辑；
   孤儿清理按所有权判据。
6. **健康面**：`th health` + observation 输出 `mptcp: enabled/unsupported`、
   endpoint 数量；TUI Babel settings 页加 MPTCP 段（开关、scheduler 选择、
   endpoint 计数，外部接口同理只读提示）。
7. **TUI**：`internal/app/settings.go` 增加 MPTCP 编辑项；隧道编辑器加 per-tunnel
   endpoint 开关；能力不可用时显示原因。
8. **测试**：
   - 单测：config/model 校验、ownership 判据、对账 diff；
   - fake genl：Add/Del/List、孤儿清理只删 TH 地址；
   - 集成（`//go:build integration`）：netns 双隧道 + 内核 MPTCP 可用时的
     endpoint 出现/消失断言；不可用时降级断言。

## 10. 验收标准

- `mptcp.enabled=false`（默认）：零 endpoint、零 sysctl 写入、health 显示关闭；
- `enabled=true` + 内核支持：启用隧道的地址全部注册为 endpoint，禁用/删除后
  1 个周期内消失；
- `enabled=true` + 内核不支持：隧道和 Babel 不受影响，health 明确报 unsupported；
- 手工注册的非 TH endpoint 在任何操作下都保持不变；
- daemon 重启后 endpoint 集合与隧道记录一致（无孤儿、无缺失）。
