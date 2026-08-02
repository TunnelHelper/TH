# Babel 加权多路径实现指南：端到端瓶颈带宽 + 可调带宽/延迟权重

本文档是 Babel 加权 ECMP 的完整实现规格，供实现者（含 AI agent）直接照做。
它把"木桶短板"（路径被最窄链路限制）和"带宽/延迟权重主导权"两个问题一起解决。

## 1. 背景与目标

### 1.1 现状

TH 的 Babel 引擎（`internal/backend/linux/babel_backend.go`）目前：

- 每隧道 `spec.babel {enabled, bandwidth_mbps}` 决定参与和声明带宽；
- 协议 cost 走 RFC 9616 延迟度量（RTT → 有界 cost），决定主路径与候选准入（slack）；
- weight 走 `babelMultipathWeight(bwBest, bwCandidate)`，输入**只有本地第一跳接口的
  声明带宽**（`bandwidthOf(interfaceName)`）。

### 1.2 缺陷（要解决的两个问题）

1. **木桶短板**：多跳网格中，节点 C 只知道"自己到 B 的带宽"，不知道 B 之后路径的
   瓶颈。一条"前段 1000 Mbps、后段 10 Mbps"的路会被高估，流量拥上去。
2. **主导权不可调**：当前 weight 是纯带宽（延迟完全失效）；协议 cost 是纯 RTT
   （带宽完全不参与排序）。需要把"带宽还是延迟主导分流"变成一个可调旋钮。

### 1.3 目标

- 任意节点通过 Babel 通告知道每条候选路径的**端到端瓶颈带宽**和**端到端平滑 RTT**；
- weight 用端到端值计算：`w ∝ bottleneck^α / path_rtt^β`，α/β 可调（默认 1,1）；
- 准入与排序职责不变：仍由 RTT cost + slack 决定候选集，weight 只管已准入路径的分流；
- 稳定性优先：权重变化超过阈值才重装内核路由，避免流重哈希抖动；
- 支持外部 PTP 接口（BIRD 风格显式配置），与 TH 隧道在瓶颈传播中行为一致。

### 1.4 非目标

- 不做逐字节/逐包分摊（内核 weight 是按流 hash，比例是统计近似）；
- 不做基于流特征的策略路由（交互流 vs 大流分类属于另一个层次）；
- 不做吞吐主动测量（带宽来自声明值，RTT 来自 RFC 9616 被动测量）。

## 2. 设计总览：职责分层

```
协议 cost（RTT，有界）── 主路径选择 + 故障切换 + 候选准入（metric ≤ best + slack）
        │
        ▼
候选集（SelectedRoutes，携带端到端瓶颈/端到端 RTT）
        │
        ▼
weight（bottleneck^α / path_rtt^β）── 已准入路径之间的流量分流
        │
        ▼
内核 multipath（nexthop 权重 1..256，按流 hash）
```

核心原则：**weight 只分"协议已经认证活着且无环"的路**。路径不可达时，Babel 的
活体检测（IHU 超时）→ metric 无穷 → 退出候选集 → 引擎重装路由，该路径的权重随之消失
（不存在"权重指向黑洞"的状态）。

## 3. 协议扩展：瓶颈带宽与端到端 RTT 的传播

### 3.1 核心机制

与 cost 相同地随 Update 逐跳传播，但组合规则不同：

| 属性 | 组合规则 | 每跳贡献 |
|---|---|---|
| cost（现状） | 加法 | 本跳链路 cost |
| **瓶颈带宽（新增）** | **min** | 本跳出站接口声明带宽 |
| **端到端 RTT（新增）** | 加法 | 本跳平滑 RTT（`n.rtt`） |

min 满足结合律：`min(min(a,b),c) = min(a,b,c)`，逐跳 min 等价于全路径 min。
节点不需要知道远端拓扑，只需要自己出站链路的声明带宽。

### 3.2 数据模型（`internal/babel/proto`）

`Update` 新增两个**派生字段**（不进线格式主体，模式与 RouterID/NextHop/V4ViaV6 相同）：

```go
// internal/babel/proto/tlv_update.go
type Update struct {
    // ...现有字段...

    // PathBottleneckMbps 是这条通告路径的端到端瓶颈带宽（Mbps）。
    // 未知/源头视为最大值（不设限）。
    PathBottleneckMbps int

    // PathRTTMicros 是端到端平滑 RTT 之和（微秒）。
    PathRTTMicros int64
}
```

线格式：新增一个 sub-TLV（复用现有 sub-TLV 框架，模式与 RFC 9616 Timestamp 相同），
编码在 Update 的 sub-TLV 区。标准 Babel 实现遇到未知 sub-TLV 会静默忽略，
因此向后兼容。

### 3.3 三节点例子

```
A ──(10 Mbps)── B ──(1000 Mbps)── C

A 通告 10.0.0.0/24：bottleneck = 10（源头=接口声明带宽），rtt = 0
B 收到后重通告：bottleneck = min(10, 1000) = 10，rtt = 0 + B→A 平滑RTT
C 收到后：bottleneck = min(10, 1000) = 10
  → C 知道到 10.0.0.0/24 的整条路瓶颈是 10 Mbps，无需知道 B 的拓扑
```

## 4. 节点行为

### 4.1 接收（`internal/babel/speaker.go` → `onUpdateReceived`）

```go
route.PathBottleneckMbps = upd.PathBottleneckMbps  // 缺失 → 视为未设置（∞）
route.PathRTTMicros      = upd.PathRTTMicros
```

存储到 `Route`（`internal/babel/route.go` 新增两个字段）。

### 4.2 转通告（`encodeRoutes`）

```go
bottleneckOut := min(route.PathBottleneckMbps, 出站接口声明带宽)
rttOut        := route.PathRTTMicros + 本接口邻居平滑RTT(n.rtt，μs)
```

"出站接口声明带宽"来源：TH 隧道取 `spec.babel.bandwidth_mbps`；外部 PTP 取
`settings.babel.interfaces.<name>.bandwidth_mbps`；未声明视为 ∞（该跳不设限）。

### 4.3 本地注入（`Advertise`，源头）

```go
bottleneck = 本隧道/外部接口声明带宽
rtt        = 0
```

### 4.4 导出（`SelectedRoute`）

`SelectedRoute` 增加 `BottleneckMbps int`、`PathRTTMicros int64`，随候选集导出。

## 5. weight 公式与 α/β 旋钮

### 5.1 公式（`internal/backend/linux/babel_backend.go`）

对每个目的前缀的候选集：

```
score_i = bw_i^α / rtt_i^β
w_i     = clamp( round( 256 × score_i / max_j(score_j) ), 1, 256 )
```

其中：

- `bw_i` = `SelectedRoute.BottleneckMbps`（端到端瓶颈）；缺失（对端是 babeld/bird
  等不认此字段的实现）→ 回退 `bandwidthOf(interfaceName)` 本地声明；
- `rtt_i` = `SelectedRoute.PathRTTMicros`；缺失 → 回退本邻居 `n.rtt`；
- `α`、`β` 可调指数，默认 `1.0, 1.0`（w ∝ 带宽/RTT）；
- 下限保护：权重最小 1（clamp 已有），差路径不被完全饿死。

### 5.2 数值例子

链路 A：1 Mbps / 1 ms；链路 B：1000 Mbps / 1000 ms；α=β=1：

```
score_A = 1/1   = 1
score_B = 1000/1000 = 1
w_A = w_B = 256        → 50:50（吞吐延迟比相等，各让一步）
```

比例相同的例子（10 Mbps/5ms vs 100 Mbps/50ms）同样得到 256:256。
这就是"带宽和延迟都占因素"的平衡点。

### 5.3 TUI 旋钮映射

一个滑块（左右键拖动），右偏带宽、左偏延迟，默认居中：

```
bias ∈ [-2, 2]（整数步进，默认 0）
α = 1 + bias
β = 1 - bias
```

- bias=0 → α=β=1（默认）；
- bias=+1 → α=2, β=0（纯带宽主导）；
- bias=-1 → α=0, β=2（纯延迟主导）。

settings 里存储显式的 `weight_bandwidth_exponent` / `weight_rtt_exponent`
（float64，默认 1.0，范围 [0,4]），TUI 只操作 bias 并写回换算结果，滑块旁实时显示
当前 α/β 与生效公式。

## 6. B-lite（可选）：带宽进入主路径选择

纯方案 A 只改分流，主路径选择仍是纯 RTT——极端场景下（10 Mbps/1ms vs
1000 Mbps/1000ms）主路径是薄链路，故障时全网塌到 10 Mbps。如需带宽参与排序：

```
metric = rtt_cost + K / bottleneck_bw      # K 默认 0（= 纯 A）
```

- K=0：行为与现状完全一致；
- K 调大：主路径开始偏向高瓶颈路径；
- K 只影响准入/排序，不影响 weight 公式（两旋钮各管一层，不冲突）；
- 保持加性形式，满足 RFC 8966 §3.5.2 的严格单调/左分配要求；
- 选择层已有的滞回（A.3）压住主路径抖动。

settings 字段：`weight_bottleneck_penalty`（默认 0）。

## 7. 外部 PTP 接口支持（BIRD 风格）

外部接口没有 TH 记录，在 daemon settings 显式声明：

```json
"babel": {
  "interfaces": {
    "gre-ext0": { "bandwidth_mbps": 100, "multicast": true },
    "tun-ext1": { "bandwidth_mbps": 10, "multicast": false, "neighbours": ["fe80::1"] }
  }
}
```

职责边界：

- TH 不创建/修改/删除外部接口（链路/地址/MTU/up 全归创建者），只在上面跑 Babel；
- 外部接口死亡 → Hello/IHU 超时 → 撤回，与 TH 隧道一致；
- 路由安装仍用引擎 realm（protocol 242），只删自己装的路由；
- 瓶颈传播对外部接口与 TH 隧道一视同仁（都贡献声明带宽）。

约束：

- 接口名不能与 TH 隧道接口重名（配置校验拒绝）；
- 组播能力因隧道类型而异：GRE/IPIP 通常可组播；不支持的就 `multicast: false` +
  `neighbours` 显式列表；
- **IPv4-only 外部链路的前置项**：当前 Speaker 只绑 udp6 socket，Babel-over-IPv4
  需要加 udp4 socket（双栈），否则只能支持有 IPv6 LLA 的外部链路。

## 8. 配置总览（`internal/config/settings.go`）

```json
"babel": {
  "router_id": "...",
  "route_table": 0,
  "delay_metric": true,
  "unicast_hello_seconds": 4,
  "multipath_max_paths": 4,
  "multipath_slack": 512,
  "weight_bandwidth_exponent": 1.0,
  "weight_rtt_exponent": 1.0,
  "weight_bottleneck_penalty": 0,
  "interfaces": { },
  "advertise": { "source_interfaces": ["lo"], "include": [], "exclude": [] }
}
```

校验规则（`BabelSettings.Validate()`）：

- 指数 ∈ [0,4]；
- K ≥ 0；
- `interfaces` 键为合法接口名（1-15 字符，无空白），且不与 TH 隧道接口重名；
- 外部接口的 `neighbours` 地址合法、`bandwidth_mbps` 范围同隧道；
- 既有字段校验不变。

## 9. 稳定性（冷却阈值）

权重变化触发内核路由更新 → 流重哈希 → 连接抖动。要求：

- weight 输入用**平滑 RTT**（`n.rtt` 已是指数平滑）和**静态声明带宽**；
- 引擎在 `installRoutes` 前比较新旧权重：只有任一候选的 score 相对变化 ≥ 10%
  才重装内核路由，否则沿用上次安装的路由；
- 实现：引擎记录上次安装的权重指纹（`map[prefix]string`），与本次比对后决定是否
  重装。

## 10. 边界情况

| 场景 | 行为 |
|---|---|
| 对端不认识新 sub-TLV（babeld/bird） | 字段缺失 → 回退本地第一跳值，不报错、不降级 |
| 未声明带宽的接口 | 视为 ∞，该跳不设限（min 无效果） |
| 带宽 0 | 视为未声明（∞），不允许用 0 打死路径 |
| path RTT 回绕 | 内部一律 int64 μs 累加；线格式按 RFC 9616 uint32 语义编码 |
| 路由撤回/过期 | 瓶颈值随路由消失，hold-time 条目不导出 |
| 候选集变化 | 存活候选重新归一化；只剩一条时退化为单路径（无 multipath） |
| 外部 PTP 只有 IPv4 | 依赖双栈前置项，否则暂不支持 |

## 11. 实现顺序（文件级清单）

1. **proto 层**：`internal/babel/proto/tlv_update.go` 加字段；`proto/parser.go`
   加 sub-TLV 编解码；单测覆盖：未知 sub-TLV 忽略、RTT 回绕、min 语义。
2. **speaker 层**：`internal/babel/route.go` 加存储字段；`speaker.go` 的
   `onUpdateReceived` 存储、`encodeRoutes` 重算、`Advertise` 源头值、
   `SelectedRoute` 导出；单测覆盖三跳 min 传播。
3. **settings 层**：`internal/config/settings.go` 加 α/β/K + `interfaces` 外部
   PTP 结构 + 校验 + 默认值。
4. **引擎层**：`internal/backend/linux/babel_backend.go` 的
   `babelRoutesToNetlink` 改用端到端值、`babelMultipathWeight` 换成
   `bottleneck^α/rtt^β`、权重冷却指纹、合并外部接口（`ext:<name>` 合成 ID）；
   单测覆盖公式、回退、冷却。
5. **双栈前置**：Speaker 增加 udp4+udp6 双 socket（IPv4-only 外部 PTP 依赖）。
6. **TUI**：`internal/app/settings.go` 加 bias 滑块 + α/β 实时显示。
7. **集成测试**：三节点 netns（见第 12 节）。

## 12. 测试计划与验收标准

### 12.1 单元测试

- sub-TLV 编解码 + 未知 sub-TLV 忽略；
- min 传播：模拟三跳通告链，断言每跳结果；
- weight 公式：α/β 变化时比例变化正确；缺字段回退本地值；clamp 下限 1；
- 冷却阈值：微小 RTT 波动不触发重装，≥10% 才触发。

### 12.2 集成测试（三节点 netns）

拓扑：A（10 Mbps 声明）─ B（1000 Mbps）─ C，C 另有平行路径 D（1000 Mbps）到同一前缀。

- 断言 C 学到的候选 `BottleneckMbps == 10`（不需要知道 B 的拓扑）；
- 断言两路 weight 按端到端值成比例（默认 α=β=1）；
- 调大 β 后比例向低延迟路倾斜、调大 α 后向高瓶颈路倾斜；
- 验证 10% 冷却：模拟微小 RTT 波动，断言内核路由未重装。

### 12.3 验收标准

- 三节点测试证明端到端瓶颈可见；
- `w ∝ bottleneck^α / path_rtt^β` 端到端生效，α/β 可调且默认 (1,1)；
- 冷却阈值生效；
- 外部 PTP（声明带宽）与 TH 隧道行为一致；
- 全部单测/集成/race/guard 通过。

## 13. 参考文件

- `internal/babel/proto/tlv_update.go`、`proto/parser.go`：Update 结构、sub-TLV 编解码
- `internal/babel/route.go`、`speaker.go`：Route/SelectedRoute、通告与选择
- `internal/backend/linux/babel_backend.go`：引擎、weight、路由安装
- `internal/config/settings.go`：Babel settings 与校验
- `internal/app/settings.go`：TUI settings 视图
- `internal/model/types.go`：`BabelTunnelConfig`
- RFC 8966 §3.5.2（metric 代数）、RFC 9616（延迟度量与时间戳）、RFC 9229（v4-via-v6）
