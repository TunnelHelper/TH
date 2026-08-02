# Babel 延迟检测与加权多路径

本文描述 TH 当前的 Babel 路径选择、持续延迟估计、质量传播和 Linux
weighted ECMP 行为。实现分别位于 `internal/babel`、
`internal/backend/linux/babel_backend.go` 和 `internal/config/settings.go`。

## 1. 两层决策

TH 不让权重替代 Babel 的可达性和可行性判断：

```text
Hello/IHU 活性 + Babel 可行性
             |
             v
有界链路 cost + multipath slack -> 候选集
             |
             v
带宽/RTT/抖动/置信度 score -> Linux nexthop weight 1..256
```

- 协议层负责存活、无环、主路径和候选准入。
- 数据面 score 只在已准入的候选间分流。
- 候选准入以真实的最小可行 metric 为基准，而不是被滞回暂时保留的旧主路径。
- IHU 或 Hello 失效永远先产生无穷 cost。旧 RTT 样本不能维持一条死亡链路。

## 2. 协议 cost 与带宽 K

启用 delay metric 后，新鲜且完成预热的 RTT 通过 RFC 9616 风格的有界映射
转换成链路 cost。没有新鲜样本时使用 Babel 的常规 Rx/Tx cost。

可选的 `weight_bottleneck_penalty` 使用加性形式：

```text
link_metric = delay_or_rx_tx_cost + round(K / local_link_bandwidth_mbps)
path_metric = sum(link_metric)
```

K 在每个本地链路上只加一次。不能在每一跳重复对已累计路径的 bottleneck
计算 `K/bottleneck`，否则同一个窄链路会被下游节点重复计数，破坏度量语义。
加法使用饱和运算，不会越过 Babel 的 retraction 值。

## 3. 持续延迟和抖动估计

延迟探测与 liveness 广告解耦。默认每 2 秒发送一个带时间戳的 Hello+IHU，
而 IHU 的通告周期和 hold time 保持原值。这样能提高测量分辨率而不缩短故障判定窗口。

### 3.1 样本过滤

时间戳先经过 RFC 9616 的负值、回绕和最大 3 分钟检查。有效样本再进入因果
3 点中值滤波：

```text
x'_n = median(x_(n-2), x_(n-1), x_n)
```

一个孤立尖峰不会污染均值和方差；连续两个同向变化会在下一个探测周期进入
估计器，因此真实的持续阶跃不会被永久忽略。被中值窗口确认且偏差大于
`max(6 * MAD, 5 ms)` 的中间样本计入 `outliers`，供健康页诊断。

### 3.2 时间感知 EWMA

滤波系数由实际采样间隔决定，而不是按包固定：

```text
a = 1 - exp(-dt / tau)
mean_n = mean_(n-1) + a * (x'_n - mean_(n-1))
var_n = (1-a) * (var_(n-1) + a * delta^2)
jitter_n = sqrt(var_n)
```

默认 `tau=30s`。丢包或调度延迟改变 `dt` 时，滤波器的物理响应时间仍保持一致。
前三个样本用中值和 `1.4826 * MAD` 建立稳健初值。另维护 10 分钟重置窗口内的
最小 RTT，帮助观察基础传播延迟。

### 3.3 新鲜度和置信度

默认需要 4 个有效样本完成预热，样本最大年龄为 10 秒。置信度为：

```text
warmup = min(samples / 4, 1)
freshness = 1                              age <= max_age/2
          = (max_age-age)/(max_age/2)      max_age/2 < age < max_age
          = 0                              age >= max_age
confidence = warmup * freshness
```

均值、抖动、置信度任一相对变化超过 10% 时可以发布质量更新；最短发布间隔为
`max(2 * probe_interval, 2s)`，并至少随正常 Update 周期发布一次。即使没有新样本，
探测计时器也会重新计算 freshness，使陈旧数据按时退出 cost 和 weight。

## 4. 端到端质量传播

Update 使用两个非 mandatory TH sub-TLV。未知它们的 Babel 实现会安全忽略。

| sub-TLV | 长度 | 内容 |
|---|---:|---|
| PathMetrics (4) | 8 | bottleneck Mbps `u32`，RTT us `u32` |
| PathQuality (5) | 12 | jitter us `u32`，age ms `u32`，confidence Q0.16 `u16`，reserved `u16` |

PathMetrics 中 `0xffffffff` 分别表示未知带宽和未知 RTT。可表示的 RTT 上限会饱和到
`0xfffffffe`，不会让内部 `int64` 负值在线上变成约 71 分钟的伪 RTT。
PathQuality 的 jitter 和 age 也使用 `0xffffffff` 表示未知，并在上限饱和，避免
混合已知/未知字段被误解为零或发生整数回绕。

逐跳组合规则：

| 属性 | 组合 |
|---|---|
| bottleneck | `min`，未声明链路不设限 |
| mean RTT | 各跳相加 |
| jitter | 各跳标准差相加 |
| age | 取最大值，并加入本节点 residence time |
| confidence | 取最小值 |

标准差相加是 Minkowski 不等式给出的保守上界，即使各跳延迟相关也不会低估。
residence time 防止一次收到的远端质量数据在本地永久保持“新鲜”。

共享 multicast 接口无法在同一个组播 Update 中表达每个接收者不同的 RTT；有显著
质量变化时，TH 会向各邻居发送带该邻居质量的 unicast Update。

## 5. 无量纲路径 score

对每个候选路径计算：

```text
score_i = (B_i / 100Mbps)^alpha
          / (RTT_i / 10ms)^beta
          / (1 + Jitter_i / 5ms)^gamma
          * confidence_i

weight_i = clamp(round(256 * score_i / max(score)), 1, 256)
```

固定参考值使 score 无量纲。改变 Mbps/bps 或 us/ms 的表示单位不会在指数不同时
改变路径排序。

- `B_i` 优先使用端到端 bottleneck，再回退本地声明带宽；完全未知按 1 Mbps 保守处理。
- 未知 RTT 使用 120 ms、未知 jitter 使用 20 ms，置信度使用 0.10。
- 只有 PathRTT 缺失时才回退新鲜的本地第一跳估计。
- 已知但过期的端到端 RTT不会回退成更小的第一跳 RTT，而是使用保守未知值。
- 非有限或非正 score 得到最小 weight 1；整个候选集都无有效 score 时等权 256。

全局 `alpha`、`beta`、`gamma` 默认均为 1，范围 `[0,4]`。每隧道的 `balance`
仍可覆盖 alpha/beta，映射为 `alpha=clamp(1+bias)`、
`beta=clamp(1-bias)`；gamma 使用全局值。

## 6. 权重稳定性

Linux multipath 权重变化可能导致流重新哈希。自动质量变化采用每前缀独立状态机：

1. 比较归一化流量份额，而不是直接比较 1..256 整数。
2. 所有份额变化不超过 10% 时不更新。
3. 显著变化必须连续观察两次。
4. 每个前缀两次 weight-only 更新至少间隔 60 秒。
5. 30 秒周期 reconcile 会重试已确认但仍在 cooldown 的目标。

候选增删、next hop 变化和故障撤回属于结构变化，立即安装。管理员显式修改全局
alpha/beta/gamma 也立即刷新，不受测量噪声冷却限制。若外部程序修改了内核路由，
下一次 reconcile 以 netlink 当前状态为准重新建立基线。

## 7. 配置与可观测性

默认 Babel 配置的相关字段：

```json
{
  "babel": {
    "delay_metric": true,
    "unicast_hello_seconds": 4,
    "delay_probe_interval_milliseconds": 2000,
    "delay_sample_max_age_milliseconds": 10000,
    "delay_smoothing_time_constant_milliseconds": 30000,
    "multipath_max_paths": 4,
    "multipath_slack": 512,
    "weight_bandwidth_exponent": 1,
    "weight_rtt_exponent": 1,
    "weight_jitter_exponent": 1,
    "weight_bottleneck_penalty": 0
  }
}
```

约束：probe 为 250..60000 ms；max age 必须大于 probe 且不超过 600000 ms；
tau 为 1000..600000 ms；指数必须有限且在 `[0,4]`；K 必须有限且在
`[0, 1e9]`。

TUI 的 Babel settings 可编辑这些字段，并提供 Live path metrics 页面。健康数据包含：

- 邻居 mean RTT、jitter、窗口 min、age、samples、outliers、confidence、fresh；
- 候选路径 metric、bottleneck、端到端 RTT/jitter/age/confidence、score；
- 已安装 weight 与当前目标 weight。

Tunnel dashboard 的 Babel peer 行显示 RTT、jitter、age、confidence 和 fresh/stale，
不会混入 WireGuard handshake/transfer 字段。

## 8. 限制

- 带宽是静态声明值，不是主动吞吐测量。
- Linux nexthop weight 是按流 hash 的统计比例，不是逐包调度保证。
- PathMetrics/PathQuality 是 TH 扩展；旧实现仍能交换基础 Babel 路由，但只提供
  本地回退质量。
- weight 只影响已通过 Babel 可行性和 slack 的候选，不能把不可达路径重新加入。

## 9. 验证重点

单元测试覆盖时间感知均值/方差、孤立尖峰、持续阶跃、新鲜度、未知值 sentinel、
多跳质量组合、真实 best metric 的 slack、无量纲 score、过期回退、权重份额阈值、
两次确认、每前缀 cooldown、结构变化和健康/TUI 展示。Linux namespace 集成测试
继续验证实际接口、路由所有权和并发 reconcile。
