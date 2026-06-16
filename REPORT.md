# 设计与实验报告：简化版客户端—网关抗量子迁移握手协议

> 配套代码见同目录各 `.py` 文件；运行方式见 [README.md](README.md)。
> 本报告中的实验数值由 `python main.py experiment` 自动产出，下表为一次代表性运行结果
> （运行环境见 §6.1）。

---

## 1. 运行形态选择说明：为何用真实 socket 两进程 + bench/experiment 编排

题目要求“基于真实 TCP socket”。本实现没有在内存里直接传递 Python 对象，而是：

- **真实分帧与序列化**：每条消息都经 `messages.py` 确定性序列化为字节，再经 `wire.py`
  的「4 字节大端长度前缀 + payload」分帧通过 `socket.sendall` / `recv` 传输。这样
  **通信开销（应用层字节数，含帧头）才是真实、可测量的**，而不是凭空估算。
- **真实双方视角**：客户端与网关各自维护**独立**的 transcript 增量哈希，分别喂入自己
  “实际收发的字节”。只有当双方对消息字节的看法完全一致时，transcript hash 才对齐、
  session_key 才相同——这正是中间人篡改能被检出的根本原因。若在内存里共享对象，就**无法**
  暴露“双方字节视图不一致”这一关键安全性质。
- **编排便利**：`run_handshake()` 在临时端口拉起一个网关线程、客户端连 `127.0.0.1`
  跑通四步后合并双方 metrics；`bench` / `experiment` 复用持久化的 `GatewayServer`
  连续跑 N 次。演示时则用两个真实终端分别启动 `gateway` 与 `client`。

---

## 2. 接口设计

### 2.1 C++ struct ↔ Python 字段映射

| C++ `HandshakeResult`                     | Python `HandshakeResult`        | 说明 |
|-------------------------------------------|---------------------------------|------|
| `std::vector<uint8_t> client_session_key` | `client_session_key: bytes`     | 客户端会话密钥（32B）|
| `std::vector<uint8_t> gateway_session_key`| `gateway_session_key: bytes`    | 网关会话密钥（32B）|
| `bool success`                            | `success: bool`                 | 双方密钥逐字节一致才为 True |
| `std::string mode`                        | `mode: str`                     | **实际** selected_mode |
| `double time_ms`                          | `time_ms: float`                | = `metrics.end_to_end_ms` |
| —（扩展）                                  | `warnings: list[str]`           | 安全警告 |
| —（扩展）                                  | `metrics: Metrics`              | 通信/计算/端到端开销 |

函数签名一致：
`run_handshake(mode, client_supported_algs, gateway_supported_algs) -> HandshakeResult`。

### 2.2 `mode` 与 `selected_mode` 语义

- `mode` 是客户端**请求**的模式：
  - `"auto"`：客户端公布其 `client_supported_algs` 全集，由网关按安全偏好选最高；
  - 具体模式（`legacy`/`hybrid`/`pq-only`）：客户端**仅公布该模式**。这实现了
    **fail-closed 冲突策略**——若网关不支持该模式，则交集为空、握手直接失败，**不静默降级**。
- `selected_mode` 是网关协商后**实际选定**的模式，回填在 `GatewayHello.selected_mode`，
  并作为 `HandshakeResult.mode`。

### 2.3 `Metrics` 字段含义

| 字段 | 含义 |
|------|------|
| `bytes_c2g` / `bytes_g2c` / `bytes_total` | 通信开销：客户端→网关 / 网关→客户端 / 合计字节（含帧头）|
| `per_message_bytes` | 每条消息的字节数（含帧头）|
| `num_messages` / `num_round_trips` | 消息条数(4) / 往返次数(2) |
| `client_compute_ms` / `gateway_compute_ms` | 计算开销：各侧所有密码/序列化操作 perf_counter 耗时之和 |
| `op_timings_ms` | 逐操作计时，键形如 `client.dh_keygen` / `gateway.kem_encaps` |
| `end_to_end_ms` | 端到端：客户端发首包到收到 GatewayFinished 的墙钟时间 |

---

## 3. 三种模式的密钥派生差异与 KDF 参数选择

```text
classical_secret = DH(self_dh_private, peer_dh_public)        # X25519，再经 SHA-256 压成 32B
pq_secret        = KEM.Decaps / Encaps                        # 网关 encaps、客户端 decaps 得相同 32B

legacy : ikm = classical_secret
pq-only: ikm = pq_secret
hybrid : ikm = len(classical)||classical || len(pq)||pq       # 长度前缀拼接，消除拼接歧义

session_key = HKDF-SHA256(ikm, salt = transcript_hash_TH1, info = "hybrid-pq-migration-v1", L = 32)
```

**KDF 参数选择理由**：
- 采用标准 **HKDF-SHA256（Extract-then-Expand, RFC 5869）**，把可能非均匀的 DH/KEM 秘密
  先 Extract 提纯为均匀 PRK，再 Expand 出会话密钥。
- **`transcript_hash` 作 salt**：使会话密钥绑定整段握手脚本（信道绑定）。任何对握手消息
  的篡改都会改变 salt → session_key 不同 → 后续 Finished MAC 验证失败。把握手哈希放在
  salt（而非 info）符合 HKDF 中“salt 承载上下文随机性/绑定值”的用法。
- **`context` 作 info**：`"hybrid-pq-migration-v1"` 做**域分离**，避免与其他协议/版本/用途
  复用同一密钥材料。
- **hybrid 用长度前缀拼接**而非裸接，消除 `a||b` 的解析歧义（见任务一 Q3）。

---

## 4. transcript hash 与 Finished MAC 绑定、降级保护原理与安全假设

### 4.1 传输文本绑定（transcript hash）

增量 SHA-256：每收/发一条消息，就把其**规范化字节**喂入。定义两个快照：
- `TH1 = SHA256(ClientHello || GatewayHello)` —— 用于派生 session_key 与 ClientFinished；
- `TH2 = SHA256(ClientHello || GatewayHello || ClientFinished)` —— 用于 GatewayFinished。

### 4.2 Finished MAC 绑定上下文

```text
finished_key (方向各一) = HKDF(session_key, info = "client finished" / "gateway finished")
client_finished_mac  = HMAC(client_finished_key,  TH1 || mode || algs || client_nonce || gateway_nonce)
gateway_finished_mac = HMAC(gateway_finished_key, TH2 || mode || algs || client_nonce || gateway_nonce)
```

MAC 显式覆盖**协商模式、算法列表、双方 nonce**。由于 `finished_key` 派生自 `session_key`
（而后者绑定 `TH1`），任何对协商内容的篡改都会令双方 MAC 不一致 → 握手失败。

### 4.3 降级保护字段

```text
early_key                  = HKDF(ikm, info = "downgrade-protection")     # 由握手共享密钥派生
downgrade_protection_field = HMAC(early_key, 客户端 supported_algorithms || client_version)
```

网关对**它实际收到的**客户端算法列表做 MAC；客户端用**自己发出的原始列表**重算并比对。
中间人若裁剪/篡改算法列表（如把 `[legacy,hybrid,pq-only]` 改成 `[legacy]`），网关算出的
字段就对应被篡改的列表，与客户端期望不符 → **检出并失败**。而中间人**不知道 `early_key`**
（它由 DH/KEM 共享密钥派生，被动观测公钥无法恢复），故无法伪造该字段。
这一点已被 `tests.py` 中 `test_mitm_strip_*` 验证。

**双重保护**：即使没有降级字段，篡改算法列表也会让双方 ClientHello 字节视图不同 →
`TH1` 不同 → session_key 不同 → Finished MAC 失败。降级字段与 transcript 绑定互为冗余。

### 4.4 安全假设（重要、诚实声明）

- 本协议**没有长期身份**。`gateway_authenticator` 仅由握手共享密钥派生，本质是
  **密钥确认（key confirmation）**：它证明对端算出了相同的共享密钥，但**不**认证网关身份。
- 因此降级保护的真实有效性**依赖 transcript MAC 绑定 + 共享密钥保密性**，能挡住
  **不知道共享密钥的被动/半主动中间人**；但对能完全冒充网关、与客户端独立完成 KEM/DH 的
  **主动中间人**无效——这需要证书或预共享 PSK 提供的长期身份认证才能解决。真实部署中
  `gateway_authenticator` 应替换为对长期密钥的签名或基于 PSK 的 MAC。

### 4.5 legacy 兼容 + 告警

任意一方仅支持 legacy 时，协商落到 legacy，握手**仍能完成**，但 `warnings` 输出：
> “对端不支持后量子算法，本次握手仅使用传统 DH，不具备抗量子安全性”。

---

## 5. 开销测量口径（务必区分，不混用）

| 开销类型 | 口径 | 采集方式 | 性质 |
|----------|------|----------|------|
| 通信开销 | 一次完整握手在 socket 上传输的**应用层字节数（含 4B 帧头）** | `wire.py` 收发处累加，按消息/方向拆分 | 每模式**确定值**，报精确数字 |
| 计算开销 | 单个密码/序列化操作的**墙钟 CPU 时间**（`time.perf_counter`） | `metrics.OpTimer` 包裹每个操作，分 client/gateway 汇总 | 统计量（mean/median/stdev/min/max/p95）|
| 端到端时延 | 客户端发 ClientHello 到收 GatewayFinished 的**墙钟时间** | `protocol.client_handshake` 计时 | = 通信 + 计算 + OS 调度 |

> localhost 上网络时延极小，故**通信开销用“字节数”刻画、计算开销用“CPU 时间”刻画，二者分列**，
> 不把字节当时间、也不把时间当字节。

---

## 6. 实验与分析（任务六）

### 6.1 运行环境与所用原语

| 项 | 值 |
|----|----|
| 操作系统 | Windows-11-10.0.26200-SP0 |
| CPU | AMD64 Family 25 Model 116 (AuthenticAMD) |
| 内存 | 15.2 GB |
| Python | 3.13.3 |
| 传统 DH | **x25519（真实库 `cryptography 46.0.3`）** |
| 后量子 KEM | **ML-KEM-768（真实库 `quantcrypt`，底层 PQClean，FIPS 203）** |

> 传统与后量子**均为真实实现**。后量子 KEM 经 `quantcrypt` 调用 PQClean 的 ML-KEM-768，
> 公钥 1184 B、密文 1088 B、共享密钥 32 B，与 FIPS 203 规范一致。
> `primitives.py` 按 `liboqs > quantcrypt > toy` 的优先级自动选用首个可用的真实后端，
> 协议代码零改动。仅当三者都不可用时才回退 toy（届时运行时会打印 toy 声明）。

### 6.2 实验一：握手协议性能与正确性（每模式 warmup=10 + 计时 100 轮）

| mode | avg_time_ms | min_time_ms | max_time_ms | std_time_ms | comm_bytes | correctness |
|------|------------:|------------:|------------:|------------:|-----------:|:-----------:|
| legacy  | 0.548 | 0.417 | 0.783 | 0.077 | 488  | True |
| hybrid  | 3.127 | 2.421 | 5.235 | 0.410 | 2786 | True |
| pq-only | 3.112 | 2.529 | 5.579 | 0.436 | 2714 | True |

每条消息字节（含帧头），以及计算开销（mean，ms）：

| mode | ClientHello | GatewayHello | ClientFinished | GatewayFinished | client_compute | gateway_compute |
|------|------------:|-------------:|---------------:|----------------:|---------------:|----------------:|
| legacy  | 110  | 189  | 94 | 95 | 0.181 | 0.188 |
| hybrid  | 1294 | 1303 | 94 | 95 | 2.423 | 1.799 |
| pq-only | 1263 | 1262 | 94 | 95 | 2.109 | 1.544 |

> 关键操作计时（mean，ms，real ML-KEM-768）：客户端 `kem_keygen ≈ 1.09`、`kem_decaps ≈ 1.10`；
> 网关 `kem_encaps ≈ 1.68`；X25519 各操作 ≈ 0.05–0.08；KDF/MAC 均 < 0.07。

**十条分析**：

1. **实验环境**：见 §6.1（程序用 `platform`/`psutil` 自动采集）。
2. **使用的密码原语**：传统 DH = 真实 **X25519**（`cryptography 46.0.3`）；
   后量子 KEM = 真实 **ML-KEM-768**（`quantcrypt`，PQClean）。
3. **平均握手时间**：legacy ≈ 0.55 ms，hybrid ≈ 3.13 ms，pq-only ≈ 3.11 ms。
4. **波动（stdev）**：legacy 0.077、hybrid 0.410、pq-only 0.436 ms；含 PQ 的模式波动更大，
   主要来自 KEM 运算与 OS 调度抖动（max 偶有 ~5 ms 长尾）。
5. **通信字节**：legacy 488 B、hybrid 2786 B、pq-only 2714 B。
6. **密钥一致性**：三种模式 correctness 均为 True（双方 session_key 逐字节相等）。
7. **性能对比**：legacy 时延/字节均最小（仅 X25519，32 B 公钥）；hybrid 与 pq-only 因 ML-KEM
   运算与大公钥/密文显著更重；hybrid 计算略重于 pq-only（多一组 X25519）。
8. **hybrid 相比 legacy 的额外开销**：
   - *计算*：新增 `kem_keygen`（客户端 ≈ 1.09 ms）、`kem_encaps`（网关 ≈ 1.68 ms）、
     `kem_decaps`（客户端 ≈ 1.10 ms），使客户端单侧计算从 ~0.18 ms 升到 ~2.4 ms；
   - *通信*：多 **2298 B**——ML-KEM-768 公钥 1184 B 进 ClientHello、密文 1088 B 进 GatewayHello。
9. **pq-only 与 hybrid 的差异**：pq-only 省去 DH keygen/derive 与 X25519 的 32 B 公钥，
   通信少 72 B、计算略低；**代价是失去“传统+PQ 双保险”**——一旦 ML-KEM 被攻破即无后备。
   这是“时延/字节”与“安全余量”的此消彼长。
10. **结果解释**：含 PQ 的模式报文显著更大，是因为 ML-KEM-768 公钥/密文（1184 B / 1088 B）
    远超 X25519 公钥（32 B）；但**时延反而比之前的 toy KEM 更低**——真实 ML-KEM 是格上多项式
    运算（NTT），比 toy 的 2048-bit 大数模幂更快。这印证了“通信开销是 PQ 迁移的主要成本，
    计算开销其次”的工程判断。

**实验方法学（减少偶然误差的措施）**：
- **多轮取统计**：每模式 ≥ 100 轮（演示用 50），报 mean/median/stdev/min/max/p95；
- **排除冷启动**：丢弃前 `warmup`（默认 10）轮，规避首次导入、JIT/缓存、socket 预热；
- **随机源**：`nonce` 与 DH/KEM 私钥**必须随机**（固定将破坏安全性与密钥唯一性），故时延有
  天然波动，用统计量而非单点刻画；可固定的是算法选择与消息结构（确定性序列化保证字节稳定）；
- **计算与通信分开统计**：计算用 `perf_counter` 逐操作计时、通信用字节计数，二者分列不混用；
- **方向/逐消息拆分**：通信开销按 C→G / G→C 与每条消息分别报告。

### 6.3 实验二：算法协商与兼容性

| case | client_supports | gateway_supports | expected | actual | warn | pass |
|:----:|-----------------|------------------|----------|--------|:----:|:----:|
| 1 | legacy,hybrid,pq-only | legacy,hybrid,pq-only | pq-only/hybrid | pq-only | N | ✅ |
| 2 | legacy,hybrid | legacy,hybrid,pq-only | hybrid | hybrid | N | ✅ |
| 3 | legacy | legacy,hybrid,pq-only | legacy(+warn) | legacy | Y | ✅ |
| 4 | pq-only | legacy | failed | failed | N | ✅ |

结论：
1. 协商出的最终模式**均符合预期**。
2. 只能用 legacy 时（用例 3）**输出了安全警告**（warn=Y）。
3. 双方无共同安全算法时（用例 4）**拒绝连接**（success=False）。
4. 协议**默认优先更高安全等级**：偏好顺序 `pq-only > hybrid > legacy` 生效（用例 1 选中 pq-only）。

---

## 7. 原语声明与可加分项

- **真实库（本交付已启用）**：
  - 传统 DH：真实 **X25519**（`cryptography 46.0.3`）。
  - 后量子 KEM：真实 **ML-KEM-768**（`quantcrypt`，底层 PQClean，FIPS 203；公钥 1184 B / 密文 1088 B / 共享密钥 32 B）。
  - `primitives.py` 通过抽象基类按 `liboqs > quantcrypt > toy` 优先级自动选用首个可用真实后端，
    **切换实现协议代码零改动**。安装 `liboqs-python` 后会自动优先使用 liboqs。
- **toy 原语声明（仅当真实库全部缺失时回退）**：`ToyDH` / `ToyKEM` 仅用于**模拟协议流程**，
  使用固定 MODP 群、未加固，**不具备真实密码学安全性**，绝不可用于生产。代码注释与运行时打印
  均有此声明；可用环境变量 `HPQ_FORCE_TOY=1` 强制回退 toy 以做对照实验。

---

## 8. 已知简化与局限

1. **缺长期身份认证**：无证书/PSK，`gateway_authenticator` 只是密钥确认，**无法抵抗能完整
   冒充网关的主动中间人**（见 §4.4）。真实系统需引入 PKI 或预共享密钥。
2. **缺抗重放机制**：未实现基于时间戳/计数器/服务器状态的重放检测（nonce 仅用于绑定，
   不维护已见 nonce 集合）。任务四中“重放旧 ClientHello/GatewayHello”需额外状态才能完整防护。
3. **签名/身份缺失而非原语缺失**：DH 与 KEM 均已是真实实现（X25519 + ML-KEM-768），
   但协议未引入后量子**签名**（如 ML-DSA）做长期身份认证（见第 1 点）。
4. **未实现群组密钥树（任务五）**：本交付聚焦任务二/三与任务六实验；群组扩展为后续工作。
5. **错误处理简化**：协商失败时网关直接关闭连接，客户端据连接中断判定失败，未定义专门的
   告警/错误消息类型。
6. **单连接顺序模型**：`GatewayServer` 顺序处理连接、结果走队列；未做高并发优化（与本题的
   开销测量目标无关）。
