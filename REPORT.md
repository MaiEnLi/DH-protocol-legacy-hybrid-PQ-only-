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

### 6.4 实验三：降级攻击检测（任务四，选做）

本实验用 `attacker.py` 实现的**真实中间人 socket 代理**（坐在 Client 与真实 Gateway 之间，
在线篡改/重放握手帧）检验降级防护。判定口径：客户端握手未成功（success=False）即视为攻击**被检测到**。
命令：`python main.py attack`。

| attack_type | detected | 检测依据（首先触发） |
|-------------|:--------:|----------------------|
| remove_pq_only            | true | downgrade_protection_field |
| remove_hybrid             | true | downgrade_protection_field |
| force_legacy              | true | downgrade_protection_field |
| replace_downgrade_field   | true | downgrade_protection_field |
| replay_old_client_hello   | true | downgrade_protection_field |
| replay_old_gateway_hello（扩展） | true | downgrade_protection_field |

> 无篡改基线（代理透传）握手 success=True，说明代理透明、**无误报**。

**1）哪些攻击被检测到**：题目要求的五种 + 扩展的“重放旧 GatewayHello”，**全部检出**（detected 全为 true）。

**2）检测依据**：本协议有三道相互独立的防线——
(i) `downgrade_protection_field`（对客户端原始算法列表的 MAC）；
(ii) `transcript hash`（双方传输文本视图须一致）；
(iii) `Finished MAC`（密钥确认）。
客户端收到 GatewayHello 后*最先*做降级保护校验，故六种攻击都在该处首先触发失败。
究其根因：篡改算法列表使双方该字段不符；篡改 `selected_mode` 或重放使双方共享密钥/`ikm` 不同，
导致 `early_key` 不同、降级字段对不上。

为**实证三道防线相互独立**，做了**纵深防御对比实验**（`run_defense_in_depth`）：
人为关闭“降级字段 + 认证符”这一层后，仅凭 `transcript hash` / `Finished MAC` **仍然全部检出**：

| attack_type | 完整防护 | 仅 transcript/Finished |
|-------------|:--------:|:----------------------:|
| remove_pq_only / remove_hybrid / force_legacy | true | true |
| replace_downgrade_field | true | true |
| replay_old_client_hello / replay_old_gateway_hello | true | true |

这说明：即便降级保护字段被绕过，传输文本绑定与 Finished MAC 仍能兜底——**两层防护互为冗余**。

**3）未检出的攻击与改进**：本实验中**无未检出项**。但需诚实指出防护边界（见 §8）：
上述检测成立的前提是**攻击者不知道握手共享密钥**。若攻击者能**完整冒充网关**、
与客户端独立跑完 DH/KEM（从而掌握共享密钥），则它可伪造一致的降级字段与 Finished MAC，
本协议**无法**抵抗——根因是缺少**长期身份认证**。改进方案：为网关引入长期密钥，
用后量子签名（如 ML-DSA / Dilithium）对 GatewayHello 与 transcript 签名，把
`gateway_authenticator` 从“密钥确认”升级为“身份认证”，即可抵抗主动冒充。

### 6.5 实验四：动态群组密钥迁移（任务五，选做）

**设计取舍**：Gateway 是可信 KDC（已与每个成员通过任务二握手得到 pairwise session key），
故采用**对称密钥树（LKH，Logical Key Hierarchy）**而非公钥树（TreeKEM）。
对称树的意义在于把成员变更时的 rekey 广播从 O(n) 降到 **O(log n)**，而非“让服务器不知道群钥”——
KDC 本就知道全部密钥。公钥树是为“没有可信中心”的场景（如端到端群聊）设计的，本题不需要。
模型：堆式二叉树，叶子密钥 `leaf_key = HKDF(session_key, epoch, "leaf")`，
内部节点持随机 KEK，`group_key = 根密钥`；**成员离开时对其到根路径上的节点重新随机化**，
保证离开者无法用旧密钥算出新 group_key（前向安全）。命令：`python main.py group`。

测量（n = 8/16/32/64，每个 (n, mode) 各测 group_init / member_join / member_leave；
group_init 时间含 n 次握手、member_join 含 1 次新成员握手、member_leave 为纯对称操作）：

| n | mode | operation | time_ms | updated_nodes | broadcast_msgs | correct |
|---|------|-----------|--------:|--------------:|---------------:|:-------:|
| 8  | hybrid | group_init   |  72.2 | 7  | 14  | True |
| 8  | hybrid | member_join  |   5.3 | 4  | 5   | True |
| 8  | hybrid | member_leave |  0.01 | 3  | 5   | True |
| 16 | hybrid | group_init   |  79.7 | 15 | 30  | True |
| 16 | hybrid | member_join  |   5.1 | 5  | 6   | True |
| 16 | hybrid | member_leave |  0.02 | 4  | 7   | True |
| 32 | hybrid | group_init   | 157.9 | 31 | 62  | True |
| 32 | hybrid | member_join  |   5.1 | 6  | 7   | True |
| 32 | hybrid | member_leave |  0.05 | 5  | 9   | True |
| 64 | hybrid | group_init   | 312.1 | 63 | 126 | True |
| 64 | hybrid | member_join  |   5.4 | 7  | 8   | True |
| 64 | hybrid | member_leave |  0.11 | 6  | 11  | True |

> 完整三模式表见 `python main.py group` 输出 / `results/` 存档；上表取 hybrid 行示意。
> legacy 的 group_init 显著更快（n=64 约 66 ms vs hybrid 312 ms），因其每个成员只做一次 X25519 握手。

**分析（对应任务六 6.4 各条）**：
1. **群组初始化时间**：随 n 线性增长（主导项是 n 次 pairwise 握手），且随模式变化
   （hybrid/pq-only 因 ML-KEM 明显高于 legacy）。
2. **成员加入更新时间**：约 1 次握手量级（含新成员握手），树操作本身可忽略。
3. **成员离开更新时间**：纯对称操作，亚毫秒级，与模式无关。
4. **更新节点数**：group_init = n−1（线性 7/15/31/63）；member_leave = log₂n（3/4/5/6）；
   member_join = log₂(2n)（4/5/6/7）。
5. **广播消息数**：group_init = 2(n−1)（14/30/62/126，线性）；member_leave = 2·log₂n−1（5/7/9/11，对数）。
6. **group_key 一致性**：所有合法成员均算出相同 group_key（correct 全 True）。
7. **离开成员无法计算新 group_key**：leave 后对被逐成员做 `member_cannot_compute` 校验，全部为真（前向安全成立）。
8. **对数级增长**：member_join / member_leave 的更新节点数与广播消息数随 n 呈 **O(log n)**，
   而 group_init 呈 O(n)——印证二叉密钥树把 rekey 开销从线性降到对数，这正是用树（而非“直接逐个分发”）的意义。

### 6.6 创新扩展：后量子身份认证（pq-auth，挡住冒充网关）

§4.4 与 §8 指出本协议最大短板：无长期身份，`gateway_authenticator` 仅为密钥确认，
**挡不住完整冒充网关的主动中间人**。为闭环该缺口，新增可选的 **pq-auth** 模式：
给网关一个长期 **ML-DSA-65（Dilithium3，FIPS 204）** 签名密钥对，网关用长期私钥对
`(ClientHello ∥ GatewayHello)` 签名（写入 `gateway_authenticator`），客户端用**预置（pinned）的
网关公钥**验证——把"密钥确认"升级为"身份认证"。命令：`python main.py auth`。

威胁模型：主动攻击者完整冒充网关，自己与客户端跑完 DH/KEM、从而掌握会话密钥。前后对比：

| scenario | gateway_auth | client_success | impersonation_detected |
|----------|--------------|:--------------:|:----------------------:|
| no auth (current protocol) | MAC（密钥确认） | True  | NO（vulnerable）|
| pq-auth (ML-DSA signature) | ML-DSA 签名     | False | YES（secure）|

> 无认证时客户端无法分辨真假网关，冒充得逞（success=True）；引入 pq-auth 后，攻击者无网关长期私钥、
> 签名验不过，握手中止（success=False），冒充被挡。正常对照（真网关 + pq-auth）握手成功，
> 说明认证未破坏合法连接。

**迁移成本**（ML-DSA-65）：网关签名约 1.3–2.7 ms、客户端验签约 0.6–0.8 ms；
GatewayHello 由 1303 B 增至约 4580 B（**+约 3.3 KB**，即一枚 ML-DSA 签名 3309 B）。
这正体现"抗量子迁移"中身份认证一环的代价：后量子签名比经典签名（Ed25519 64 B）大一到两个数量级，
是 PQ 迁移通信开销的又一主要来源。

**说明**：pq-auth 与 legacy/hybrid/pq-only 的密钥协商正交——它认证的是"网关是谁"，
而非"用哪种 KEX"。`primitives.py` 以 `SignatureScheme` 抽象，按 `ML-DSA(quantcrypt) > Ed25519(经典回退)`
自动选用；signing 用真实 ML-DSA。

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

1. **长期身份认证（已由可选 pq-auth 部分闭环）**：默认模式下 `gateway_authenticator` 只是密钥确认，
   无法抵抗完整冒充网关的主动中间人（见 §4.4）。§6.6 新增的 pq-auth 模式用 ML-DSA 长期签名挡住了该攻击；
   但仍依赖"客户端预置网关公钥（pinning）"这一信任锚，未实现完整 PKI / 证书链 / 吊销，也未对客户端做认证（单向认证）。
2. **重放检测靠密钥新鲜性、而非专门的抗重放状态**：实验 §6.4 中重放旧 ClientHello/GatewayHello
   均被检出，但其根因是每次握手 nonce 与 DH/KEM 临时密钥都新鲜，重放导致双方密钥不一致而失败；
   协议本身未维护“已见 nonce 集合”或时间戳窗口。若需在更复杂场景（如带长期密钥的会话恢复）下
   防重放，仍需引入显式的计数器/时间戳/服务器状态。
3. **签名/身份缺失而非原语缺失**：DH 与 KEM 均已是真实实现（X25519 + ML-KEM-768），
   但协议未引入后量子**签名**（如 ML-DSA）做长期身份认证（见第 1 点）。这也是 §6.4 指出的
   降级防护边界——能抵抗篡改协商，但不能抵抗完整冒充网关的主动攻击。
4. **群组密钥树为对称 LKH 简化模型（任务五）**：采用可信 KDC + 对称密钥树，已实现一致性与
   离开前向安全（路径重随机化），并验证 O(log n) rekey 开销。但未做：成员加入时的后向安全严格化、
   树的再平衡、并发成员变更、以及 TreeKEM 式的去中心化/抗泄露恢复（PCS）——这些属于更复杂的群组协议范畴。
5. **错误处理简化**：协商失败时网关直接关闭连接，客户端据连接中断判定失败，未定义专门的
   告警/错误消息类型。
6. **单连接顺序模型**：`GatewayServer` 顺序处理连接、结果走队列；未做高并发优化（与本题的
   开销测量目标无关）。
