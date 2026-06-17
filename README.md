# 简化版客户端—网关抗量子迁移握手协议

用 Python 3.10+ 实现的、基于**真实 TCP socket** 的简化版客户端—网关认证密钥协商协议，
支持 `legacy` / `hybrid` / `pq-only` 三种模式，含算法协商、降级保护、传输文本绑定、
会话密钥派生与内置开销测量。

## 环境与依赖

- Python 3.10+（开发与测试用 3.13）。
- 传统 DH：真实 **X25519**（来自 `cryptography`，若缺失自动回退 toy DH）。
- 后量子 KEM：真实 **ML-KEM-768**，多后端自动探测，优先级 `liboqs(oqs) > quantcrypt > toy`
  （三者皆缺失才回退 toy KEM）。
- 可选 `psutil`（仅用于在实验报告中打印内存大小）。

安装：

```bash
pip install cryptography      # 真实 X25519
pip install quantcrypt        # 真实 ML-KEM-768（PQClean，带预编译 wheel，Windows）
# 或： pip install liboqs-python   # 真实 ML-KEM（liboqs，优先级更高，但 Windows 需自行编译/部署 liboqs）
pip install psutil            # 可选，打印内存信息
```

> 本仓库默认环境已安装 `cryptography` + `quantcrypt`，运行时打印
> `DH=x25519(real)  KEM=ml-kem-768(quantcrypt)(real)`。

> 运行时会打印当前实际使用的是真实库还是 toy 原语。**toy 原语仅用于模拟协议流程，不具备真实密码学安全性。**
> 设置环境变量 `HPQ_FORCE_TOY=1` 可强制全部使用 toy 原语（便于对照实验）。

## 运行方式

```bash
# 1) 双终端演示
python main.py gateway --host 127.0.0.1 --port 9000
python main.py client --host 127.0.0.1 --port 9000 --mode hybrid

# 2) 基准测试（本进程内拉起网关线程，跑 N 次）
python main.py bench --mode all --iterations 100

# 3) 任务六全部实验（性能/正确性 + 协商兼容性 + 降级攻击检测）
python main.py experiment --iterations 100

# 4) 任务四：中间人降级攻击模拟与检测
python main.py attack

# 5) 任务五：动态群组密钥迁移（LKH 树）实验
python main.py group

# 6) 创新扩展：pq-auth 后量子身份认证，冒充网关前后对比
python main.py auth
```

`client` 子命令参数：
- `--mode {auto,legacy,hybrid,pq-only}`：客户端**请求**的模式。`auto` 时按 `--algs` 公布支持集，由网关按偏好选最高；指定具体模式时仅公布该模式（fail-closed 冲突策略）。
- `--algs`：`auto` 模式下客户端支持集，如 `legacy,hybrid` 或 `all`。

`gateway` 子命令的 `--algs` 控制网关支持的模式集（用于兼容性测试）。

### 结果自动保存

`client` / `bench` / `experiment` 三个命令**每次运行都会自动**把完整输出（含开销表）
原样存一份到 `results/` 目录下**带时间戳的新 txt 文件**（精确到毫秒，**绝不覆盖**历史结果），
例如 `results/experiment_20260615_211927_439.txt`。终端照常实时显示，文件是同步副本。
`gateway` 为常驻服务端，不产出一次性开销报告，故不存档（每次握手结果实时打印在终端）。

## 文件结构

```text
primitives.py     DH / KEM / 签名 抽象基类 + 真实实现（X25519 / ML-KEM-768 / ML-DSA-65）+ toy 回退
crypto_utils.py   HKDF-SHA256、HMAC-SHA256、Transcript、确定性序列化读写器
messages.py       四种握手消息 dataclass + 确定性序列化/反序列化
wire.py           4 字节大端长度前缀分帧；send_msg/recv_msg；字节统计
negotiation.py    模式与算法协商、降级保护策略
protocol.py       Client/Gateway 状态机；GatewayServer；run_handshake()
attacker.py       任务四：中间人 socket 代理 + 降级攻击套件 + 纵深防御对比 + 冒充网关/pq-auth 对比
group.py          任务五：对称 LKH 群组密钥树 + 动态迁移开销实验
metrics.py        Metrics 数据结构、计时器、统计量（mean/median/stdev/min/max/p95）
experiment.py     任务六实验（性能/正确性 + 协商兼容性 + 降级攻击 + 群组迁移）
main.py           子命令 gateway/client/bench/experiment/attack/group 入口
tests.py          单元测试
REPORT.md         设计与实验报告
```

## 握手流程

```text
Client                                   Gateway
  | ---------- ClientHello ------------->  |
  | <--------- GatewayHello ------------   |   (含 selected_mode / 降级保护字段 / authenticator)
  | --------- ClientFinished ----------->  |
  | <-------- GatewayFinished -----------  |
共 4 条消息、2 个往返(RTT)
```

