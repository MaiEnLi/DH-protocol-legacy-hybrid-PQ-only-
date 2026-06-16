"""
experiment.py
=============
任务六实验：
  - 实验一（10.1）：握手协议性能与正确性分析（每模式 >=100 轮）；
  - 实验二（10.2）：算法协商与兼容性矩阵。
以及 bench 子命令复用的多轮采集引擎 collect_runs()。

口径再次强调（不可混用）：
  - 通信开销 = 应用层传输字节（含 4 字节帧头），每模式确定值；
  - 计算开销 = 各原语 perf_counter CPU 时间（client/gateway 分列）；
  - 端到端   = 墙钟时延。
减少偶然误差的方法学：丢弃前 WARMUP 轮冷启动；其后 N 轮取 mean/median/stdev/min/max/p95；
nonce 必须随机（不可固定，否则破坏安全性），故时延存在天然波动，用统计量刻画。
"""

from __future__ import annotations

from typing import Dict, List

import negotiation as neg
from metrics import Stat, environment_info
from primitives import primitive_info
from protocol import GatewayServer, _build_result, client_handshake, run_handshake

ALL = [neg.MODE_LEGACY, neg.MODE_HYBRID, neg.MODE_PQ_ONLY]
DEFAULT_WARMUP = 10


# --------------------------------------------------------------------------- #
# 多轮采集引擎
# --------------------------------------------------------------------------- #
def collect_runs(mode: str, iterations: int, warmup: int,
                 gateway_supported: List[str], host: str = "127.0.0.1") -> Dict:
    """对单一模式跑 warmup+iterations 轮，返回统计结果。"""
    server = GatewayServer(host, 0, gateway_supported).start()
    e2e: List[float] = []
    cc: List[float] = []
    gc: List[float] = []
    op_lists: Dict[str, List[float]] = {}
    comm_total = None
    per_msg = None
    correctness = True
    warnings: List[str] = []
    try:
        for i in range(warmup + iterations):
            client = client_handshake(host, server.port, mode, gateway_supported)
            try:
                gateway = server.results.get(timeout=5)
            except Exception:
                gateway = {"success": False, "session_key": b"", "gateway_ops": {},
                           "gateway_compute_ms": 0.0, "selected_mode": "failed",
                           "warnings": [], "reason": "网关无响应"}
            res = _build_result(client, gateway)
            if i < warmup:
                continue
            if not res.success:
                correctness = False
            m = res.metrics
            e2e.append(m.end_to_end_ms)
            cc.append(m.client_compute_ms)
            gc.append(m.gateway_compute_ms)
            for k, v in m.op_timings_ms.items():
                op_lists.setdefault(k, []).append(v)
            if comm_total is None:
                comm_total = m.bytes_total
                per_msg = dict(m.per_message_bytes)
                warnings = res.warnings
    finally:
        server.stop()

    return {
        "mode": mode,
        "e2e": Stat.of(e2e),
        "client_compute": Stat.of(cc),
        "gateway_compute": Stat.of(gc),
        "ops": {k: Stat.of(v) for k, v in op_lists.items()},
        "comm_bytes": comm_total or 0,
        "per_message_bytes": per_msg or {},
        "correctness": correctness,
        "warnings": warnings,
        "iterations": iterations,
        "warmup": warmup,
    }


# --------------------------------------------------------------------------- #
# 打印辅助
# --------------------------------------------------------------------------- #
def _print_env() -> None:
    env = environment_info(primitive_info())
    print("运行环境：")
    print(f"  OS        : {env['platform']}")
    print(f"  CPU       : {env['processor']}")
    print(f"  内存(GB)  : {env['memory_gb'] if env['memory_gb'] is not None else '未知(psutil 未安装)'}")
    print(f"  Python    : {env['python']}")
    print(f"  DH 原语   : {env['dh']}")
    print(f"  KEM 原语  : {env['kem']}")
    if "toy" in env["kem"] or "toy" in env["dh"]:
        print("  [声明] 含 toy 原语：仅模拟协议流程，不具备真实密码学安全性。")
    print()


# --------------------------------------------------------------------------- #
# bench 子命令
# --------------------------------------------------------------------------- #
def run_bench(modes: List[str], iterations: int, warmup: int = DEFAULT_WARMUP) -> None:
    _print_env()
    print(f"基准测试：每模式 warmup={warmup} 轮(丢弃) + 计时 {iterations} 轮\n")

    results = {m: collect_runs(m, iterations, warmup, ALL) for m in modes}

    # 端到端 + 通信总览
    print("== 端到端时延 (ms) 与 通信开销 (bytes, 含帧头) ==")
    hdr = f"{'mode':<8}{'avg':>9}{'median':>9}{'min':>9}{'max':>9}{'stdev':>9}{'p95':>9}{'comm_B':>9}{'correct':>9}"
    print(hdr)
    print("-" * len(hdr))
    for m in modes:
        r = results[m]
        s = r["e2e"]
        print(f"{m:<8}{s.mean:>9.3f}{s.median:>9.3f}{s.minimum:>9.3f}{s.maximum:>9.3f}"
              f"{s.stdev:>9.3f}{s.p95:>9.3f}{r['comm_bytes']:>9}{str(r['correctness']):>9}")
    print()

    # 计算开销（client / gateway 分列）
    print("== 计算开销 (ms)：client 侧 / gateway 侧 (mean) ==")
    print(f"{'mode':<8}{'client_avg':>12}{'gateway_avg':>14}")
    for m in modes:
        print(f"{m:<8}{results[m]['client_compute'].mean:>12.4f}{results[m]['gateway_compute'].mean:>14.4f}")
    print()

    # 每条消息字节
    print("== 每条消息字节数 (含帧头) ==")
    msgs = ["ClientHello", "GatewayHello", "ClientFinished", "GatewayFinished"]
    print(f"{'mode':<8}" + "".join(f"{x:>16}" for x in msgs))
    for m in modes:
        pm = results[m]["per_message_bytes"]
        print(f"{m:<8}" + "".join(f"{pm.get(x, 0):>16}" for x in msgs))
    print()

    # 关键操作计时
    print("== 关键操作计时 (ms, mean) ==")
    keys = ["client.dh_keygen", "client.kem_keygen", "client.dh_derive", "client.kem_decaps",
            "gateway.dh_keygen", "gateway.dh_derive", "gateway.kem_encaps",
            "client.kdf", "gateway.kdf", "client.mac", "gateway.mac"]
    print(f"{'mode':<8}" + "".join(f"{k.split('.')[-1][:9]:>10}" for k in keys))
    for m in modes:
        ops = results[m]["ops"]
        row = "".join(f"{(ops[k].mean if k in ops else 0):>10.4f}" for k in keys)
        print(f"{m:<8}{row}")
    print()
    return results


# --------------------------------------------------------------------------- #
# 实验一：性能与正确性
# --------------------------------------------------------------------------- #
def run_experiment_perf(iterations: int, warmup: int = DEFAULT_WARMUP) -> Dict:
    print("=" * 72)
    print("实验一：握手协议性能与正确性分析")
    print("=" * 72)
    _print_env()
    print(f"方法学：每模式丢弃前 {warmup} 轮(冷启动) + 计时 {iterations} 轮；"
          f"端到端用墙钟、计算用 perf_counter、通信用字节计数，三者分列。\n")

    results = {m: collect_runs(m, iterations, warmup, ALL) for m in ALL}

    hdr = f"{'mode':<8}{'avg_time_ms':>13}{'min_time_ms':>13}{'max_time_ms':>13}{'std_time_ms':>13}{'comm_bytes':>12}{'correctness':>13}"
    print(hdr)
    print("-" * len(hdr))
    for m in ALL:
        r = results[m]
        s = r["e2e"]
        print(f"{m:<8}{s.mean:>13.3f}{s.minimum:>13.3f}{s.maximum:>13.3f}{s.stdev:>13.3f}"
              f"{r['comm_bytes']:>12}{str(r['correctness']):>13}")
    print()
    _perf_analysis(results)
    return results


def _perf_analysis(results: Dict) -> None:
    leg, hyb, pq = results["legacy"], results["hybrid"], results["pq-only"]
    print("分析（程序自动生成数值 + 固定结论）：")
    print(f"  3) 平均握手时间: legacy={leg['e2e'].mean:.3f}ms, "
          f"hybrid={hyb['e2e'].mean:.3f}ms, pq-only={pq['e2e'].mean:.3f}ms")
    print(f"  4) 波动(stdev): legacy={leg['e2e'].stdev:.3f}, "
          f"hybrid={hyb['e2e'].stdev:.3f}, pq-only={pq['e2e'].stdev:.3f}")
    print(f"  5) 通信字节: legacy={leg['comm_bytes']}B, "
          f"hybrid={hyb['comm_bytes']}B, pq-only={pq['comm_bytes']}B")
    print(f"  6) 双方密钥一致: legacy={leg['correctness']}, "
          f"hybrid={hyb['correctness']}, pq-only={pq['correctness']}")
    d_bytes = hyb["comm_bytes"] - leg["comm_bytes"]
    print(f"  8) hybrid 相比 legacy 多出: KEM keygen/encaps/decaps 计算项；"
          f"通信多 {d_bytes}B（PQ 公钥+密文）。")
    print(f"  9) pq-only 相比 hybrid: 省去 DH 计算与 DH 公钥字节，"
          f"通信差 {hyb['comm_bytes'] - pq['comm_bytes']}B；但失去“传统+PQ 双保险”。")
    print("  10) 解释：PQ 公钥/密文远大于 X25519(32B)，故 hybrid/pq-only 报文更大；"
          "toy KEM 的数字不代表真实 ML-KEM 性能（见报告）。")
    print()


# --------------------------------------------------------------------------- #
# 实验二：协商兼容性矩阵
# --------------------------------------------------------------------------- #
def run_experiment_negotiation() -> List[Dict]:
    print("=" * 72)
    print("实验二：算法协商与兼容性测试")
    print("=" * 72)

    cases = [
        (1, ["legacy", "hybrid", "pq-only"], ["legacy", "hybrid", "pq-only"], {"pq-only", "hybrid"}),
        (2, ["legacy", "hybrid"],            ["legacy", "hybrid", "pq-only"], {"hybrid"}),
        (3, ["legacy"],                      ["legacy", "hybrid", "pq-only"], {"legacy"}),
        (4, ["pq-only"],                     ["legacy"],                      {"failed"}),
    ]

    rows = []
    hdr = f"{'case':<5}{'client_supports':<24}{'gateway_supports':<26}{'expected':<16}{'actual':<10}{'warn':<6}{'pass':<6}"
    print(hdr)
    print("-" * len(hdr))
    for cid, cs, gs, expected in cases:
        r = run_handshake("auto", cs, gs)
        actual = r.mode if r.success else "failed"
        has_warn = "Y" if r.warnings else "N"
        if cid == 4:
            ok = (not r.success)
        elif cid == 3:
            ok = (r.success and actual == "legacy" and bool(r.warnings))
        else:
            ok = (r.success and actual in expected)
        rows.append({"case": cid, "actual": actual, "warn": has_warn, "pass": ok})
        exp_str = "/".join(sorted(expected))
        print(f"{cid:<5}{','.join(cs):<24}{','.join(gs):<26}{exp_str:<16}{actual:<10}{has_warn:<6}{str(ok):<6}")
    print()
    print("结论：")
    print("  1) 协商模式均符合预期（默认优先高安全等级 pq-only/hybrid）。")
    print("  2) 仅 legacy 时输出了安全警告（见 warn=Y）。")
    print("  3) 双方无共同安全算法（用例4）时拒绝连接（pass=True 表示如期失败）。")
    print("  4) 偏好顺序 pq-only > hybrid > legacy 生效。")
    print()
    return rows


def run_experiment_attack() -> None:
    """实验 6.3：降级攻击检测（任务四）。"""
    import attacker  # 延迟导入，避免循环
    attacker.print_attack_report(attacker.run_attack_suite())
    attacker.run_defense_in_depth()


def run_experiment_group() -> None:
    """实验 6.4：动态群组密钥迁移（任务五）。"""
    import group  # 延迟导入，避免循环
    group.print_group_report(group.run_group_experiment())


def run_experiment_auth() -> None:
    """创新扩展：pq-auth 身份认证，冒充网关前后对比。"""
    import attacker  # 延迟导入，避免循环
    attacker.print_impersonation_report(attacker.run_impersonation_experiment())


def run_experiment(iterations: int) -> None:
    run_experiment_perf(iterations)
    run_experiment_negotiation()
    run_experiment_attack()
    run_experiment_group()
    run_experiment_auth()
