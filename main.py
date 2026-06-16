"""
main.py
=======
子命令入口：

  python main.py gateway --host 127.0.0.1 --port 9000
      启动网关（TCP 服务端，循环 accept，可处理多次连接）。

  python main.py client --host 127.0.0.1 --port 9000 --mode hybrid
      启动客户端，连接网关完成一次握手并打印结果。

  python main.py bench --mode all --iterations 100
      基准测试：本进程内把网关作为后台线程拉起，客户端连 127.0.0.1 跑 N 次。

  python main.py experiment [--iterations 100]
      运行任务六全部实验（性能/正确性 + 协商兼容性），自动产出表格与结论。
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import os
import sys

import negotiation as neg
from primitives import primitive_info
from protocol import GatewayServer, client_handshake

ALL = [neg.MODE_LEGACY, neg.MODE_HYBRID, neg.MODE_PQ_ONLY]

# 结果自动保存目录（与本文件同级的 results/）
RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")


class _Tee:
    """把写入分流到多个流（终端 + 文件），从而“边打印边存档”。"""

    def __init__(self, *streams) -> None:
        self._streams = streams

    def write(self, data: str) -> int:
        for s in self._streams:
            s.write(data)
        return len(data)

    def flush(self) -> None:
        for s in self._streams:
            s.flush()


@contextlib.contextmanager
def _save_output(prefix: str):
    """
    上下文管理器：把期间所有 stdout 输出**原样**复制一份到带时间戳的新 txt 文件。
    每次调用都生成**唯一新文件**（精确到毫秒）。
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]  # 到毫秒，防同秒冲突
    path = os.path.join(RESULTS_DIR, f"{prefix}_{ts}.txt")
    f = open(path, "w", encoding="utf-8")
    old_stdout = sys.stdout
    sys.stdout = _Tee(old_stdout, f)
    try:
        print(f"# {prefix} 运行结果")
        print(f"# 生成时间: {datetime.datetime.now().isoformat(timespec='seconds')}")
        print("=" * 72)
        yield path
    finally:
        sys.stdout = old_stdout      # 先恢复，下面这行只在终端提示、不写进文件
        f.flush()
        f.close()
        print(f"\n[已保存] 本次开销结果 -> {path}")


def _print_primitives() -> None:
    info = primitive_info()
    print(f"[原语] DH={info['dh_name']}({'real' if info['dh_is_real'] else 'toy'})  "
          f"KEM={info['kem_name']}({'real' if info['kem_is_real'] else 'toy'})")
    if not (info["dh_is_real"] and info["kem_is_real"]):
        print("[声明] 含 toy 原语：仅模拟协议流程，不具备真实密码学安全性。")


def _parse_algs(s: str) -> list:
    if s == "all":
        return list(ALL)
    return [x.strip() for x in s.split(",") if x.strip()]


def cmd_gateway(args: argparse.Namespace) -> None:
    _print_primitives()
    supported = _parse_algs(args.algs)
    server = GatewayServer(args.host, args.port, supported).start()
    print(f"[网关] 监听 {server.host}:{server.port}  支持模式={supported}")
    print("[网关] 等待客户端连接（Ctrl+C 退出）……")
    try:
        while True:
            res = server.results.get()
            tag = "OK" if res.get("success") else "FAIL"
            print(f"[网关] 握手 {tag}  mode={res.get('selected_mode')}  "
                  f"compute={res.get('gateway_compute_ms', 0):.3f}ms  "
                  f"warn={res.get('warnings')}  reason={res.get('reason','')}", flush=True)
    except KeyboardInterrupt:
        print("\n[网关] 退出。")
    finally:
        server.stop()


def cmd_client(args: argparse.Namespace) -> None:
    with _save_output("client"):
        _cmd_client_impl(args)


def _cmd_client_impl(args: argparse.Namespace) -> None:
    _print_primitives()
    supported = _parse_algs(args.algs)
    res = client_handshake(args.host, args.port, args.mode, supported)
    print(f"[客户端] 请求模式 = {args.mode}")
    print(f"  success        : {res['success']}")
    print(f"  selected_mode  : {res['selected_mode']}")
    sk = res["session_key"]
    print(f"  session_key[:8]: {sk[:8].hex() if sk else '(无)'}")
    print(f"  time_ms        : {res['end_to_end_ms']:.3f}")
    print(f"  client_compute : {res['client_compute_ms']:.3f} ms")
    print(f"  comm_bytes     : c2g={res['bytes_c2g']} g2c={res['bytes_g2c']} "
          f"total={res['bytes_c2g'] + res['bytes_g2c']}")
    print(f"  warnings       : {res['warnings']}")
    if not res["success"]:
        print(f"  reason         : {res['reason']}")
        return

    # --- 单次握手的开销分解（仅客户端可见的部分；网关计算在另一进程，故不含）---
    print("\n  -- 通信开销：每条消息字节数 (含帧头) --")
    pm = res.get("per_message_bytes", {})
    for name in ("ClientHello", "GatewayHello", "ClientFinished", "GatewayFinished"):
        print(f"     {name:<16}: {pm.get(name, 0)}")
    print(f"     {'合计':<16}: {res['bytes_c2g'] + res['bytes_g2c']}  "
          f"(C->G={res['bytes_c2g']}, G->C={res['bytes_g2c']})")

    print("\n  -- 计算开销：客户端各操作耗时 (ms) --")
    ops = res.get("client_ops", {})
    for k in ("dh_keygen", "kem_keygen", "dh_derive", "kem_decaps",
              "kdf", "mac", "transcript_hash", "serialize", "deserialize"):
        if k in ops:
            print(f"     {k:<16}: {ops[k]:.4f}")
    print(f"     {'client_compute':<16}: {res['client_compute_ms']:.4f}  (以上各项之和)")


def cmd_bench(args: argparse.Namespace) -> None:
    import experiment  # 延迟导入，避免循环
    modes = ALL if args.mode == "all" else [args.mode]
    with _save_output("bench"):
        experiment.run_bench(modes, args.iterations, warmup=args.warmup)


def cmd_experiment(args: argparse.Namespace) -> None:
    import experiment
    with _save_output("experiment"):
        experiment.run_experiment(args.iterations)


def cmd_attack(args: argparse.Namespace) -> None:
    import attacker
    with _save_output("attack"):
        _print_primitives()
        print()
        attacker.print_attack_report(attacker.run_attack_suite())
        attacker.run_defense_in_depth()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="简化版客户端—网关抗量子迁移握手协议")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gateway", help="启动网关 TCP 服务端")
    g.add_argument("--host", default="127.0.0.1")
    g.add_argument("--port", type=int, default=9000)
    g.add_argument("--algs", default="all", help="网关支持模式，逗号分隔或 all")
    g.set_defaults(func=cmd_gateway)

    c = sub.add_parser("client", help="启动客户端发起一次握手")
    c.add_argument("--host", default="127.0.0.1")
    c.add_argument("--port", type=int, default=9000)
    c.add_argument("--mode", default="auto",
                   choices=["auto", "legacy", "hybrid", "pq-only"])
    c.add_argument("--algs", default="all", help="auto 模式下客户端支持集，逗号分隔或 all")
    c.set_defaults(func=cmd_client)

    b = sub.add_parser("bench", help="基准测试")
    b.add_argument("--mode", default="all",
                   choices=["all", "legacy", "hybrid", "pq-only"])
    b.add_argument("--iterations", type=int, default=100)
    b.add_argument("--warmup", type=int, default=10)
    b.set_defaults(func=cmd_bench)

    e = sub.add_parser("experiment", help="运行任务六全部实验")
    e.add_argument("--iterations", type=int, default=100)
    e.set_defaults(func=cmd_experiment)

    a = sub.add_parser("attack", help="任务四：中间人降级攻击模拟与检测")
    a.set_defaults(func=cmd_attack)

    return p


def main(argv=None) -> int:
    # Windows 控制台中文输出保护：尽量切到 UTF-8
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
