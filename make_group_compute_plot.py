"""
make_group_compute_plot.py
==========================
群组操作的“计算开销”图：每次操作执行的密码运算次数（= 节点密钥生成 + 对称加密分发
+ 叶子 KDF）。这是与实现无关的计算开销度量；其值由 group.LKHTree 现算得到。

  - group_init  : 约 4n-3          -> O(n)
  - member_join : 约 3*log2(2n)    -> O(log n)
  - member_leave: 约 3*log2(n)-1   -> O(log n)

同时实测纯密码运算的墙钟时间（不含为正确性校验而做的 O(n) 视图簿记）。
运行： python make_group_compute_plot.py  ->  group_compute.png
"""

from __future__ import annotations

import math
import secrets
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from crypto_utils import hkdf_sha256
from group import LKHTree

NS = [8, 16, 32, 64, 128, 256, 512, 1024]


def crypto_ops():
    """每种操作的密码运算次数（key-gen + 加密分发 + 叶子 KDF），由实跑结构量推得。"""
    init_ops, join_ops, leave_ops = [], [], []
    for n in NS:
        keys = [secrets.token_bytes(32) for _ in range(n)]
        t = LKHTree(n)
        iu, im = t.build(keys)                  # 实跑：iu=keygen 数, im=加密分发数
        init_ops.append(iu + im + n)            # + n 个叶子 KDF
        lt = LKHTree(n); lt.build(keys)
        lu, lm, _ = lt.leave(0)
        leave_ops.append(lu + lm)
        jt = LKHTree(2 * n); jt.build(keys)
        ju, jm = jt.join(n, secrets.token_bytes(32), n)
        join_ops.append(ju + jm + 1)            # + 1 个新叶子 KDF
    return init_ops, join_ops, leave_ops


def measure_time():
    """实测纯密码运算的墙钟（只做 leave 路径上的 keygen + 一次 hash 模拟加密），repeats 取均值。"""
    leave_us = []
    REP = 200
    for n in NS:
        depth = int(math.log2(n))
        t0 = time.perf_counter()
        for _ in range(REP):
            acc = b""
            for _ in range(depth):                       # log2(n) 个新节点密钥
                k = secrets.token_bytes(32)               # key 生成
                acc = hkdf_sha256(k, b"", b"enc", 32)     # 一次派生模拟加密分发
        leave_us.append((time.perf_counter() - t0) / REP * 1e6)  # 微秒
    return leave_us


def main():
    init_ops, join_ops, leave_ops = crypto_ops()
    leave_us = measure_time()

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.8))

    # 左：每操作密码运算次数（init O(n) vs join/leave O(log n)），线性 x 看对比
    ax1.plot(NS, init_ops, "D-", color="tab:red", label="group_init   [O(n)]")
    ax1.plot(NS, join_ops, "s-", color="tab:orange", label="member_join  [O(log n)]")
    ax1.plot(NS, leave_ops, "o-", color="tab:blue", label="member_leave [O(log n)]")
    ax1.set_xlabel("group size n")
    ax1.set_ylabel("crypto operations per op")
    ax1.set_title("Computation overhead: crypto ops per operation")
    ax1.grid(True, alpha=0.3)
    ax1.legend(fontsize=9)

    # 右：实测纯密码运算墙钟（leave），log2-x -> 对数则成直线
    ax2.plot(NS, leave_us, "o-", color="tab:blue", label="measured member_leave crypto time")
    ax2.plot(NS, [leave_us[0] / math.log2(NS[0]) * math.log2(n) for n in NS],
             "k--", alpha=0.5, label="log2(n) reference")
    ax2.set_xscale("log", base=2)
    ax2.set_xticks(NS); ax2.set_xticklabels(NS)
    ax2.set_xlabel("group size n (log2 scale)")
    ax2.set_ylabel("time per leave (microseconds)")
    ax2.set_title("Measured crypto time per leave (~ log n)")
    ax2.grid(True, alpha=0.3)
    ax2.legend(fontsize=9)

    fig.suptitle("LKH group key tree: computation overhead", fontsize=13)
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    out = "group_compute.png"
    fig.savefig(out, dpi=150)
    print(f"saved -> {out}")
    print(f"  n              : {NS}")
    print(f"  init  cryptoops: {init_ops}  (~4n, O(n))")
    print(f"  join  cryptoops: {join_ops}  (O(log n))")
    print(f"  leave cryptoops: {leave_ops}  (O(log n))")
    print(f"  leave time (us): {[round(x,2) for x in leave_us]}  (measured, ~log n)")


if __name__ == "__main__":
    main()
