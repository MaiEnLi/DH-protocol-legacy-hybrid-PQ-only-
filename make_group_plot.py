"""
make_group_plot.py
==================
群组 rekey 通信开销对比图：成员离开（leave）时，
  - 朴素方案（不用树，Gateway 逐个用 pairwise key 重发新群钥）： n-1 条消息  -> O(n)
  - LKH 对称密钥树（只重随机化路径并按子树广播）：           2*log2(n)-1 条 -> O(log n)
这张图说明“用树”的实际意义：通信开销从线性降到对数，且群组越大省得越多。

数据为结构确定值（与实现无关、可精确推导），运行：
    python make_group_plot.py   ->  group_overhead.png
"""

from __future__ import annotations

import math

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# 用 LKHTree 现算 leave 的真实广播消息数，验证 == 2*log2(n)-1（非硬编码）
from group import LKHTree
import secrets

NS = [8, 16, 32, 64, 128, 256, 512, 1024]


def tree_leave_messages(n: int) -> int:
    keys = [secrets.token_bytes(32) for _ in range(n)]
    t = LKHTree(n)
    t.build(keys)
    _, msgs, _ = t.leave(0)
    return msgs


def main():
    naive = [n - 1 for n in NS]                      # 朴素：逐个 pairwise 重发 -> n-1
    tree = [tree_leave_messages(n) for n in NS]       # LKH 树：实测广播消息数
    saving = [a / b for a, b in zip(naive, tree)]     # 节省倍数

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.8))

    # 左：每次 leave 的广播消息数（绝对值，线性轴）
    ax1.plot(NS, naive, "D-", color="tab:red", label="naive (no tree):  n-1   [O(n)]")
    ax1.plot(NS, tree, "o-", color="tab:blue", label="LKH tree:  2*log2(n)-1   [O(log n)]")
    ax1.set_xlabel("group size n")
    ax1.set_ylabel("broadcast messages per member_leave")
    ax1.set_title("Rekey communication overhead on a member leave")
    ax1.grid(True, alpha=0.3)
    ax1.legend(fontsize=9)
    for x, a, b in zip(NS, naive, tree):
        if x in (64, 1024):
            ax1.annotate(f"{a}", (x, a), textcoords="offset points", xytext=(-6, 6),
                         fontsize=8, color="tab:red")
            ax1.annotate(f"{b}", (x, b), textcoords="offset points", xytext=(-6, 8),
                         fontsize=8, color="tab:blue")

    # 右：节省倍数（树相对朴素省了多少倍）
    ax2.plot(NS, saving, "s-", color="tab:green")
    ax2.set_xscale("log", base=2)
    ax2.set_xticks(NS)
    ax2.set_xticklabels(NS)
    ax2.set_xlabel("group size n (log2 scale)")
    ax2.set_ylabel("saving factor  (naive / tree)")
    ax2.set_title("Message saving grows with group size")
    ax2.grid(True, alpha=0.3)
    for x, s in zip(NS, saving):
        if x in (64, 256, 1024):
            ax2.annotate(f"{s:.0f}x", (x, s), textcoords="offset points", xytext=(-4, 6), fontsize=9)

    fig.suptitle("LKH group key tree: rekey communication overhead vs naive distribution",
                 fontsize=13)
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    out = "group_overhead.png"
    fig.savefig(out, dpi=150)
    print(f"saved -> {out}")
    print(f"  n            : {NS}")
    print(f"  naive (n-1)  : {naive}")
    print(f"  LKH tree     : {tree}")
    print(f"  saving factor: {[round(s,1) for s in saving]}")


if __name__ == "__main__":
    main()
