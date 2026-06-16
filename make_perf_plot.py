"""
make_perf_plot.py
=================
实验一（握手性能）通信开销 + 计算开销对比图。
数据取自报告 §实验一 的实测结果（100 轮），与表格保持一致。
运行： python make_perf_plot.py  ->  perf_overhead.png
"""

from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

MODES = ["legacy", "hybrid", "pq-only"]

# 每条消息字节（含帧头）
CH = [110, 1294, 1263]
GH = [189, 1303, 1262]
CF = [94, 94, 94]
GF = [95, 95, 95]

# 计算开销（mean, ms）：client / gateway
CLIENT_CMP = [0.176, 2.191, 1.933]
GATEWAY_CMP = [0.186, 1.710, 1.451]


def main():
    x = np.arange(len(MODES))
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.8))

    # ---- 左：通信开销（每种模式分组，4 根独立柱子）----
    msgs = [("ClientHello", CH, "tab:blue"), ("GatewayHello", GH, "tab:orange"),
            ("ClientFinished", CF, "tab:green"), ("GatewayFinished", GF, "tab:red")]
    wm = 0.2
    for j, (lab, vals, color) in enumerate(msgs):
        pos = x + (j - 1.5) * wm
        ax1.bar(pos, vals, wm, label=lab, color=color)
        for xi, v in zip(pos, vals):
            ax1.text(xi, v + 25, str(v), ha="center", fontsize=7)
    ax1.set_xticks(x)
    ax1.set_xticklabels(MODES)
    ax1.set_ylabel("bytes per message (with 4B frame header)")
    ax1.set_title("Communication overhead per message")
    ax1.legend(fontsize=8)
    ax1.set_ylim(0, max(max(CH), max(GH)) * 1.18)
    ax1.grid(True, axis="y", alpha=0.3)

    # ---- 右：计算开销（client / gateway 分组）----
    w = 0.38
    ax2.bar(x - w / 2, CLIENT_CMP, w, label="client compute", color="tab:purple")
    ax2.bar(x + w / 2, GATEWAY_CMP, w, label="gateway compute", color="tab:cyan")
    for i in range(len(MODES)):
        ax2.text(i - w / 2, CLIENT_CMP[i] + 0.03, f"{CLIENT_CMP[i]:.2f}", ha="center", fontsize=8)
        ax2.text(i + w / 2, GATEWAY_CMP[i] + 0.03, f"{GATEWAY_CMP[i]:.2f}", ha="center", fontsize=8)
    ax2.set_xticks(x)
    ax2.set_xticklabels(MODES)
    ax2.set_ylabel("mean compute time (ms)")
    ax2.set_title("Computation overhead per side")
    ax2.legend(fontsize=9)
    ax2.set_ylim(0, max(CLIENT_CMP) * 1.25)
    ax2.grid(True, axis="y", alpha=0.3)

    fig.suptitle("Handshake overhead by mode (legacy / hybrid / pq-only)", fontsize=13)
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    fig.savefig("perf_overhead.png", dpi=150)
    print("saved -> perf_overhead.png")
    print(f"  comm totals (B): {dict(zip(MODES, totals.tolist()))}")
    print(f"  client cmp (ms): {dict(zip(MODES, CLIENT_CMP))}")
    print(f"  gateway cmp(ms): {dict(zip(MODES, GATEWAY_CMP))}")


if __name__ == "__main__":
    main()
