"""
metrics.py
==========
开销测量的数据结构与统计工具。

三类开销的口径（务必区分，不可混用）：
  - 通信开销 communication overhead：一次完整握手在 socket 上传输的应用层字节数
    （含 4 字节长度帧头）。对每种模式是确定值，报精确数字。
  - 计算开销 computation overhead：各密码 / 序列化操作的墙钟 CPU 时间
    （time.perf_counter），分别汇总到 client / gateway 侧，单位 ms。
  - 端到端时延 end-to-end latency：客户端发出 ClientHello 到收到 GatewayFinished
    的墙钟时间，单位 ms（= 通信 + 计算 + OS 调度）。
"""

from __future__ import annotations

import platform
import statistics
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List


# --------------------------------------------------------------------------- #
# 单次握手的指标
# --------------------------------------------------------------------------- #
@dataclass
class Metrics:
    # --- 通信开销（精确值，含帧头）---
    bytes_c2g: int = 0                      # 客户端 -> 网关 总字节
    bytes_g2c: int = 0                      # 网关 -> 客户端 总字节
    bytes_total: int = 0
    per_message_bytes: Dict[str, int] = field(default_factory=dict)
    num_messages: int = 0
    num_round_trips: int = 0

    # --- 计算开销（ms）---
    client_compute_ms: float = 0.0          # 客户端侧所有密码/序列化操作耗时之和
    gateway_compute_ms: float = 0.0
    op_timings_ms: Dict[str, float] = field(default_factory=dict)  # 形如 client.dh_keygen / gateway.kem_encaps

    # --- 端到端 ---
    end_to_end_ms: float = 0.0


# --------------------------------------------------------------------------- #
# 计时器
# --------------------------------------------------------------------------- #
class OpTimer:
    """
    单侧（client 或 gateway）的操作计时器。
    用法：
        with timer.time("dh_keygen"):
            ...
    记录到 timer.timings（每个操作各一次/握手），单位 ms。
    """

    def __init__(self) -> None:
        self.timings: Dict[str, float] = {}

    def time(self, name: str) -> "_TimerCtx":
        return _TimerCtx(self, name)

    def total_ms(self) -> float:
        return sum(self.timings.values())


class _TimerCtx:
    def __init__(self, owner: OpTimer, name: str) -> None:
        self.owner = owner
        self.name = name
        self.t0 = 0.0

    def __enter__(self) -> "_TimerCtx":
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, *exc) -> None:
        dt_ms = (time.perf_counter() - self.t0) * 1000.0
        self.owner.timings[self.name] = self.owner.timings.get(self.name, 0.0) + dt_ms


# --------------------------------------------------------------------------- #
# 多轮统计
# --------------------------------------------------------------------------- #
def percentile(values: List[float], p: float) -> float:
    """线性插值百分位（p 取 0~100）。"""
    if not values:
        return 0.0
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    frac = k - lo
    return s[lo] + (s[hi] - s[lo]) * frac


@dataclass
class Stat:
    mean: float
    median: float
    stdev: float
    minimum: float
    maximum: float
    p95: float
    n: int

    @staticmethod
    def of(values: List[float]) -> "Stat":
        if not values:
            return Stat(0, 0, 0, 0, 0, 0, 0)
        return Stat(
            mean=statistics.fmean(values),
            median=statistics.median(values),
            stdev=statistics.stdev(values) if len(values) > 1 else 0.0,
            minimum=min(values),
            maximum=max(values),
            p95=percentile(values, 95),
            n=len(values),
        )


def environment_info(primitive_info: dict) -> dict:
    """采集运行环境信息（CPU / OS / Python / 原语），供报告标注。"""
    info = {
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "python": sys.version.split()[0],
        "dh": f"{primitive_info['dh_name']} ({'real' if primitive_info['dh_is_real'] else 'toy'})",
        "kem": f"{primitive_info['kem_name']} ({'real' if primitive_info['kem_is_real'] else 'toy'})",
        "memory_gb": None,
    }
    try:  # psutil 可选
        import psutil

        info["memory_gb"] = round(psutil.virtual_memory().total / (1024 ** 3), 1)
    except Exception:
        pass
    return info
