"""
negotiation.py
==============
模式与算法协商、降级保护策略。

supported_algorithms 用模式标识表示：legacy / hybrid / pq-only。
安全偏好（从高到低）：pq-only > hybrid > legacy。

协商规则：
  - 对 客户端支持集 ∩ 网关支持集 取交集，按安全偏好选最高者；
  - 交集为空           -> 拒绝连接（success=False）；
  - 选中 legacy        -> 附带安全警告（不具备抗量子安全性）。

“非 auto 显式模式”的冲突策略（见报告）：
  客户端把它“请求的具体模式”作为唯一对外公布的 supported_algorithms（见 protocol.py），
  因此若该模式不在网关支持集内，交集为空 -> 直接握手失败（fail-closed），不静默降级。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

MODE_LEGACY = "legacy"
MODE_HYBRID = "hybrid"
MODE_PQ_ONLY = "pq-only"

ALL_MODES = [MODE_LEGACY, MODE_HYBRID, MODE_PQ_ONLY]

# 安全偏好顺序（索引越大越优先）
_PREFERENCE = {MODE_LEGACY: 0, MODE_HYBRID: 1, MODE_PQ_ONLY: 2}

LEGACY_WARNING = (
    "对端不支持后量子算法，本次握手仅使用传统 DH，不具备抗量子安全性"
)


@dataclass
class NegotiationResult:
    success: bool
    selected_mode: Optional[str]
    selected_algorithms: List[str]
    warnings: List[str]
    reason: str = ""


def mode_needs_dh(mode: str) -> bool:
    return mode in (MODE_LEGACY, MODE_HYBRID)


def mode_needs_pq(mode: str) -> bool:
    return mode in (MODE_HYBRID, MODE_PQ_ONLY)


def selected_algorithms_for(mode: str, dh_name: str, kem_name: str) -> List[str]:
    """把抽象模式映射到具体算法名（供 selected_algorithms 字段与报告记录）。"""
    algs: List[str] = []
    if mode_needs_dh(mode):
        algs.append(dh_name)
    if mode_needs_pq(mode):
        algs.append(kem_name)
    return algs


def negotiate(
    client_supported: List[str],
    gateway_supported: List[str],
    dh_name: str,
    kem_name: str,
) -> NegotiationResult:
    """网关侧协商：从交集中按安全偏好选最高模式。"""
    valid = set(ALL_MODES)
    inter = [m for m in client_supported if m in gateway_supported and m in valid]

    if not inter:
        return NegotiationResult(
            success=False,
            selected_mode=None,
            selected_algorithms=[],
            warnings=[],
            reason="双方无共同安全算法，拒绝连接",
        )

    selected = max(inter, key=lambda m: _PREFERENCE[m])
    warnings: List[str] = []
    if selected == MODE_LEGACY:
        warnings.append(LEGACY_WARNING)

    return NegotiationResult(
        success=True,
        selected_mode=selected,
        selected_algorithms=selected_algorithms_for(selected, dh_name, kem_name),
        warnings=warnings,
    )
