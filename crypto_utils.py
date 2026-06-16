"""
crypto_utils.py
===============
对称密码工具与确定性序列化原语：
  - HKDF-SHA256 （KDF），手写实现，不依赖第三方库；
  - HMAC-SHA256 （MAC）；
  - Transcript （增量 SHA-256 传输文本哈希）；
  - 确定性、无歧义的“长度前缀”序列化读写器。

确定性序列化规则（全局统一）：
  - 每个 bytes 字段编码为  4 字节大端长度前缀 || 原始字节；
  - 每个 str  字段先 UTF-8 编码再按 bytes 规则编码；
  - 字符串列表先把每个元素按 str 规则编码并拼接，整体再按 bytes 规则编码。
这样保证双方对同一消息计算出的字节序列完全一致，transcript hash 才能对齐。
"""

from __future__ import annotations

import hashlib
import hmac
from typing import List


# --------------------------------------------------------------------------- #
# MAC / KDF
# --------------------------------------------------------------------------- #
def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256。"""
    return hmac.new(key, data, hashlib.sha256).digest()


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """Extract 阶段：把可能非均匀的 ikm “提纯”为定长伪随机密钥 PRK = HMAC(salt, ikm)。"""
    if salt is None or len(salt) == 0:
        salt = b"\x00" * hashlib.sha256().digest_size  # 空盐按 RFC 5869 用全零块
    return hmac_sha256(salt, ikm)


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """Expand 阶段：用 PRK 与 info 迭代 HMAC，扩展出所需长度的密钥流（RFC 5869）。"""
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        # T(i) = HMAC(PRK, T(i-1) || info || i)，info 承载上下文/域分离标签
        t = hmac_sha256(prk, t + info + bytes([counter]))
        out += t
        counter += 1
    return out[:length]


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """
    标准 HKDF-SHA256（Extract-then-Expand, RFC 5869）。
    - ikm  : 输入密钥材料（如 classical_secret || pq_secret）；
    - salt : 提取阶段盐值（本协议用 transcript_hash 作 salt）；
    - info : 扩展阶段上下文（本协议用 context 标签做域分离）。
    """
    prk = _hkdf_extract(salt, ikm)
    return _hkdf_expand(prk, info, length)


def constant_time_eq(a: bytes, b: bytes) -> bool:
    """常数时间比较，避免计时侧信道。"""
    return hmac.compare_digest(a, b)


# --------------------------------------------------------------------------- #
# 传输文本哈希（增量）
# --------------------------------------------------------------------------- #
class Transcript:
    """
    增量 SHA-256。每收/发一条握手消息，就把其“规范化字节”喂入；
    任意时刻 digest() 返回当前传输文本哈希。
    """

    def __init__(self) -> None:
        self._h = hashlib.sha256()

    def update(self, message_bytes: bytes) -> None:
        self._h.update(message_bytes)

    def digest(self) -> bytes:
        # copy 以便在不“封口”的情况下取中间快照
        return self._h.copy().digest()


# --------------------------------------------------------------------------- #
# 确定性序列化：写
# --------------------------------------------------------------------------- #
def w_bytes(b: bytes) -> bytes:
    """bytes 字段 -> 4 字节大端长度前缀 || 原始字节（长度前缀消除拼接歧义）。"""
    return len(b).to_bytes(4, "big") + b


def w_str(s: str) -> bytes:
    """str 字段 -> 先 UTF-8 编码，再按 bytes 规则编码。"""
    return w_bytes(s.encode("utf-8"))


def w_str_list(items: List[str]) -> bytes:
    """字符串列表 -> 每个元素按 str 规则编码后拼接，整体再包一层长度前缀。
    这样列表边界无歧义，双方反序列化必得到相同元素序列。"""
    inner = b"".join(w_str(x) for x in items)
    return w_bytes(inner)


def encode_str_list_for_mac(items: List[str]) -> bytes:
    """供 MAC / 降级字段使用的算法列表规范化编码（与序列化口径一致）。"""
    return w_str_list(items)


# --------------------------------------------------------------------------- #
# 确定性序列化：读
# --------------------------------------------------------------------------- #
class Reader:
    """配套的“长度前缀”读取器。"""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def _take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("反序列化越界：消息被截断或格式错误")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def r_bytes(self) -> bytes:
        n = int.from_bytes(self._take(4), "big")
        return self._take(n)

    def r_str(self) -> str:
        return self.r_bytes().decode("utf-8")

    def r_str_list(self) -> List[str]:
        inner = self.r_bytes()
        sub = Reader(inner)
        out: List[str] = []
        while sub.pos < len(inner):
            out.append(sub.r_str())
        return out

    def at_end(self) -> bool:
        return self.pos >= len(self.data)
