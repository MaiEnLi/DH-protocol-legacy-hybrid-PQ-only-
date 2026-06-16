"""
primitives.py
=============
传统 DH 与后量子 KEM 的抽象基类 + toy 实现 + 真实实现。

上层协议只依赖抽象基类暴露的统一接口：
    DHScheme  : keygen() -> (private, public_bytes); derive(private, peer_public_bytes) -> shared_secret
    KEMScheme : keygen() -> (private, public_bytes); encaps(public_bytes) -> (ciphertext, shared_secret)
                decaps(private, ciphertext) -> shared_secret

切换 toy / 真实实现不需要改动任何协议代码。

实现优先级：有真实库就用，否则自动回退 toy，并在运行时打印当前使用的是哪一种。

================================ 安全声明 ================================
本文件中的 ToyDH / ToyKEM 仅用于“模拟协议流程”，**不具备真实密码学安全性**：
  - ToyDH 使用固定的 MODP 群，私钥位数与实现均未经安全加固；
  - ToyKEM 是 ElGamal 风格的“玩具 KEM”，并非格密码，无法抵抗任何现实攻击。
真实部署必须使用经过验证的库（X25519 / ML-KEM-768 等）。
========================================================================
"""

from __future__ import annotations

import abc
import hashlib
import os
import secrets
from typing import Tuple


# --------------------------------------------------------------------------- #
# 抽象基类
# --------------------------------------------------------------------------- #
class DHScheme(abc.ABC):
    """传统 Diffie-Hellman 密钥协商抽象接口。"""

    name: str = "abstract-dh"

    @abc.abstractmethod
    def keygen(self) -> Tuple[object, bytes]:
        """返回 (私钥对象, 公钥字节)。私钥对象对上层不透明。"""

    @abc.abstractmethod
    def derive(self, private: object, peer_public: bytes) -> bytes:
        """用本端私钥与对端公钥计算共享密钥（bytes）。"""


class KEMScheme(abc.ABC):
    """后量子密钥封装机制（KEM）抽象接口。"""

    name: str = "abstract-kem"

    @abc.abstractmethod
    def keygen(self) -> Tuple[object, bytes]:
        """返回 (私钥对象, 公钥字节)。"""

    @abc.abstractmethod
    def encaps(self, peer_public: bytes) -> Tuple[bytes, bytes]:
        """对对端公钥封装，返回 (密文字节, 共享密钥字节)。"""

    @abc.abstractmethod
    def decaps(self, private: object, ciphertext: bytes) -> bytes:
        """用本端私钥解封装密文，返回共享密钥字节。"""


# --------------------------------------------------------------------------- #
# Toy 实现（仅模拟，不具真实安全性）
# --------------------------------------------------------------------------- #
# RFC 3526 中的 2048-bit MODP 群（Group 14）。仅用于 toy 演示。
_TOY_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_TOY_G = 2
_TOY_BYTES = (_TOY_P.bit_length() + 7) // 8  # 公钥/密文的固定字节长度


def _int_to_fixed_bytes(x: int) -> bytes:
    return x.to_bytes(_TOY_BYTES, "big")


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


class ToyDH(DHScheme):
    """玩具有限域 DH（仅模拟流程，不安全）。"""

    name = "toy-dh-modp2048"

    def keygen(self) -> Tuple[object, bytes]:
        priv = secrets.randbits(256) + 1            # 256-bit 私钥
        pub = pow(_TOY_G, priv, _TOY_P)
        return priv, _int_to_fixed_bytes(pub)

    def derive(self, private: object, peer_public: bytes) -> bytes:
        peer = _bytes_to_int(peer_public)
        shared_int = pow(peer, int(private), _TOY_P)
        # 用 SHA-256 把群元素压成 32 字节共享密钥
        return hashlib.sha256(_int_to_fixed_bytes(shared_int)).digest()


class ToyKEM(KEMScheme):
    """
    玩具 KEM（ElGamal 风格，仅模拟流程，不安全）。
    keygen : 私钥 x, 公钥 g^x
    encaps : 选 y, 密文 c = g^y, 共享密钥 = H((g^x)^y) = H(g^{xy})
    decaps : 共享密钥 = H(c^x) = H(g^{xy})
    注意：这不是格密码，公钥/密文大小也不代表 ML-KEM 的真实尺寸。
    """

    name = "toy-kem-elgamal2048"

    def keygen(self) -> Tuple[object, bytes]:
        x = secrets.randbits(256) + 1
        pub = pow(_TOY_G, x, _TOY_P)
        return x, _int_to_fixed_bytes(pub)

    def encaps(self, peer_public: bytes) -> Tuple[bytes, bytes]:
        pub = _bytes_to_int(peer_public)
        y = secrets.randbits(256) + 1
        c = pow(_TOY_G, y, _TOY_P)
        shared_int = pow(pub, y, _TOY_P)
        shared = hashlib.sha256(_int_to_fixed_bytes(shared_int)).digest()
        return _int_to_fixed_bytes(c), shared

    def decaps(self, private: object, ciphertext: bytes) -> bytes:
        c = _bytes_to_int(ciphertext)
        shared_int = pow(c, int(private), _TOY_P)
        return hashlib.sha256(_int_to_fixed_bytes(shared_int)).digest()


# --------------------------------------------------------------------------- #
# 真实实现
# --------------------------------------------------------------------------- #
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    class RealX25519DH(DHScheme):
        """真实 ECDH（X25519），来自 `cryptography` 库。"""

        name = "x25519"

        def keygen(self) -> Tuple[object, bytes]:
            priv = X25519PrivateKey.generate()
            pub = priv.public_key().public_bytes_raw()  # 32 字节
            return priv, pub

        def derive(self, private: object, peer_public: bytes) -> bytes:
            peer = X25519PublicKey.from_public_bytes(peer_public)
            shared = private.exchange(peer)              # 32 字节
            return hashlib.sha256(shared).digest()       # 统一压成 32 字节

    _HAVE_REAL_DH = True
except Exception:  # pragma: no cover
    _HAVE_REAL_DH = False


# 真实 KEM 后端，按优先级尝试；装上哪个用哪个，协议代码无需改动。
# 优先级： liboqs(oqs) > quantcrypt(预编译 PQClean) 。
_REAL_KEM_FACTORIES: list = []  # [(backend_name, class), ...]

# --- 后端 1：liboqs-python（oqs），最权威 ---
try:
    import oqs  # type: ignore

    def _pick_mlkem_alg() -> str:
        enabled = set(oqs.get_enabled_kem_mechanisms())
        for cand in ("ML-KEM-768", "Kyber768"):
            if cand in enabled:
                return cand
        raise RuntimeError("liboqs 未启用 ML-KEM-768 / Kyber768")

    class RealMLKEM_OQS(KEMScheme):
        """真实后量子 KEM（ML-KEM-768 / Kyber768），来自 liboqs。"""

        def __init__(self) -> None:
            self.alg = _pick_mlkem_alg()
            self.name = self.alg.lower() + "(liboqs)"

        def keygen(self) -> Tuple[object, bytes]:
            kem = oqs.KeyEncapsulation(self.alg)   # 私钥保存在对象内部
            return kem, kem.generate_keypair()

        def encaps(self, peer_public: bytes) -> Tuple[bytes, bytes]:
            with oqs.KeyEncapsulation(self.alg) as enc:
                ciphertext, shared = enc.encap_secret(peer_public)
            return ciphertext, shared

        def decaps(self, private: object, ciphertext: bytes) -> bytes:
            return private.decap_secret(ciphertext)

    _REAL_KEM_FACTORIES.append(("liboqs", RealMLKEM_OQS))
except Exception:
    pass

# --- 后端 2：quantcrypt（预编译 PQClean 实现，pip 安装即可，跨平台带 wheel）---
try:
    from quantcrypt.kem import MLKEM_768 as _QC_MLKEM768  # type: ignore

    class RealMLKEM_QuantCrypt(KEMScheme):
        """真实后量子 KEM（ML-KEM-768），来自 quantcrypt（PQClean）。

        API： keygen()->(pk, sk)；encaps(pk)->(ct, ss)；decaps(sk, ct)->ss。
        ML-KEM-768 尺寸：公钥 1184 B、密文 1088 B、共享密钥 32 B（FIPS 203）。
        """

        name = "ml-kem-768(quantcrypt)"

        def __init__(self) -> None:
            self._kem = _QC_MLKEM768()

        def keygen(self) -> Tuple[object, bytes]:
            pk, sk = self._kem.keygen()
            return sk, pk                       # private=sk, public=pk

        def encaps(self, peer_public: bytes) -> Tuple[bytes, bytes]:
            ciphertext, shared = self._kem.encaps(peer_public)
            return ciphertext, shared

        def decaps(self, private: object, ciphertext: bytes) -> bytes:
            return self._kem.decaps(private, ciphertext)

    _REAL_KEM_FACTORIES.append(("quantcrypt", RealMLKEM_QuantCrypt))
except Exception:
    pass

_HAVE_REAL_KEM = len(_REAL_KEM_FACTORIES) > 0


# --------------------------------------------------------------------------- #
# 工厂：自动选择真实 / toy
# --------------------------------------------------------------------------- #
def _force_toy() -> bool:
    """设置环境变量 HPQ_FORCE_TOY=1 可强制使用 toy 原语（便于对照实验）。"""
    return os.environ.get("HPQ_FORCE_TOY", "0") == "1"


def get_dh_scheme() -> Tuple[DHScheme, bool]:
    """返回 (DH 方案实例, 是否为真实库)。"""
    if _HAVE_REAL_DH and not _force_toy():
        return RealX25519DH(), True
    return ToyDH(), False


def get_kem_scheme() -> Tuple[KEMScheme, bool]:
    """返回 (KEM 方案实例, 是否为真实库)。按优先级选用首个可用的真实后端。"""
    if _HAVE_REAL_KEM and not _force_toy():
        _, cls = _REAL_KEM_FACTORIES[0]
        return cls(), True
    return ToyKEM(), False


def primitive_info() -> dict:
    """汇总当前生效的原语信息，供运行时打印与报告记录。"""
    dh, dh_real = get_dh_scheme()
    kem, kem_real = get_kem_scheme()
    return {
        "dh_name": dh.name,
        "dh_is_real": dh_real,
        "kem_name": kem.name,
        "kem_is_real": kem_real,
    }


if __name__ == "__main__":
    info = primitive_info()
    print("当前密码原语：")
    print(f"  DH  : {info['dh_name']}  ({'真实库' if info['dh_is_real'] else 'toy(不安全)'})")
    print(f"  KEM : {info['kem_name']} ({'真实库' if info['kem_is_real'] else 'toy(不安全)'})")
