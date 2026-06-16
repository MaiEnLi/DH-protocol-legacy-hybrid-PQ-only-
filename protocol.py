"""
protocol.py
===========
Client 与 Gateway 状态机，以及 run_handshake() 编排入口。

握手四步（经真实 localhost TCP socket）：
    ClientHello  ->  GatewayHello  ->  ClientFinished  ->  GatewayFinished
共 4 条消息、2 个往返（RTT）。

密钥派生（context = "hybrid-pq-migration-v1"）：
    ikm = {legacy: classical_secret;  pq-only: pq_secret;
           hybrid: len(classical)||classical || len(pq)||pq}
    session_key = HKDF-SHA256(ikm, salt = transcript_hash_TH1, info = context)
  其中 TH1 = SHA256(ClientHello || GatewayHello)。

绑定与防护：
    - 传输文本绑定：每收/发一条消息，把其规范化字节喂入 transcript（增量哈希）；
    - Finished MAC：HMAC(finished_key, transcript_hash || mode || algs || c_nonce || g_nonce)，
      finished_key 由 session_key 经 HKDF 派生（client/gateway 方向各一把）；
    - 降级保护：downgrade_protection_field = HMAC(early_key, 客户端原始 supported || version)，
      early_key 由握手共享密钥派生（中间人不知该密钥，无法伪造）。客户端用“自己发出的
      原始算法列表”重算并比对；若中间人裁剪/篡改了列表，则网关算出的字段与客户端期望不符，
      握手失败。该绑定同时也被 transcript hash 二次保护（篡改会令双方 session_key 不一致）。

安全假设（详见报告）：本协议没有长期身份。gateway_authenticator 仅由握手共享密钥派生，
属于“密钥确认（key confirmation）”，证明网关算出了相同密钥，但不提供对网关身份的认证；
真实场景需引入证书或预共享 PSK 才能抵抗主动冒充。
"""

from __future__ import annotations

import os
import socket
import threading
import time
from queue import Queue
from typing import Callable, Dict, List, Optional, Tuple

import negotiation as neg
from crypto_utils import (
    Transcript,
    constant_time_eq,
    hkdf_sha256,
    hmac_sha256,
    w_bytes,
    w_str,
    w_str_list,
)
from messages import ClientFinished, ClientHello, GatewayFinished, GatewayHello
from metrics import Metrics, OpTimer
from primitives import get_dh_scheme, get_kem_scheme, get_sig_scheme
from wire import recv_msg, send_msg

CONTEXT = b"hybrid-pq-migration-v1"

GATEWAY_ID = "gateway-1"
CLIENT_ID = "client-1"
CLIENT_VERSION = "1"
NONCE_LEN = 16


class GatewayIdentity:
    """
    网关长期签名身份（信任锚）。pq-auth 模式下，网关用其长期私钥对
    (ClientHello || GatewayHello) 签名，客户端用预置（pinned）的网关公钥验证，
    从而把 gateway_authenticator 从“密钥确认”升级为“真身份认证”，抵抗冒充网关的主动中间人。
    """

    def __init__(self, scheme, priv, pub: bytes) -> None:
        self.scheme = scheme
        self.priv = priv
        self.pub = pub

    @staticmethod
    def generate() -> "GatewayIdentity":
        scheme, _ = get_sig_scheme()
        priv, pub = scheme.keygen()
        return GatewayIdentity(scheme, priv, pub)


# --------------------------------------------------------------------------- #
# 密钥派生辅助
# --------------------------------------------------------------------------- #
def _combine_secret(mode: str, classical: bytes, pq: bytes) -> bytes:
    """
    把传统/后量子共享密钥组合成 HKDF 的输入密钥材料 ikm。
    - legacy  仅传统 DH 秘密；
    - pq-only 仅 KEM 秘密；
    - hybrid  二者“长度前缀拼接”。用长度前缀(而非裸接)是为了消除拼接歧义：
      避免 a||b 与 a'||b' 拼出相同字节串而被构造混淆攻击（见报告 Q3）。
    """
    if mode == neg.MODE_LEGACY:
        return classical
    if mode == neg.MODE_PQ_ONLY:
        return pq
    return w_bytes(classical) + w_bytes(pq)


def _derive_secrets(ikm: bytes, th1: bytes) -> Dict[str, bytes]:
    """
    从 ikm 一次性派生本协议用到的全部对称密钥（HKDF-SHA256，info 做域分离）。
    注意：early_key / auth_key 用 salt="" —— 它们在 GatewayHello 构造阶段就要用到，
    而此刻 TH1（含 GatewayHello 的传输文本哈希）尚未确定，故不能依赖 TH1；
    session_key 则用 salt=TH1，把会话密钥牢牢绑定到整段握手脚本。
    """
    session_key = hkdf_sha256(ikm, salt=th1, info=CONTEXT, length=32)
    return {
        "session_key": session_key,
        "early_key": hkdf_sha256(ikm, salt=b"", info=b"downgrade-protection", length=32),
        "auth_key": hkdf_sha256(ikm, salt=b"", info=b"gateway-auth", length=32),
        # client/gateway 各用一把 finished_key，避免两个方向的 MAC 用同一密钥
        "client_finished_key": hkdf_sha256(session_key, salt=b"", info=b"client finished", length=32),
        "gateway_finished_key": hkdf_sha256(session_key, salt=b"", info=b"gateway finished", length=32),
    }


def _finished_bind(transcript_hash: bytes, mode: str, algs: List[str],
                   c_nonce: bytes, g_nonce: bytes) -> bytes:
    """Finished MAC 的被签数据：显式覆盖 协商模式 / 算法列表 / 双方 nonce，
    使任何对协商结果的篡改都会令 MAC 验证失败（满足安全要求第 3 条）。"""
    return (
        transcript_hash
        + w_str(mode)
        + w_str_list(algs)
        + w_bytes(c_nonce)
        + w_bytes(g_nonce)
    )


def _downgrade_bind(supported: List[str], version: str) -> bytes:
    """降级保护字段的被 MAC 数据：客户端原始算法列表 + 版本号。
    中间人若裁剪/篡改列表，双方算出的此值不同 -> 检出降级（见安全要求第 4 条）。"""
    return w_str_list(supported) + w_str(version)


def _auth_bind(mode: str, algs: List[str], g_nonce: bytes, c_nonce: bytes) -> bytes:
    """gateway_authenticator 的被 MAC 数据：网关对所选参数做密钥确认。
    注意这只证明对端算出了相同共享密钥，并非长期身份认证（见报告 §4.4）。"""
    return w_str(mode) + w_str_list(algs) + w_bytes(g_nonce) + w_bytes(c_nonce)


# --------------------------------------------------------------------------- #
# 网关侧：处理单个连接
# --------------------------------------------------------------------------- #
def gateway_handle_connection(conn: socket.socket, gateway_supported: List[str],
                              identity: Optional["GatewayIdentity"] = None) -> Dict:
    """处理一次握手；返回网关侧结果字典。失败时关闭连接并返回 success=False。
    identity 非空时启用 pq-auth：用网关长期私钥对握手签名（gateway_authenticator 为签名）。"""
    timer = OpTimer()
    dh, _ = get_dh_scheme()
    kem, _ = get_kem_scheme()

    transcript = Transcript()

    # 1) 接收 ClientHello
    payload, _ = recv_msg(conn)
    ch_bytes = payload
    with timer.time("deserialize"):
        ch = ClientHello.deserialize(payload)
    transcript.update(payload)  # 喂入“网关实际收到的字节”

    # 2) 协商
    nres = neg.negotiate(ch.supported_algorithms, gateway_supported, dh.name, kem.name)
    if not nres.success:
        conn.close()
        return {"success": False, "selected_mode": "failed", "warnings": [],
                "session_key": b"", "gateway_compute_ms": timer.total_ms(),
                "gateway_ops": dict(timer.timings), "reason": nres.reason}

    mode = nres.selected_mode

    # 3) 按选定模式只做必要的密钥运算（未用到的字段留空 b""，节省该模式的计算/带宽）。
    #    网关用 encaps 直接得到 pq_secret 与要回传的密文；客户端随后用 decaps 得到相同 pq_secret。
    gw_dh_pub = b""
    pq_ct = b""
    classical = b""
    pq_secret = b""
    if neg.mode_needs_dh(mode):
        with timer.time("dh_keygen"):
            gw_dh_priv, gw_dh_pub = dh.keygen()
        with timer.time("dh_derive"):
            classical = dh.derive(gw_dh_priv, ch.client_dh_public_key)
    if neg.mode_needs_pq(mode):
        with timer.time("kem_encaps"):
            pq_ct, pq_secret = kem.encaps(ch.client_pq_public_key)

    ikm = _combine_secret(mode, classical, pq_secret)

    # 4) 派生密钥（early/auth 不依赖 TH1）
    with timer.time("kdf"):
        early_key = hkdf_sha256(ikm, salt=b"", info=b"downgrade-protection", length=32)
        auth_key = hkdf_sha256(ikm, salt=b"", info=b"gateway-auth", length=32)

    # 5) 降级保护字段：对“网关实际收到的”客户端算法列表 + 版本做 MAC
    g_nonce = os.urandom(NONCE_LEN)
    with timer.time("mac"):
        downgrade_field = hmac_sha256(early_key, _downgrade_bind(ch.supported_algorithms, ch.client_version))

    gh = GatewayHello(
        gateway_id=GATEWAY_ID,
        gateway_nonce=g_nonce,
        selected_mode=mode,
        selected_algorithms=nres.selected_algorithms,
        gateway_dh_public_key=gw_dh_pub,
        pq_ciphertext=pq_ct,
        downgrade_protection_field=downgrade_field,
        gateway_authenticator=b"",          # 先占位，下面据模式填 MAC 或签名
    )
    if identity is not None:
        # pq-auth：对 (ClientHello || GatewayHello[authenticator 置空]) 做后量子签名
        tbs = ch_bytes + gh.serialize()
        with timer.time("sig_sign"):
            gh.gateway_authenticator = identity.scheme.sign(identity.priv, tbs)
    else:
        # 默认：基于握手密钥的 MAC（仅密钥确认，不认证身份）
        with timer.time("mac"):
            gh.gateway_authenticator = hmac_sha256(
                auth_key, _auth_bind(mode, nres.selected_algorithms, g_nonce, ch.client_nonce))
    with timer.time("serialize"):
        gh_bytes = gh.serialize()
    send_msg(conn, gh_bytes)
    transcript.update(gh_bytes)

    # 6) GatewayHello 已喂入 transcript，此刻得到 TH1，并据此派生会话密钥与两把 finished_key。
    with timer.time("transcript_hash"):
        th1 = transcript.digest()
    with timer.time("kdf"):
        session_key = hkdf_sha256(ikm, salt=th1, info=CONTEXT, length=32)
        cfk = hkdf_sha256(session_key, salt=b"", info=b"client finished", length=32)
        gfk = hkdf_sha256(session_key, salt=b"", info=b"gateway finished", length=32)

    # 7) 接收并校验 ClientFinished：要求其携带的 transcript_hash == 网关本地 TH1，
    #    且 MAC 正确。任一不符即说明双方握手视图不一致（篡改/降级），立即中止。
    payload, _ = recv_msg(conn)
    with timer.time("deserialize"):
        cf = ClientFinished.deserialize(payload)
    with timer.time("mac"):
        expect = hmac_sha256(cfk, _finished_bind(cf.transcript_hash, mode, nres.selected_algorithms,
                                                 ch.client_nonce, g_nonce))
    if not (constant_time_eq(cf.transcript_hash, th1) and constant_time_eq(cf.client_finished_mac, expect)):
        conn.close()
        return {"success": False, "selected_mode": mode, "warnings": nres.warnings,
                "session_key": b"", "gateway_compute_ms": timer.total_ms(),
                "gateway_ops": dict(timer.timings), "reason": "ClientFinished 校验失败（传输文本/降级篡改）"}
    transcript.update(payload)
    with timer.time("transcript_hash"):
        th2 = transcript.digest()

    # 8) 发送 GatewayFinished
    with timer.time("mac"):
        gw_mac = hmac_sha256(gfk, _finished_bind(th2, mode, nres.selected_algorithms, ch.client_nonce, g_nonce))
    gf = GatewayFinished(transcript_hash=th2, gateway_finished_mac=gw_mac)
    with timer.time("serialize"):
        gf_bytes = gf.serialize()
    send_msg(conn, gf_bytes)
    transcript.update(gf_bytes)   # 完整性：最后一条消息也纳入 transcript（其后无消息再用到）
    conn.close()

    return {"success": True, "selected_mode": mode, "warnings": nres.warnings,
            "session_key": session_key, "gateway_compute_ms": timer.total_ms(),
            "gateway_ops": dict(timer.timings), "reason": ""}


# --------------------------------------------------------------------------- #
# 客户端侧：完成一次握手
# --------------------------------------------------------------------------- #
def client_handshake(
    host: str,
    port: int,
    mode: str,
    client_supported: List[str],
    mitm: Optional[Callable[[ClientHello], ClientHello]] = None,
    _skip_negotiation_checks: bool = False,
    expected_gw_pub: Optional[bytes] = None,
    gw_sig_scheme=None,
) -> Dict:
    """
    发起一次握手；返回客户端侧结果字典（含通信开销与计算开销）。
    - mode: 客户端请求的模式。"auto" -> 公布 client_supported 全集，由网关按偏好选；
            具体模式（legacy/hybrid/pq-only）-> 仅公布该模式（fail-closed 冲突策略）。
    - mitm: 测试用钩子，篡改“上线发送”的 ClientHello 副本（模拟中间人），
            但不改变客户端用于 transcript / 降级校验的“原始 ClientHello”。
    - _skip_negotiation_checks: 仅供“纵深防御”分析实验使用——跳过降级保护字段与
            gateway_authenticator 两项显式校验，以验证仅凭 transcript / Finished MAC
            这一层是否仍能检出篡改。生产中绝不应开启。
    """
    timer = OpTimer()
    dh, _ = get_dh_scheme()
    kem, _ = get_kem_scheme()

    # auto -> 公布全部支持模式由网关挑最高；指定模式 -> 只公布它（不支持就直接失败）。
    advertised = list(client_supported) if mode == "auto" else [mode]
    # 客户端事先并不知道最终选哪个模式，故按“公布集合可能用到的”预生成密钥：
    # 只要可能协商出需要 DH/PQ 的模式，就先把对应密钥对备好。
    need_dh = any(neg.mode_needs_dh(m) for m in advertised)
    need_pq = any(neg.mode_needs_pq(m) for m in advertised)

    c_nonce = os.urandom(NONCE_LEN)  # 每次握手必须新鲜随机，保证密钥唯一、抗重放绑定
    c_dh_priv = c_dh_pub = None
    c_pq_priv = c_pq_pub = None
    if need_dh:
        with timer.time("dh_keygen"):
            c_dh_priv, c_dh_pub = dh.keygen()
    if need_pq:
        with timer.time("kem_keygen"):
            c_pq_priv, c_pq_pub = kem.keygen()

    ch = ClientHello(
        client_id=CLIENT_ID,
        client_nonce=c_nonce,
        supported_algorithms=advertised,
        client_dh_public_key=c_dh_pub or b"",
        client_pq_public_key=c_pq_pub or b"",
        client_version=CLIENT_VERSION,
    )

    per_msg: Dict[str, int] = {}
    bytes_c2g = 0
    bytes_g2c = 0

    sock = socket.create_connection((host, port))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        t_start = time.perf_counter()

        # 1) ClientHello。关键：transcript 喂入客户端“真正想发的原始字节”，
        #    而上线发送的是“可能被中间人篡改的字节”。正常情况两者相同；
        #    模拟 MITM 时二者不同 -> 网关算出的 transcript 与客户端不一致
        #    -> session_key 不同 -> Finished 校验失败，从而暴露篡改。
        with timer.time("serialize"):
            ch_bytes = ch.serialize()
        transcript = Transcript()
        transcript.update(ch_bytes)
        sent_bytes = ch_bytes
        if mitm is not None:
            tampered = mitm(ClientHello(**ch.__dict__))  # 仅篡改“上线副本”，不动原始 ch
            sent_bytes = tampered.serialize()
        n = send_msg(sock, sent_bytes)
        per_msg["ClientHello"] = n
        bytes_c2g += n

        # 2) GatewayHello
        payload, n = recv_msg(sock)
        per_msg["GatewayHello"] = n
        bytes_g2c += n
        with timer.time("deserialize"):
            gh = GatewayHello.deserialize(payload)
        transcript.update(payload)
        mode_sel = gh.selected_mode

        # 3) 计算共享秘密
        classical = b""
        pq_secret = b""
        if neg.mode_needs_dh(mode_sel):
            with timer.time("dh_derive"):
                classical = dh.derive(c_dh_priv, gh.gateway_dh_public_key)
        if neg.mode_needs_pq(mode_sel):
            with timer.time("kem_decaps"):
                pq_secret = kem.decaps(c_pq_priv, gh.pq_ciphertext)
        ikm = _combine_secret(mode_sel, classical, pq_secret)

        # 4) 派生密钥
        with timer.time("kdf"):
            early_key = hkdf_sha256(ikm, salt=b"", info=b"downgrade-protection", length=32)
            auth_key = hkdf_sha256(ikm, salt=b"", info=b"gateway-auth", length=32)

        # 5) 降级保护 / 认证校验。expect_dg 用 advertised（客户端自己发出的“真实”列表）重算；
        #    若网关收到的是被裁剪的列表，它算出的 downgrade_field 就对不上 -> 检出降级。
        #    中间人不知道 early_key（由握手秘密派生），无法伪造正确字段。
        with timer.time("mac"):
            expect_dg = hmac_sha256(early_key, _downgrade_bind(advertised, CLIENT_VERSION))
        if not _skip_negotiation_checks:
            if not constant_time_eq(expect_dg, gh.downgrade_protection_field):
                raise _HandshakeFailure("降级保护校验失败：算法列表疑似被中间人篡改/裁剪")
            if expected_gw_pub is not None:
                # pq-auth：用预置的网关长期公钥验证签名（认证网关身份，抵抗冒充）
                gh_nosig = GatewayHello(**{**gh.__dict__, "gateway_authenticator": b""}).serialize()
                tbs = ch_bytes + gh_nosig
                with timer.time("sig_verify"):
                    sig_ok = gw_sig_scheme.verify(expected_gw_pub, tbs, gh.gateway_authenticator)
                if not sig_ok:
                    raise _HandshakeFailure("网关签名验证失败：身份不可信（疑似冒充网关）")
            else:
                # 默认：校验基于握手密钥的 MAC（仅密钥确认，不认证身份）
                with timer.time("mac"):
                    expect_auth = hmac_sha256(auth_key, _auth_bind(mode_sel, gh.selected_algorithms,
                                                                   gh.gateway_nonce, c_nonce))
                if not constant_time_eq(expect_auth, gh.gateway_authenticator):
                    raise _HandshakeFailure("gateway_authenticator 校验失败")

        # 6) TH1 = SHA256(ClientHello || GatewayHello)，作为会话密钥的 salt（信道绑定）。
        with timer.time("transcript_hash"):
            th1 = transcript.digest()
        with timer.time("kdf"):
            session_key = hkdf_sha256(ikm, salt=th1, info=CONTEXT, length=32)
            cfk = hkdf_sha256(session_key, salt=b"", info=b"client finished", length=32)
            gfk = hkdf_sha256(session_key, salt=b"", info=b"gateway finished", length=32)

        # 7) ClientFinished：携带 TH1，并对其做 MAC；发出后再把它喂入 transcript 得到 TH2。
        with timer.time("mac"):
            c_mac = hmac_sha256(cfk, _finished_bind(th1, mode_sel, gh.selected_algorithms, c_nonce, gh.gateway_nonce))
        cf = ClientFinished(transcript_hash=th1, client_finished_mac=c_mac)
        with timer.time("serialize"):
            cf_bytes = cf.serialize()
        n = send_msg(sock, cf_bytes)
        per_msg["ClientFinished"] = n
        bytes_c2g += n
        transcript.update(cf_bytes)
        with timer.time("transcript_hash"):
            th2 = transcript.digest()  # TH2 = SHA256(... || ClientFinished)，供校验 GatewayFinished

        # 8) GatewayFinished：网关对 TH2 做 MAC；客户端核对 TH2 与 MAC，完成双向密钥确认。
        payload, n = recv_msg(sock)
        per_msg["GatewayFinished"] = n
        bytes_g2c += n
        with timer.time("deserialize"):
            gf = GatewayFinished.deserialize(payload)
        with timer.time("mac"):
            expect_gw = hmac_sha256(gfk, _finished_bind(gf.transcript_hash, mode_sel,
                                                        gh.selected_algorithms, c_nonce, gh.gateway_nonce))
        if not (constant_time_eq(gf.transcript_hash, th2) and constant_time_eq(gf.gateway_finished_mac, expect_gw)):
            raise _HandshakeFailure("GatewayFinished 校验失败")
        transcript.update(payload)   # 完整性：最后一条消息也纳入 transcript（与网关侧对称）

        end_to_end_ms = (time.perf_counter() - t_start) * 1000.0

        warnings: List[str] = []
        if mode_sel == neg.MODE_LEGACY:
            warnings.append(neg.LEGACY_WARNING)

        return {"success": True, "selected_mode": mode_sel, "warnings": warnings,
                "session_key": session_key, "end_to_end_ms": end_to_end_ms,
                "client_compute_ms": timer.total_ms(), "client_ops": dict(timer.timings),
                "per_message_bytes": per_msg, "bytes_c2g": bytes_c2g, "bytes_g2c": bytes_g2c,
                "reason": ""}

    except (_HandshakeFailure, ConnectionError, ValueError, AssertionError) as e:
        return {"success": False, "selected_mode": "failed", "warnings": [],
                "session_key": b"", "end_to_end_ms": 0.0,
                "client_compute_ms": timer.total_ms(), "client_ops": dict(timer.timings),
                "per_message_bytes": per_msg, "bytes_c2g": bytes_c2g, "bytes_g2c": bytes_g2c,
                "reason": str(e)}
    finally:
        try:
            sock.close()
        except Exception:
            pass


class _HandshakeFailure(Exception):
    pass


# --------------------------------------------------------------------------- #
# 网关服务器（持久监听，供 bench / experiment / 双终端演示复用）
# --------------------------------------------------------------------------- #
class GatewayServer:
    """持久 TCP 服务端：循环 accept，每个连接跑一次握手，结果推入队列。"""

    def __init__(self, host: str, port: int, gateway_supported: List[str],
                 identity: Optional["GatewayIdentity"] = None) -> None:
        self.gateway_supported = gateway_supported
        self.identity = identity          # 非空则启用 pq-auth（网关对握手签名）
        self.results: "Queue[Dict]" = Queue()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(16)
        self.host, self.port = self._sock.getsockname()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def _serve(self) -> None:
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                break
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                res = gateway_handle_connection(conn, self.gateway_supported, identity=self.identity)
            except Exception as e:  # 任何异常都不应让服务器崩溃
                res = {"success": False, "selected_mode": "failed", "warnings": [],
                       "session_key": b"", "gateway_compute_ms": 0.0,
                       "gateway_ops": {}, "reason": f"网关异常: {e}"}
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            self.results.put(res)

    def start(self) -> "GatewayServer":
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._running = False
        try:
            self._sock.close()
        except Exception:
            pass
        if self._thread:
            self._thread.join(timeout=2)


# --------------------------------------------------------------------------- #
# 结果数据结构与 run_handshake 编排
# --------------------------------------------------------------------------- #
from dataclasses import dataclass, field  # noqa: E402  (放末尾避免与上方循环引用混淆)


@dataclass
class HandshakeResult:
    client_session_key: bytes
    gateway_session_key: bytes
    success: bool
    mode: str                      # 实际 selected_mode
    time_ms: float                 # = metrics.end_to_end_ms
    warnings: List[str] = field(default_factory=list)
    metrics: Optional[Metrics] = None
    reason: str = ""


def _merge_metrics(client: Dict, gateway: Dict) -> Metrics:
    ops: Dict[str, float] = {}
    for k, v in client.get("client_ops", {}).items():
        ops[f"client.{k}"] = v
    for k, v in gateway.get("gateway_ops", {}).items():
        ops[f"gateway.{k}"] = v
    per_msg = client.get("per_message_bytes", {})
    return Metrics(
        bytes_c2g=client.get("bytes_c2g", 0),
        bytes_g2c=client.get("bytes_g2c", 0),
        bytes_total=client.get("bytes_c2g", 0) + client.get("bytes_g2c", 0),
        per_message_bytes=per_msg,
        num_messages=len(per_msg),
        num_round_trips=2,
        client_compute_ms=client.get("client_compute_ms", 0.0),
        gateway_compute_ms=gateway.get("gateway_compute_ms", 0.0),
        op_timings_ms=ops,
        end_to_end_ms=client.get("end_to_end_ms", 0.0),
    )


def _build_result(client: Dict, gateway: Dict) -> HandshakeResult:
    metrics = _merge_metrics(client, gateway)
    c_key = client.get("session_key", b"")
    g_key = gateway.get("session_key", b"")
    success = bool(client.get("success") and gateway.get("success")
                   and c_key and constant_time_eq(c_key, g_key))
    warnings = list(dict.fromkeys(client.get("warnings", []) + gateway.get("warnings", [])))
    reason = client.get("reason", "") or gateway.get("reason", "")
    return HandshakeResult(
        client_session_key=c_key,
        gateway_session_key=g_key,
        success=success,
        mode=client.get("selected_mode", "failed"),
        time_ms=metrics.end_to_end_ms,
        warnings=warnings,
        metrics=metrics,
        reason="" if success else reason,
    )


def run_handshake(
    mode: str,
    client_supported_algs: List[str],
    gateway_supported_algs: List[str],
    host: str = "127.0.0.1",
    mitm: Optional[Callable[[ClientHello], ClientHello]] = None,
    authenticate: bool = False,
) -> HandshakeResult:
    """
    单次握手编排：在临时端口拉起网关线程，客户端连 localhost 跑通四步，
    合并双方 metrics 后返回 HandshakeResult。
    authenticate=True 时启用 pq-auth：网关生成长期 ML-DSA 身份并签名，
    客户端用 pinned 公钥验证（演示对“真身份认证”的支持）。
    """
    identity = GatewayIdentity.generate() if authenticate else None
    exp_pub = identity.pub if identity else None
    exp_scheme = identity.scheme if identity else None
    server = GatewayServer(host, 0, gateway_supported_algs, identity=identity).start()
    try:
        client = client_handshake(host, server.port, mode, client_supported_algs, mitm=mitm,
                                  expected_gw_pub=exp_pub, gw_sig_scheme=exp_scheme)
        try:
            gateway = server.results.get(timeout=5)
        except Exception:
            gateway = {"success": False, "selected_mode": "failed", "warnings": [],
                       "session_key": b"", "gateway_compute_ms": 0.0, "gateway_ops": {},
                       "reason": "网关无响应"}
        return _build_result(client, gateway)
    finally:
        server.stop()
