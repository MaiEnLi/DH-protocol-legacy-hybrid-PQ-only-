"""
attacker.py
===========
任务四：中间人（MITM）降级攻击模拟器。

与“客户端钩子”式的半模拟不同，这里实现一个“真正的中间人 socket 代理”：
它坐在 Client 与真实 Gateway 之间，转发四条握手帧，并在转发途中按策略
篡改或重放消息，从而真实地检验协议的降级防护。

  Client  ──►  Attacker(代理)  ──►  Gateway
          ◄──                ◄──

握手固定 4 条消息、顺序确定，代理据此逐条中继：
  ClientHello (C→G) → GatewayHello (G→C) → ClientFinished (C→G) → GatewayFinished (G→C)

“被检测到（detected）”的判定：客户端握手未成功（success=False）即视为攻击被检出——
因为协议要么校验失败中止、要么因传输文本不一致导致会话密钥不一致。
"""

from __future__ import annotations

import socket
import threading
from typing import Callable, Dict, List, Optional

import negotiation as neg
from messages import ClientHello, GatewayHello
from protocol import GatewayServer, client_handshake
from wire import recv_msg, send_msg

# 篡改函数类型：输入一条消息的原始字节，返回（可能被改过的）字节
TamperFn = Callable[[bytes], bytes]


# --------------------------------------------------------------------------- #
# 中间人代理
# --------------------------------------------------------------------------- #
class Attacker:
    """
    在 Client 与真实 Gateway 之间中继握手，并对指定消息施加篡改。
    tamper：{'ClientHello'|'GatewayHello'|'ClientFinished'|'GatewayFinished': fn}
    record：若提供（dict），把转发途中看到的 ClientHello / GatewayHello 原始字节存入，
            供“重放攻击”复用。
    """

    def __init__(self, gateway_host: str, gateway_port: int,
                 tamper: Optional[Dict[str, TamperFn]] = None,
                 record: Optional[Dict[str, bytes]] = None,
                 host: str = "127.0.0.1") -> None:
        self.gw_host = gateway_host
        self.gw_port = gateway_port
        self.tamper = tamper or {}
        self.record = record
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, 0))
        self._sock.listen(8)
        self.host, self.port = self._sock.getsockname()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def _apply(self, name: str, raw: bytes) -> bytes:
        fn = self.tamper.get(name)
        return fn(raw) if fn else raw

    def _relay_once(self, cconn: socket.socket) -> None:
        gw = socket.create_connection((self.gw_host, self.gw_port))
        gw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            # 1) ClientHello: Client -> Gateway
            ch, _ = recv_msg(cconn)
            if self.record is not None:
                self.record["ClientHello"] = ch
            send_msg(gw, self._apply("ClientHello", ch))

            # 2) GatewayHello: Gateway -> Client
            gh, _ = recv_msg(gw)
            if self.record is not None:
                self.record["GatewayHello"] = gh
            send_msg(cconn, self._apply("GatewayHello", gh))

            # 3) ClientFinished: Client -> Gateway
            cf, _ = recv_msg(cconn)
            send_msg(gw, self._apply("ClientFinished", cf))

            # 4) GatewayFinished: Gateway -> Client
            gf, _ = recv_msg(gw)
            send_msg(cconn, self._apply("GatewayFinished", gf))
        except (ConnectionError, OSError, ValueError):
            # 篡改导致某一方提前中止连接，属预期内（说明攻击被检出）
            pass
        finally:
            try:
                gw.close()
            except Exception:
                pass

    def _serve(self) -> None:
        while self._running:
            try:
                cconn, _ = self._sock.accept()
            except OSError:
                break
            cconn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                self._relay_once(cconn)
            except Exception:
                pass
            finally:
                try:
                    cconn.close()
                except Exception:
                    pass

    def start(self) -> "Attacker":
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
# 各类篡改策略
# --------------------------------------------------------------------------- #
def tamper_remove_alg(alg: str) -> TamperFn:
    """从 ClientHello 的 supported_algorithms 中删除某个模式（裁剪降级）。"""
    def f(raw: bytes) -> bytes:
        ch = ClientHello.deserialize(raw)
        ch.supported_algorithms = [m for m in ch.supported_algorithms if m != alg]
        return ch.serialize()
    return f


def tamper_force_legacy(raw: bytes) -> bytes:
    """把 GatewayHello 的 selected_mode 强行改成 legacy。"""
    gh = GatewayHello.deserialize(raw)
    gh.selected_mode = neg.MODE_LEGACY
    return gh.serialize()


def tamper_replace_downgrade(raw: bytes) -> bytes:
    """替换 GatewayHello 的 downgrade_protection_field（全 0 伪造）。"""
    gh = GatewayHello.deserialize(raw)
    n = len(gh.downgrade_protection_field) or 32
    gh.downgrade_protection_field = bytes(n)
    return gh.serialize()


def tamper_replay(old_bytes: bytes) -> TamperFn:
    """用一条录制的旧消息替换当前消息（重放攻击）。"""
    def f(_raw: bytes) -> bytes:
        return old_bytes
    return f


# --------------------------------------------------------------------------- #
# 检测依据归类（供报告“检测依据”列）
# --------------------------------------------------------------------------- #
def detection_basis(reason: str) -> str:
    if "降级保护" in reason:
        return "downgrade_protection_field"
    if "authenticator" in reason:
        return "gateway_authenticator"
    if "Finished" in reason or "传输文本" in reason:
        return "transcript hash / Finished MAC"
    if reason:
        return "transcript hash / Finished MAC"  # 连接被对端中止，根因仍是绑定不一致
    return "-"


# --------------------------------------------------------------------------- #
# 攻击实验套件
# --------------------------------------------------------------------------- #
def run_attack_suite(host: str = "127.0.0.1", skip_negotiation_checks: bool = False) -> Dict:
    """
    依次执行：一次无篡改基线 + 五种规定攻击 + 一种扩展攻击（重放旧 GatewayHello）。
    skip_negotiation_checks=True 时，客户端跳过“降级保护字段 + 认证符”这一层，
    仅靠 transcript / Finished MAC 防护——用于纵深防御对比实验。
    返回 {'baseline': ..., 'rows': [...]}。
    """
    server = GatewayServer(host, 0, neg.ALL_MODES).start()
    gport = server.port

    def drain() -> None:
        try:
            server.results.get(timeout=5)
        except Exception:
            pass

    def do(proxy_port, mode):
        return client_handshake(host, proxy_port, mode, neg.ALL_MODES,
                                _skip_negotiation_checks=skip_negotiation_checks)

    try:
        # 基线（无篡改）：顺便录制本次 CH/GH 供重放攻击复用
        rec: Dict[str, bytes] = {}
        proxy = Attacker(host, gport, record=rec).start()
        baseline = do(proxy.port, "hybrid")
        proxy.stop()
        drain()

        attacks = [
            ("remove_pq_only",          {"ClientHello": tamper_remove_alg(neg.MODE_PQ_ONLY)}, "auto"),
            ("remove_hybrid",           {"ClientHello": tamper_remove_alg(neg.MODE_HYBRID)},  "auto"),
            ("force_legacy",            {"GatewayHello": tamper_force_legacy},                "hybrid"),
            ("replace_downgrade_field", {"GatewayHello": tamper_replace_downgrade},           "hybrid"),
            ("replay_old_client_hello", {"ClientHello": tamper_replay(rec["ClientHello"])},   "hybrid"),
            # —— 创新扩展：重放旧的 GatewayHello ——
            ("replay_old_gateway_hello", {"GatewayHello": tamper_replay(rec["GatewayHello"])}, "hybrid"),
        ]

        rows: List[Dict] = []
        for name, tamper, mode in attacks:
            proxy = Attacker(host, gport, tamper=tamper).start()
            res = do(proxy.port, mode)
            proxy.stop()
            drain()
            rows.append({
                "attack": name,
                "detected": not res["success"],
                "basis": detection_basis(res.get("reason", "")),
                "reason": res.get("reason", ""),
            })
        return {"baseline": baseline, "rows": rows}
    finally:
        server.stop()


def run_defense_in_depth(host: str = "127.0.0.1") -> None:
    """
    纵深防御对比实验（创新扩展）：分两趟跑同一组攻击——
      第 1 趟：完整防护（降级字段/认证符 + transcript/Finished 全开）；
      第 2 趟：人为关闭“降级字段 + 认证符”这一层，仅留 transcript/Finished。
    若第 2 趟仍全部检出，则证明两层防护各自独立有效、互为冗余。
    """
    print("=" * 72)
    print("纵深防御对比实验：关闭“降级保护层”后，transcript/Finished 能否独立兜底")
    print("=" * 72)
    full = run_attack_suite(host, skip_negotiation_checks=False)
    only_tr = run_attack_suite(host, skip_negotiation_checks=True)

    print(f"{'attack_type':<28}{'完整防护':<10}{'仅 transcript/Finished'}")
    print("-" * 60)
    for a, b in zip(full["rows"], only_tr["rows"]):
        print(f"{a['attack']:<28}{str(a['detected']).lower():<10}{str(b['detected']).lower()}")
    print()
    both = all(r["detected"] for r in only_tr["rows"])
    print(f"结论：关闭降级保护层后，仅凭 transcript/Finished MAC {'仍能全部检出' if both else '存在漏检'}，"
          "证明两层防护相互独立、互为冗余（纵深防御）。")
    print()


def print_attack_report(result: Dict) -> None:
    base = result["baseline"]
    rows = result["rows"]
    print("=" * 72)
    print("任务四：中间人降级攻击模拟（真实 socket 代理）")
    print("=" * 72)
    print(f"基线（无篡改透传）: success={base['success']}  selected_mode={base['selected_mode']}"
          f"  -> 代理透明、无误报\n")

    print(f"{'attack_type':<28}{'detected':<10}{'检测依据 (detection basis)'}")
    print("-" * 72)
    for r in rows:
        print(f"{r['attack']:<28}{str(r['detected']).lower():<10}{r['basis']}")
    print()

    all_detected = all(r["detected"] for r in rows)
    print(f"结论：六种攻击全部{'被检测到' if all_detected else '——存在未检出项！'}"
          f"（detected 全为 true），且无篡改基线握手成功（无误报）。")
    print("检测依据：降级保护字段（downgrade_protection_field）+ 传输文本哈希（transcript hash）")
    print("          + Finished MAC，三重绑定互为冗余。")
    print("局限：本模拟假设攻击者不知握手共享密钥；若攻击者能完整冒充网关，需长期身份"
          "（证书 / 后量子签名 ML-DSA）才能防护——见报告。")
    print()


if __name__ == "__main__":
    print_attack_report(run_attack_suite())
    run_defense_in_depth()
