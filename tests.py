"""
tests.py
========
单元测试，覆盖：
  (a) 三种模式双方 session_key 逐字节一致；
  (b) 模拟中间人篡改 ClientHello 算法列表后，hybrid 不被降级到 legacy（握手失败 / 检出篡改）；
  (c) 一方仅支持 legacy 时握手仍完成，但产生安全警告；
另含协商偏好、空交集拒绝等补充用例。

运行： python tests.py   或   python -m unittest tests
"""

from __future__ import annotations

import unittest

import negotiation as neg
from messages import ClientHello
from protocol import run_handshake

ALL = [neg.MODE_LEGACY, neg.MODE_HYBRID, neg.MODE_PQ_ONLY]


class TestKeyAgreement(unittest.TestCase):
    def test_three_modes_keys_match(self):
        """(a) legacy / hybrid / pq-only 三模式双方密钥一致。"""
        for mode in ALL:
            r = run_handshake(mode, ALL, ALL)
            self.assertTrue(r.success, f"{mode} 握手应成功: {r.reason}")
            self.assertEqual(r.mode, mode)
            self.assertEqual(r.client_session_key, r.gateway_session_key,
                             f"{mode} 双方密钥应逐字节相等")
            self.assertEqual(len(r.client_session_key), 32)


class TestDowngradeProtection(unittest.TestCase):
    def test_mitm_strip_not_downgraded_to_legacy(self):
        """(b) 中间人把 ClientHello 算法列表裁剪为仅 legacy，握手必须失败（不被静默降级）。"""

        def strip_to_legacy(ch: ClientHello) -> ClientHello:
            ch.supported_algorithms = [neg.MODE_LEGACY]
            return ch

        r = run_handshake("auto", ALL, ALL, mitm=strip_to_legacy)
        self.assertFalse(r.success, "篡改算法列表后握手不应成功")
        # 关键：不能出现“成功且被降级到 legacy”
        self.assertFalse(r.success and r.mode == neg.MODE_LEGACY)

    def test_mitm_strip_pq_only(self):
        """中间人删除 pq-only 项同样应被检出。"""

        def strip_pq(ch: ClientHello) -> ClientHello:
            ch.supported_algorithms = [m for m in ch.supported_algorithms if m != neg.MODE_PQ_ONLY]
            return ch

        r = run_handshake("auto", ALL, ALL, mitm=strip_pq)
        self.assertFalse(r.success, "裁剪 pq-only 后握手应被检出而失败")


class TestLegacyCompatWarning(unittest.TestCase):
    def test_legacy_only_peer_warns(self):
        """(c) 客户端仅支持 legacy：握手成功但带安全警告。"""
        r = run_handshake("auto", [neg.MODE_LEGACY], ALL)
        self.assertTrue(r.success)
        self.assertEqual(r.mode, neg.MODE_LEGACY)
        self.assertTrue(r.warnings, "仅 legacy 时必须输出安全警告")
        self.assertEqual(r.client_session_key, r.gateway_session_key)


class TestNegotiation(unittest.TestCase):
    def test_prefers_pq_only(self):
        r = run_handshake("auto", ALL, ALL)
        self.assertEqual(r.mode, neg.MODE_PQ_ONLY)

    def test_prefers_hybrid_when_no_pq_only(self):
        r = run_handshake("auto", [neg.MODE_LEGACY, neg.MODE_HYBRID], ALL)
        self.assertEqual(r.mode, neg.MODE_HYBRID)

    def test_empty_intersection_rejected(self):
        r = run_handshake("auto", [neg.MODE_PQ_ONLY], [neg.MODE_LEGACY])
        self.assertFalse(r.success, "无共同安全算法应拒绝连接")

    def test_explicit_mode_conflict_fails(self):
        """显式请求 hybrid 但网关不支持 -> fail-closed。"""
        r = run_handshake("hybrid", ALL, [neg.MODE_LEGACY])
        self.assertFalse(r.success)


class TestMitmAttacks(unittest.TestCase):
    """任务四：中间人代理对五种规定攻击 + 扩展攻击均应被检出。"""

    def test_all_attacks_detected_and_no_false_positive(self):
        import attacker
        result = attacker.run_attack_suite()
        # 无篡改基线应握手成功（代理透明，无误报）
        self.assertTrue(result["baseline"]["success"], "无篡改透传应成功")
        # 每种攻击都应被检测到
        for row in result["rows"]:
            self.assertTrue(row["detected"], f"攻击 {row['attack']} 未被检出")
        # 至少覆盖题目要求的五种攻击
        names = {r["attack"] for r in result["rows"]}
        for required in ("remove_pq_only", "remove_hybrid", "force_legacy",
                         "replace_downgrade_field", "replay_old_client_hello"):
            self.assertIn(required, names)


class TestPqAuthImpersonation(unittest.TestCase):
    """创新扩展：pq-auth 应挡住冒充网关，且不破坏合法握手。"""

    def test_legit_pq_auth_succeeds(self):
        r = run_handshake("hybrid", ALL, ALL, authenticate=True)
        self.assertTrue(r.success, "真网关 + pq-auth 应握手成功")
        self.assertEqual(r.client_session_key, r.gateway_session_key)

    def test_impersonation_blocked_by_pq_auth(self):
        import attacker
        res = attacker.run_impersonation_experiment()
        by = {r["scenario"]: r for r in res["rows"]}
        # 无认证：冒充得逞（未检测）
        self.assertFalse(by["no auth (current protocol)"]["detected"])
        # pq-auth：冒充被挡（检测到）
        self.assertTrue(by["pq-auth (ML-DSA signature)"]["detected"])
        self.assertTrue(res["overhead"]["legit_success"])

    def test_mutual_auth_legit_succeeds(self):
        r = run_handshake("hybrid", ALL, ALL, mutual=True)
        self.assertTrue(r.success, "合法双向认证应握手成功")
        self.assertEqual(r.client_session_key, r.gateway_session_key)

    def test_mutual_auth_rejects_forged_client(self):
        import attacker
        res = attacker.run_mutual_auth_experiment()
        self.assertTrue(res["legit"], "合法客户端应被接受")
        self.assertFalse(res["impostor"], "冒充客户端应被拒绝")
        self.assertFalse(res["unauth"], "未认证客户端应被拒绝")


class TestGroupKeyTree(unittest.TestCase):
    """任务五：对称 LKH 树——一致性、前向安全、对数级开销。"""

    def _keys(self, n):
        import secrets
        return [secrets.token_bytes(32) for _ in range(n)]

    def test_build_and_consistency(self):
        from group import LKHTree
        t = LKHTree(16)
        t.build(self._keys(16))
        self.assertTrue(t.all_members_consistent(), "所有成员 group_key 应一致")

    def test_leave_forward_secrecy(self):
        """离开成员无法计算新 group_key，其余成员仍一致。"""
        from group import LKHTree
        t = LKHTree(16)
        t.build(self._keys(16))
        gk_old = t.group_key()
        updated, msgs, evicted = t.leave(5)
        self.assertNotEqual(t.group_key(), gk_old, "离开后 group_key 必须更新")
        self.assertTrue(t.member_cannot_compute(evicted), "离开者不应能算出新 group_key")
        self.assertTrue(t.all_members_consistent(), "其余成员应仍一致")

    def test_logarithmic_update_cost(self):
        """leave 更新节点数应等于 log2(n)。"""
        from group import LKHTree
        import math
        for n in (8, 16, 32, 64):
            t = LKHTree(n)
            t.build(self._keys(n))
            updated, msgs, _ = t.leave(0)
            self.assertEqual(updated, int(math.log2(n)),
                             f"n={n} 时 leave 更新节点数应为 log2(n)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
