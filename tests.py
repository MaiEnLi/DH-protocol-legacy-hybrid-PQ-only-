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


if __name__ == "__main__":
    unittest.main(verbosity=2)
