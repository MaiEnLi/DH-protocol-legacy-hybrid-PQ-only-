"""
group.py
========
任务五（选做）：基于对称密钥树的动态群组密钥管理（LKH，Logical Key Hierarchy）。

设计取舍（见报告）：
- Gateway 是可信 KDC（已与每个成员通过任务二握手得到 pairwise session key），
  因此采用\对称密钥树（LKH, RFC 2627 风味）而非公钥树（TreeKEM）。对称树的意义在于把
  成员变更时的 rekey 广播从 O(n) 降到 O(log n)，而非“让服务器不知道群钥”。
- 节点采用堆式编号：根=1，节点 v 的子节点为 2v / 2v+1，叶子为 [capacity, 2*capacity)。
- 叶子密钥由成员 session_key 派生：leaf_key = HKDF(session_key, salt=epoch, info="leaf")。
- 内部节点持有随机 KEK（密钥加密密钥）；group_key = 根密钥。
- 成员离开（leave）时，对“被逐成员到根的路径”上的全部节点\重新随机化（注入新随机），
  并把新节点密钥用其子节点密钥加密广播——确保离开者无法用旧密钥算出新 group_key
  （前向安全）。这正是“路径重随机化”。

每次操作统计两个结构量：
- updated_nodes      ：本次有多少节点密钥被更新；
- broadcast_messages ：KDC 需发送多少条加密 rekey 广播（= 新节点密钥 × 接收子树数）。

注：本文件不直接依赖具体握手原语；session_key 由上层（实验）通过任务二握手提供。
"""

from __future__ import annotations

import math
import os
from typing import Dict, List, Tuple

from crypto_utils import hkdf_sha256


def is_pow2(x: int) -> bool:
    return x >= 1 and (x & (x - 1)) == 0


def next_pow2(x: int) -> int:
    p = 1
    while p < x:
        p *= 2
    return p


class LKHTree:
    """对称密钥逻辑密钥层次（LKH）二叉树；Gateway 作可信 KDC。"""

    def __init__(self, capacity: int, epoch: int = 0) -> None:
        assert is_pow2(capacity), "capacity 必须是 2 的幂"
        self.capacity = capacity
        self.depth = int(math.log2(capacity))
        self.epoch = epoch
        self.keys: Dict[int, bytes] = {}                 # node_index -> key
        self.members: Dict[int, int] = {}                 # leaf_index -> member_id
        self.views: Dict[int, Dict[int, bytes]] = {}      # member_id -> {node_index: key}

    # ----- 索引辅助 -----
    def _leaf_index(self, pos: int) -> int:
        return self.capacity + pos

    def _ancestors(self, leaf: int) -> List[int]:
        """从叶子的父节点直到根（自底向上）。"""
        out = []
        v = leaf // 2
        while v >= 1:
            out.append(v)
            v //= 2
        return out

    def _is_ancestor(self, v: int, leaf: int) -> bool:
        x = leaf
        while x > v:
            x //= 2
        return x == v

    def _members_under(self, node: int) -> List[int]:
        return [li for li in self.members if self._is_ancestor(node, li)]

    def _has_member(self, node: int) -> bool:
        return any(self._is_ancestor(node, li) for li in self.members)

    def _leaf_key(self, session_key: bytes) -> bytes:
        return hkdf_sha256(session_key, salt=str(self.epoch).encode(), info=b"leaf", length=32)

    def group_key(self) -> bytes:
        return self.keys.get(1, b"")

    # ----- 路径重随机化（join/leave 复用）-----
    def _rekey_path(self, leaf: int) -> Tuple[int, int]:
        """对 leaf 到根路径上的全部祖先节点重新随机化，并广播给各子树。"""
        updated = 0
        messages = 0
        for v in self._ancestors(leaf):
            self.keys[v] = os.urandom(32)          # 注入新随机：重随机化
            updated += 1
            for child in (2 * v, 2 * v + 1):
                recipients = self._members_under(child)
                if recipients:                      # 一条密文（在子节点密钥下加密）服务整个子树
                    messages += 1
                    for li in recipients:
                        self.views[self.members[li]][v] = self.keys[v]
        return updated, messages

    # ----- 初始化 -----
    def build(self, session_keys: List[bytes]) -> Tuple[int, int]:
        """用 n 个成员的 session_key 建树。返回 (updated_nodes, broadcast_messages)。"""
        n = len(session_keys)
        assert n <= self.capacity
        self.keys.clear()
        self.members.clear()
        self.views.clear()
        for pos, sk in enumerate(session_keys):
            li = self._leaf_index(pos)
            self.members[li] = pos
            self.keys[li] = self._leaf_key(sk)
            self.views[pos] = {li: self.keys[li]}

        updated = 0
        messages = 0
        for node in range(self.capacity - 1, 0, -1):     # 内部节点 1..capacity-1，自底向上
            if not self._has_member(node):
                continue
            self.keys[node] = os.urandom(32)
            updated += 1
            for child in (2 * node, 2 * node + 1):
                recipients = self._members_under(child)
                if recipients:
                    messages += 1
                    for li in recipients:
                        self.views[self.members[li]][node] = self.keys[node]
        return updated, messages

    # ----- 成员加入 -----
    def join(self, pos: int, session_key: bytes, member_id: int) -> Tuple[int, int]:
        li = self._leaf_index(pos)
        assert li not in self.members, "该叶子已被占用"
        self.members[li] = member_id
        self.keys[li] = self._leaf_key(session_key)
        self.views[member_id] = {li: self.keys[li]}
        return self._rekey_path(li)                       # 重随机化路径：新成员拿不到旧群钥（后向安全）

    # ----- 成员离开 -----
    def leave(self, pos: int) -> Tuple[int, int, int]:
        """逐出 pos 处成员。返回 (updated_nodes, broadcast_messages, evicted_member_id)。"""
        li = self._leaf_index(pos)
        evicted_id = self.members.pop(li)
        if li in self.keys:
            del self.keys[li]
        # 注意：保留 views[evicted_id]（其仍持有旧密钥，但下面不再向其分发新密钥）
        updated, messages = self._rekey_path(li)          # 路径重随机化：离开者算不出新群钥
        return updated, messages, evicted_id

    # ----- 正确性校验 -----
    def all_members_consistent(self) -> bool:
        """所有当前合法成员都应算出与 KDC 相同的 group_key。"""
        gk = self.group_key()
        return all(self.views[mid].get(1) == gk for mid in self.members.values())

    def member_cannot_compute(self, member_id: int) -> bool:
        """（用于离开者）该成员手中的根密钥应不等于当前 group_key。"""
        return self.views.get(member_id, {}).get(1) != self.group_key()


# --------------------------------------------------------------------------- #
# 实验 6.4：动态群组密钥迁移分析
# --------------------------------------------------------------------------- #
def run_group_experiment(host: str = "127.0.0.1",
                         ns=(8, 16, 32, 64),
                         modes=("legacy", "hybrid", "pq-only")) -> List[Dict]:
    """
    对每个 (n, mode) 测量 group_init / member_join / member_leave 的
    时间、更新节点数、广播消息数与正确性。成员 pairwise session key 由任务二握手得到。
      - group_init  时间含 n 次握手（故随模式变化）；
      - member_join 时间含 1 次新成员握手；
      - member_leave 为纯对称树操作（与模式无关）。
    """
    import time

    import negotiation as neg
    from protocol import GatewayServer, client_handshake

    server = GatewayServer(host, 0, neg.ALL_MODES).start()
    gport = server.port

    def handshake_key(mode: str) -> bytes:
        r = client_handshake(host, gport, mode, neg.ALL_MODES)
        try:
            server.results.get(timeout=5)
        except Exception:
            pass
        return r["session_key"]

    rows: List[Dict] = []
    try:
        for n in ns:
            for mode in modes:
                # --- group_init（含 n 次握手）---
                t0 = time.perf_counter()
                keys = [handshake_key(mode) for _ in range(n)]
                tree = LKHTree(n)
                u, m = tree.build(keys)
                t_init = (time.perf_counter() - t0) * 1000.0
                rows.append(dict(n=n, mode=mode, op="group_init", time_ms=t_init,
                                 updated=u, msgs=m, correct=tree.all_members_consistent()))

                # --- member_join（容量 2n，含 1 次握手）---
                jt = LKHTree(2 * n)
                jt.build(keys)
                t0 = time.perf_counter()
                nk = handshake_key(mode)
                u, m = jt.join(n, nk, member_id=n)
                t_join = (time.perf_counter() - t0) * 1000.0
                rows.append(dict(n=n, mode=mode, op="member_join", time_ms=t_join,
                                 updated=u, msgs=m, correct=jt.all_members_consistent()))

                # --- member_leave（满树，无握手）---
                lt = LKHTree(n)
                lt.build(keys)
                t0 = time.perf_counter()
                u, m, ev = lt.leave(0)
                t_leave = (time.perf_counter() - t0) * 1000.0
                ok = lt.all_members_consistent() and lt.member_cannot_compute(ev)
                rows.append(dict(n=n, mode=mode, op="member_leave", time_ms=t_leave,
                                 updated=u, msgs=m, correct=ok))
    finally:
        server.stop()
    return rows


def print_group_report(rows: List[Dict]) -> None:
    print("=" * 78)
    print("实验四：动态群组密钥迁移分析（任务五，选做；对称 LKH 密钥树）")
    print("=" * 78)
    hdr = (f"{'n':<5}{'mode':<9}{'operation':<14}{'time_ms':>10}"
           f"{'updated_nodes':>15}{'broadcast_msgs':>16}{'correct':>9}")
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        print(f"{r['n']:<5}{r['mode']:<9}{r['op']:<14}{r['time_ms']:>10.3f}"
              f"{r['updated']:>15}{r['msgs']:>16}{str(r['correct']):>9}")
    print()

    # 对数增长小结（取 hybrid 模式的 join/leave 更新节点数随 n 的变化）
    print("更新节点数随群组规模的增长（hybrid 模式）：")
    for op in ("group_init", "member_join", "member_leave"):
        seq = [(r["n"], r["updated"]) for r in rows if r["op"] == op and r["mode"] == "hybrid"]
        desc = "  ".join(f"n={n}:{u}" for n, u in seq)
        tag = "≈ n-1（线性）" if op == "group_init" else "≈ log2(n)（对数）"
        print(f"  {op:<14}: {desc}    {tag}")
    print()
    all_ok = all(r["correct"] for r in rows)
    print(f"正确性：所有合法成员 group_key 一致、且离开成员无法计算新 group_key —— {'全部通过' if all_ok else '存在失败！'}")
    print("结论：member_join / member_leave 的更新节点数与广播消息数随 n 呈对数级增长，")
    print("      而 group_init 呈线性；印证二叉密钥树把 rekey 开销从 O(n) 降到 O(log n)。")
    print()


if __name__ == "__main__":
    # 单元自检
    import secrets
    keys = [secrets.token_bytes(32) for _ in range(8)]
    t = LKHTree(8)
    u, m = t.build(keys)
    print(f"build n=8: updated={u} messages={m} consistent={t.all_members_consistent()}")
    u, m, ev = t.leave(3)
    print(f"leave pos=3: updated={u} messages={m} "
          f"consistent={t.all_members_consistent()} evicted_cannot={t.member_cannot_compute(ev)}")
    u, m = t.join(3, secrets.token_bytes(32), 99)
    print(f"join pos=3: updated={u} messages={m} consistent={t.all_members_consistent()}")
    print()
    print_group_report(run_group_experiment())
