"""
wire.py
=======
socket 帧协议：4 字节大端长度前缀 + payload。

提供 send_msg / recv_msg，并在收发处精确统计“应用层字节数（含帧头）”，
这是开销测量中“通信开销”的唯一口径。
"""

from __future__ import annotations

import socket

_LEN_PREFIX = 4  # 帧头字节数


def _recvall(sock: socket.socket, n: int) -> bytes:
    """从 socket 精确读取 n 字节；对端关闭则抛 ConnectionError。"""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("对端在读取过程中关闭了连接")
        buf.extend(chunk)
    return bytes(buf)


def send_msg(sock: socket.socket, payload: bytes) -> int:
    """
    发送一帧：4 字节大端长度前缀 + payload。
    返回本帧在 socket 上的总字节数（含帧头），供通信开销统计。
    """
    frame = len(payload).to_bytes(_LEN_PREFIX, "big") + payload
    sock.sendall(frame)
    return len(frame)


def recv_msg(sock: socket.socket) -> tuple[bytes, int]:
    """
    接收一帧。返回 (payload, 本帧总字节数含帧头)。
    """
    header = _recvall(sock, _LEN_PREFIX)
    length = int.from_bytes(header, "big")
    payload = _recvall(sock, length)
    return payload, _LEN_PREFIX + length
