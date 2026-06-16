"""
messages.py
===========
四种握手消息的 dataclass + 确定性序列化 / 反序列化。

字段顺序固定、不得删减；每个字段按 crypto_utils 的“长度前缀”规则编码，
保证双方对同一消息算出的字节完全一致（否则 transcript hash 对不上）。

消息类型字节（每条消息 serialize() 的首字段）用于反序列化时分发。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from crypto_utils import Reader, w_bytes, w_str, w_str_list

# 消息类型标识
MSG_CLIENT_HELLO = "ClientHello"
MSG_GATEWAY_HELLO = "GatewayHello"
MSG_CLIENT_FINISHED = "ClientFinished"
MSG_GATEWAY_FINISHED = "GatewayFinished"


@dataclass
class ClientHello:
    client_id: str
    client_nonce: bytes
    supported_algorithms: List[str]
    client_dh_public_key: bytes
    client_pq_public_key: bytes
    client_version: str

    def serialize(self) -> bytes:
        return (
            w_str(MSG_CLIENT_HELLO)
            + w_str(self.client_id)
            + w_bytes(self.client_nonce)
            + w_str_list(self.supported_algorithms)
            + w_bytes(self.client_dh_public_key)
            + w_bytes(self.client_pq_public_key)
            + w_str(self.client_version)
        )

    @staticmethod
    def deserialize(data: bytes) -> "ClientHello":
        r = Reader(data)
        assert r.r_str() == MSG_CLIENT_HELLO, "消息类型不匹配"
        return ClientHello(
            client_id=r.r_str(),
            client_nonce=r.r_bytes(),
            supported_algorithms=r.r_str_list(),
            client_dh_public_key=r.r_bytes(),
            client_pq_public_key=r.r_bytes(),
            client_version=r.r_str(),
        )


@dataclass
class GatewayHello:
    gateway_id: str
    gateway_nonce: bytes
    selected_mode: str
    selected_algorithms: List[str]
    gateway_dh_public_key: bytes
    pq_ciphertext: bytes
    downgrade_protection_field: bytes
    gateway_authenticator: bytes

    def serialize(self) -> bytes:
        return (
            w_str(MSG_GATEWAY_HELLO)
            + w_str(self.gateway_id)
            + w_bytes(self.gateway_nonce)
            + w_str(self.selected_mode)
            + w_str_list(self.selected_algorithms)
            + w_bytes(self.gateway_dh_public_key)
            + w_bytes(self.pq_ciphertext)
            + w_bytes(self.downgrade_protection_field)
            + w_bytes(self.gateway_authenticator)
        )

    @staticmethod
    def deserialize(data: bytes) -> "GatewayHello":
        r = Reader(data)
        assert r.r_str() == MSG_GATEWAY_HELLO, "消息类型不匹配"
        return GatewayHello(
            gateway_id=r.r_str(),
            gateway_nonce=r.r_bytes(),
            selected_mode=r.r_str(),
            selected_algorithms=r.r_str_list(),
            gateway_dh_public_key=r.r_bytes(),
            pq_ciphertext=r.r_bytes(),
            downgrade_protection_field=r.r_bytes(),
            gateway_authenticator=r.r_bytes(),
        )


@dataclass
class ClientFinished:
    transcript_hash: bytes
    client_finished_mac: bytes

    def serialize(self) -> bytes:
        return (
            w_str(MSG_CLIENT_FINISHED)
            + w_bytes(self.transcript_hash)
            + w_bytes(self.client_finished_mac)
        )

    @staticmethod
    def deserialize(data: bytes) -> "ClientFinished":
        r = Reader(data)
        assert r.r_str() == MSG_CLIENT_FINISHED, "消息类型不匹配"
        return ClientFinished(
            transcript_hash=r.r_bytes(),
            client_finished_mac=r.r_bytes(),
        )


@dataclass
class GatewayFinished:
    transcript_hash: bytes
    gateway_finished_mac: bytes

    def serialize(self) -> bytes:
        return (
            w_str(MSG_GATEWAY_FINISHED)
            + w_bytes(self.transcript_hash)
            + w_bytes(self.gateway_finished_mac)
        )

    @staticmethod
    def deserialize(data: bytes) -> "GatewayFinished":
        r = Reader(data)
        assert r.r_str() == MSG_GATEWAY_FINISHED, "消息类型不匹配"
        return GatewayFinished(
            transcript_hash=r.r_bytes(),
            gateway_finished_mac=r.r_bytes(),
        )
