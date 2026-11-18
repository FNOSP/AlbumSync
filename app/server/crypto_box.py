"""纯标准库 AEAD（ChaCha20-Poly1305，RFC 8439）+ scrypt KDF。

引擎硬约束是「零第三方 Python 包」，而标准库没有 AES，因此采用
ChaCha20-Poly1305：算法短、规范明确、有官方测试向量可自证正确性
（见 tests/test_crypto_box.py）。

两类密钥用途：
- 本机静态加密（config.json 中的账号密码）：32 字节机器密钥 `secret.key`
  （chmod 600）直接作为 AEAD key，无 KDF，解密开销在微秒级；
- 导出包加密（.asbak）：用户口令经 scrypt 派生 32 字节 key。

注意：本模块只防「文件泄露」，不防能读数据目录的攻击者（机器密钥与密文同目录）。
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import struct
from typing import Any

__all__ = [
    "CryptoError",
    "aead_open",
    "aead_seal",
    "derive_key",
    "load_or_create_key",
    "seal_text",
    "open_text",
    "b64e",
    "b64d",
    "SCRYPT_PARAMS",
]

MASK32 = 0xFFFFFFFF
TAG_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32

# 导出包口令派生参数：约 100ms，仅在导出/导入时执行
SCRYPT_PARAMS = {"n": 32768, "r": 8, "p": 1, "dklen": KEY_LEN}


class CryptoError(Exception):
    """密文损坏、密钥不匹配或参数不支持。"""


# ---------- ChaCha20（RFC 8439 §2.3） ----------

def _rotl(value: int, shift: int) -> int:
    return ((value << shift) & MASK32) | (value >> (32 - shift))


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl(state[b] ^ state[c], 7)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    if len(key) != KEY_LEN:
        raise CryptoError("ChaCha20 key 必须为 32 字节")
    if len(nonce) != NONCE_LEN:
        raise CryptoError("ChaCha20 nonce 必须为 12 字节")
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key))
    state.append(counter & MASK32)
    state += list(struct.unpack("<3I", nonce))
    working = list(state)
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    out = [(working[i] + state[i]) & MASK32 for i in range(16)]
    return struct.pack("<16I", *out)


def _chacha20_xor(key: bytes, nonce: bytes, data: bytes, counter: int = 1) -> bytes:
    buf = bytearray(len(data))
    for offset in range(0, len(data), 64):
        block = _chacha20_block(key, counter + offset // 64, nonce)
        chunk = data[offset:offset + 64]
        for i, byte in enumerate(chunk):
            buf[offset + i] = byte ^ block[i]
    return bytes(buf)


# ---------- Poly1305（RFC 8439 §2.5） ----------

def _poly1305_tag(one_time_key: bytes, message: bytes) -> bytes:
    r = int.from_bytes(one_time_key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(one_time_key[16:32], "little")
    prime = (1 << 130) - 5
    acc = 0
    for offset in range(0, len(message), 16):
        chunk = message[offset:offset + 16]
        acc = ((acc + int.from_bytes(chunk + b"\x01", "little")) * r) % prime
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    return b"" if len(data) % 16 == 0 else b"\x00" * (16 - len(data) % 16)


# ---------- AEAD 封装 ----------
# 输出格式：nonce(12) || ciphertext || tag(16)

def aead_seal(key: bytes, plaintext: bytes, *, aad: bytes = b"",
              nonce: bytes | None = None) -> bytes:
    if len(key) != KEY_LEN:
        raise CryptoError("AEAD key 必须为 32 字节")
    nonce = nonce or secrets.token_bytes(NONCE_LEN)
    if len(nonce) != NONCE_LEN:
        raise CryptoError("AEAD nonce 必须为 12 字节")
    one_time_key = _chacha20_block(key, 0, nonce)[:32]
    ciphertext = _chacha20_xor(key, nonce, plaintext, counter=1)
    mac_data = (
        aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
        + struct.pack("<QQ", len(aad), len(ciphertext))
    )
    return nonce + ciphertext + _poly1305_tag(one_time_key, mac_data)


def aead_open(key: bytes, blob: bytes, *, aad: bytes = b"") -> bytes:
    if len(key) != KEY_LEN:
        raise CryptoError("AEAD key 必须为 32 字节")
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise CryptoError("密文长度不足")
    nonce, ciphertext, tag = blob[:NONCE_LEN], blob[NONCE_LEN:-TAG_LEN], blob[-TAG_LEN:]
    one_time_key = _chacha20_block(key, 0, nonce)[:32]
    mac_data = (
        aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
        + struct.pack("<QQ", len(aad), len(ciphertext))
    )
    if not secrets.compare_digest(_poly1305_tag(one_time_key, mac_data), tag):
        raise CryptoError("校验失败：密文被篡改或口令/密钥不匹配")
    return _chacha20_xor(key, nonce, ciphertext, counter=1)


# ---------- KDF / 编码 ----------

def derive_key(passphrase: str, salt: bytes | None = None,
               params: dict[str, int] | None = None) -> tuple[bytes, bytes, dict[str, int]]:
    """口令 → scrypt 派生 key；返回 (key, salt, 实际参数)。"""
    if not passphrase:
        raise CryptoError("口令不能为空")
    params = dict(params or SCRYPT_PARAMS)
    salt = salt or secrets.token_bytes(16)
    key = hashlib.scrypt(
        passphrase.encode("utf-8"), salt=salt,
        n=int(params["n"]), r=int(params["r"]), p=int(params["p"]),
        dklen=int(params["dklen"]), maxmem=128 * 1024 * 1024,
    )
    return key, salt, params


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:
        raise CryptoError(f"base64 解码失败: {exc}") from exc


def load_or_create_key(path) -> bytes:
    """读取或生成 32 字节机器密钥（原子创建 + chmod 600）。"""
    path = str(path)
    try:
        with open(path, "rb") as fh:
            key = fh.read()
    except FileNotFoundError:
        key = b""
    if len(key) == KEY_LEN:
        return key
    if key:
        raise CryptoError(f"密钥文件长度异常（{len(key)} 字节），请检查 {path}")
    key = secrets.token_bytes(KEY_LEN)
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


# ---------- 文本信封（config.json 中的 password_enc） ----------

def seal_text(key: bytes, text: str, *, aad: str = "") -> dict[str, Any]:
    blob = aead_seal(key, text.encode("utf-8"), aad=aad.encode("utf-8"))
    return {
        "v": 1,
        "aead": "chacha20poly1305",
        "aad": aad,
        "payload": b64e(blob),
    }


def open_text(key: bytes, envelope: dict[str, Any]) -> str:
    if not isinstance(envelope, dict):
        raise CryptoError("密文信封格式错误")
    if int(envelope.get("v") or 0) != 1:
        raise CryptoError(f"不支持的密文版本: {envelope.get('v')}")
    if envelope.get("aead") != "chacha20poly1305":
        raise CryptoError(f"不支持的算法: {envelope.get('aead')}")
    aad = str(envelope.get("aad") or "")
    blob = b64d(str(envelope.get("payload") or ""))
    return aead_open(key, blob, aad=aad.encode("utf-8")).decode("utf-8")
