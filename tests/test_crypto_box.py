#!/usr/bin/env python3
"""crypto_box 单元测试：RFC 8439 官方向量 + 篡改检测 + 机器密钥。

运行：PYTHONPATH=app/server python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent.parent / "app" / "server"
sys.path.insert(0, str(SERVER_DIR))

import crypto_box as cb  # noqa: E402


class Poly1305VectorTest(unittest.TestCase):
    """RFC 8439 §2.5.2 官方测试向量。"""

    def test_rfc8439_poly1305(self) -> None:
        key = bytes.fromhex(
            "85d6be7857556d337f4452fe42d506a8"
            "0103808afb0db2fd4abff6af4149f51b"
        )
        message = b"Cryptographic Forum Research Group"
        expected = bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")
        self.assertEqual(cb._poly1305_tag(key, message), expected)


class AeadVectorTest(unittest.TestCase):
    """RFC 8439 §2.8.2 官方 AEAD 测试向量。"""

    def test_rfc8439_aead_seal_and_open(self) -> None:
        key = bytes(range(0x80, 0xA0))
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        plaintext = (
            b"Ladies and Gentlemen of the class of '99: If I could offer you "
            b"only one tip for the future, sunscreen would be it."
        )
        expected_ct = bytes.fromhex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b6116"
        )
        expected_tag = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")

        blob = cb.aead_seal(key, plaintext, aad=aad, nonce=nonce)
        self.assertEqual(blob[:12], nonce)
        self.assertEqual(blob[12:-16], expected_ct)
        self.assertEqual(blob[-16:], expected_tag)
        self.assertEqual(cb.aead_open(key, blob, aad=aad), plaintext)


class AeadSafetyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.key = bytes(range(32))
        self.nonce = bytes(12)
        self.blob = cb.aead_seal(self.key, b"secret", aad=b"acc-1", nonce=self.nonce)

    def test_tampered_ciphertext_rejected(self) -> None:
        broken = bytearray(self.blob)
        broken[13] ^= 0x01
        with self.assertRaises(cb.CryptoError):
            cb.aead_open(self.key, bytes(broken), aad=b"acc-1")

    def test_tampered_tag_rejected(self) -> None:
        broken = bytearray(self.blob)
        broken[-1] ^= 0x01
        with self.assertRaises(cb.CryptoError):
            cb.aead_open(self.key, bytes(broken), aad=b"acc-1")

    def test_wrong_aad_rejected(self) -> None:
        with self.assertRaises(cb.CryptoError):
            cb.aead_open(self.key, self.blob, aad=b"acc-2")

    def test_wrong_key_rejected(self) -> None:
        with self.assertRaises(cb.CryptoError):
            cb.aead_open(bytes(range(1, 33)), self.blob, aad=b"acc-1")

    def test_truncated_rejected(self) -> None:
        with self.assertRaises(cb.CryptoError):
            cb.aead_open(self.key, self.blob[:20], aad=b"acc-1")

    def test_empty_plaintext_roundtrip(self) -> None:
        blob = cb.aead_seal(self.key, b"", nonce=self.nonce)
        self.assertEqual(cb.aead_open(self.key, blob), b"")


class EnvelopeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.key = bytes(range(32))

    def test_roundtrip_with_aad(self) -> None:
        env = cb.seal_text(self.key, "p@ssw0rd", aad="albumsync:password:acc-hw-0")
        self.assertEqual(env["v"], 1)
        self.assertNotIn("p@ssw0rd", str(env))
        self.assertEqual(
            cb.open_text(self.key, env), "p@ssw0rd"
        )

    def test_aad_binding_blocks_account_swap(self) -> None:
        env = cb.seal_text(self.key, "p@ssw0rd", aad="albumsync:password:acc-a")
        env2 = dict(env)
        env2["aad"] = "albumsync:password:acc-b"
        with self.assertRaises(cb.CryptoError):
            cb.open_text(self.key, env2)

    def test_unsupported_version(self) -> None:
        env = {"v": 9, "aead": "chacha20poly1305", "payload": ""}
        with self.assertRaises(cb.CryptoError):
            cb.open_text(self.key, env)


class KeyFileTest(unittest.TestCase):
    def test_create_then_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "secret.key"
            first = cb.load_or_create_key(path)
            self.assertEqual(len(first), 32)
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
            self.assertEqual(cb.load_or_create_key(path), first)

    def test_corrupt_key_file_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "secret.key"
            path.write_bytes(b"short")
            with self.assertRaises(cb.CryptoError):
                cb.load_or_create_key(path)


class DeriveKeyTest(unittest.TestCase):
    def test_deterministic_with_same_salt(self) -> None:
        salt = b"0123456789abcdef"
        key1, _, params = cb.derive_key("correct horse", salt)
        key2, _, _ = cb.derive_key("correct horse", salt)
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)
        self.assertNotEqual(key1, cb.derive_key("wrong horse", salt)[0])
        self.assertEqual(params["n"], cb.SCRYPT_PARAMS["n"])

    def test_empty_passphrase_rejected(self) -> None:
        with self.assertRaises(cb.CryptoError):
            cb.derive_key("")


if __name__ == "__main__":
    unittest.main()
