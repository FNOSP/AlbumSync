#!/usr/bin/env python3
"""凭据备份包单元测试（0.3.0：打包 / 口令加密 / 解包 / API 导入导出）。

运行：PYTHONPATH=app/server python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import base64
import io
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent.parent / "app" / "server"
sys.path.insert(0, str(SERVER_DIR))

import backup as backup_pkg  # noqa: E402
from scheduler import SchedulerManager  # noqa: E402

PASS = "correct-horse-9"


def _account(acc_id: str = "acc-huawei-abc123", password: str = "pw-secret") -> dict:
    return {
        "id": acc_id,
        "platform": "huawei",
        "name": "主号",
        "username": "13800000000",
        "password": password,
        "password_enc": {"v": 1, "payload": "should-not-be-exported"},
        "photos_dir": "/tmp/photos",
        "albums": ["相机"],
    }


class TestArchive(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-bak-"))
        self.acc_dir = self.tmp / "accounts" / "acc-huawei-abc123"
        self.acc_dir.mkdir(parents=True)
        (self.acc_dir / "auth.json").write_text('{"cookie": "x"}', encoding="utf-8")
        (self.acc_dir / "cas_state.json").write_text("{}", encoding="utf-8")
        (self.acc_dir / "state.db").write_bytes(b"sqlite")  # 不应被备份

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _build(self, **kw):
        params = dict(
            pkgvar=self.tmp,
            settings={"timezone": "Asia/Shanghai", "backup_dir": "/vol1/backups"},
            accounts=[_account()],
            app_version="0.3.0",
            include_passwords=True,
            include_sessions=True,
        )
        params.update(kw)
        return backup_pkg.build_archive(**params)

    def test_roundtrip_with_passwords_and_sessions(self):
        archive, manifest = self._build()
        self.assertTrue(manifest["flags"]["include_passwords"])
        self.assertEqual(manifest["accounts"][0]["id"], "acc-huawei-abc123")
        self.assertTrue(manifest["accounts"][0]["has_password"])
        self.assertTrue(manifest["accounts"][0]["has_sessions"])

        blob = backup_pkg.seal_container(archive, PASS, manifest)
        header = backup_pkg.read_header(blob)
        self.assertEqual(header["schema"], backup_pkg.BACKUP_SCHEMA)
        # 明文头不含任何凭据值
        text = json.dumps(header, ensure_ascii=False)
        self.assertNotIn("pw-secret", text)

        header2, decrypted = backup_pkg.open_container(blob, PASS)
        self.assertEqual(header2["kdf"]["alg"], "scrypt")
        files = backup_pkg.parse_archive(decrypted)

        cfg = backup_pkg.load_config_from_archive(files)
        self.assertEqual(len(cfg["accounts"]), 1)
        self.assertNotIn("password", cfg["accounts"][0])
        self.assertNotIn("password_enc", cfg["accounts"][0])
        self.assertNotIn("backup_dir", cfg["settings"])  # 目标机目录不可复用

        self.assertEqual(backup_pkg.load_secrets_from_archive(files),
                         {"acc-huawei-abc123": "pw-secret"})
        sessions = backup_pkg.collect_session_files(files, "acc-huawei-abc123")
        self.assertEqual(set(sessions), {"auth.json", "cas_state.json"})
        self.assertNotIn("accounts/acc-huawei-abc123/state.db", files)

    def test_without_passwords(self):
        archive, manifest = self._build(include_passwords=False)
        blob = backup_pkg.seal_container(archive, PASS, manifest)
        _h, decrypted = backup_pkg.open_container(blob, PASS)
        files = backup_pkg.parse_archive(decrypted)
        self.assertNotIn("secrets.json", files)
        self.assertEqual(backup_pkg.load_secrets_from_archive(files), {})
        self.assertNotIn(b"pw-secret", decrypted)

    def test_without_sessions(self):
        archive, _m = self._build(include_sessions=False)
        blob = backup_pkg.seal_container(archive, PASS, _m)
        _h, decrypted = backup_pkg.open_container(blob, PASS)
        files = backup_pkg.parse_archive(decrypted)
        self.assertEqual(backup_pkg.collect_session_files(files, "acc-huawei-abc123"), {})

    def test_account_filter(self):
        with self.assertRaises(backup_pkg.BackupError):
            self._build(accounts=[_account()], account_ids=["acc-missing"])

    def test_short_passphrase_rejected(self):
        archive, manifest = self._build()
        with self.assertRaises(backup_pkg.BackupError):
            backup_pkg.seal_container(archive, "short", manifest)

    def test_wrong_passphrase(self):
        archive, manifest = self._build()
        blob = backup_pkg.seal_container(archive, PASS, manifest)
        with self.assertRaises(backup_pkg.BackupError):
            backup_pkg.open_container(blob, "wrong-passphrase")

    def test_tampered_payload_rejected(self):
        archive, manifest = self._build()
        blob = bytearray(backup_pkg.seal_container(archive, PASS, manifest))
        blob[-1] ^= 0xFF
        with self.assertRaises(backup_pkg.BackupError):
            backup_pkg.open_container(bytes(blob), PASS)

    def test_not_a_backup_file(self):
        with self.assertRaises(backup_pkg.BackupError):
            backup_pkg.read_header(b"not-a-backup")

    def test_schema_too_new_rejected(self):
        header = json.dumps({"schema": backup_pkg.BACKUP_SCHEMA + 1}).encode("utf-8")
        blob = backup_pkg.BACKUP_MAGIC + len(header).to_bytes(4, "big") + header + b"\x00" * 16
        with self.assertRaises(backup_pkg.BackupError):
            backup_pkg.open_container(blob, PASS)

    def test_archive_path_traversal_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../evil.txt", b"x")
        with self.assertRaises(backup_pkg.BackupError):
            backup_pkg.parse_archive(buf.getvalue())

    def test_missing_config_rejected(self):
        with self.assertRaises(backup_pkg.BackupError):
            backup_pkg.load_config_from_archive({})


class TestBackupApi(unittest.TestCase):
    """SchedulerManager 的导出 → 预览 → 导入全链路（配置全程无明文密码）。"""

    def setUp(self) -> None:
        self.src = Path(tempfile.mkdtemp(prefix="albumsync-bak-src-"))
        self.dst = Path(tempfile.mkdtemp(prefix="albumsync-bak-dst-"))
        self.src_mgr = SchedulerManager(self.src)
        self.dst_mgr = SchedulerManager(self.dst)
        result = self.src_mgr.create_account({
            "name": "主号", "username": "13800000000", "password": "pw-secret",
            "platform": "huawei",
        })
        assert result["status"] == "ok", result
        self.acc_id = result["account"]["id"]
        acc_dir = self.src / "accounts" / self.acc_id
        acc_dir.mkdir(parents=True, exist_ok=True)
        (acc_dir / "auth.json").write_text('{"cookie": "session"}', encoding="utf-8")

    def tearDown(self) -> None:
        self.src_mgr.stop()
        self.dst_mgr.stop()
        shutil.rmtree(self.src, ignore_errors=True)
        shutil.rmtree(self.dst, ignore_errors=True)

    def test_export_inspect_import(self):
        exported = self.src_mgr.export_backup({
            "passphrase": PASS, "include_passwords": True, "include_sessions": True,
        })
        self.assertEqual(exported["status"], "ok", exported)
        path = Path(exported["file"])
        self.assertTrue(path.is_file())
        self.assertEqual(path.parent, self.src / "backups")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        blob = path.read_bytes()
        self.assertNotIn(b"pw-secret", blob)
        self.assertEqual(len(base64.b64decode(exported["data_b64"])), len(blob))

        listed = self.src_mgr.list_backups()
        self.assertEqual(listed["directory"], str(self.src / "backups"))
        self.assertEqual([f["name"] for f in listed["files"]], [path.name])

        data_b64 = exported["data_b64"]
        preview = self.dst_mgr.inspect_backup({"data_b64": data_b64, "passphrase": PASS})
        self.assertEqual(preview["status"], "ok", preview)
        item = preview["accounts"][0]
        self.assertEqual(item["id"], self.acc_id)
        self.assertTrue(item["has_password"])
        self.assertFalse(item["conflict"])
        self.assertEqual(item["sessions"], ["auth.json"])

        bad = self.dst_mgr.inspect_backup({"data_b64": data_b64, "passphrase": "wrong-pass"})
        self.assertEqual(bad["status"], "error")

        imported = self.dst_mgr.import_backup({
            "data_b64": "data:application/octet-stream;base64," + data_b64,
            "passphrase": PASS, "mode": "merge",
        })
        self.assertEqual(imported["status"], "ok", imported)
        self.assertEqual(imported["accounts"], [self.acc_id])

        raw_text = (self.dst / "config.json").read_text(encoding="utf-8")
        self.assertNotIn("pw-secret", raw_text)
        raw = json.loads(raw_text)
        self.assertIsNotNone(raw["accounts"][0]["password_enc"])
        cfg = self.dst_mgr.app_config.load()
        self.assertEqual(cfg["accounts"][0]["password"], "pw-secret")
        self.assertTrue((self.dst / "accounts" / self.acc_id / "auth.json").is_file())

    def test_export_short_passphrase_rejected(self):
        result = self.src_mgr.export_backup({"passphrase": "short"})
        self.assertEqual(result["status"], "error")

    def test_import_invalid_blob(self):
        self.assertEqual(self.dst_mgr.import_backup({})["status"], "error")
        self.assertEqual(self.dst_mgr.inspect_backup({"data_b64": "not-base64!"})["status"], "error")

    def test_backup_dir_setting(self):
        target = self.dst / "custom-backups"
        r = self.dst_mgr.save_settings({"backup_dir": str(target)})
        self.assertEqual(r["status"], "ok", r)
        created = self.dst_mgr.create_account({"name": "目标机账号"})
        self.assertEqual(created["status"], "ok", created)
        exported = self.dst_mgr.export_backup({"passphrase": PASS})
        self.assertEqual(exported["status"], "ok", exported)
        self.assertEqual(Path(exported["file"]).parent, target)


if __name__ == "__main__":
    unittest.main()
