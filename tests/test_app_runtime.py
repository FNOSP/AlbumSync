#!/usr/bin/env python3
"""AlbumSync 服务壳单元测试（app_runtime 层，不触网）。

运行：PYTHONPATH=app/server python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent.parent / "app" / "server"
sys.path.insert(0, str(SERVER_DIR))

import app_runtime  # noqa: E402
from app_runtime import AppConfig, AppRuntime, report_to_dict, validate_config  # noqa: E402


class TempHomeTest(unittest.TestCase):
    """每个用例独立的临时 PKGVAR。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-test-"))
        self.rt = AppRuntime(self.tmp)
        # 无凭据：daemon 不会触网，仅等待登录态

    def tearDown(self) -> None:
        self.rt.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestValidateConfig(unittest.TestCase):
    def test_valid_minimal(self):
        self.assertIsNone(validate_config({}))

    def test_invalid_cron(self):
        err = validate_config({"cron": "not a cron"})
        self.assertIsNotNone(err)
        self.assertIn("cron", err)

    def test_valid_cron_macros(self):
        for cron in ("0 3 * * *", "@daily", "*/10 * * * *"):
            self.assertIsNone(validate_config({"cron": cron}), cron)

    def test_invalid_timezone(self):
        self.assertIn("timezone", validate_config({"timezone": "Nowhere/Bad"}) or "")

    def test_invalid_photo_size(self):
        self.assertIsNotNone(validate_config({"photo_size": "huge"}))

    def test_relative_photos_dir(self):
        self.assertIn("绝对路径", validate_config({"photos_dir": "photos"}))

    def test_bad_date_format(self):
        self.assertIn("YYYY-MM-DD", validate_config({"created_after": "2026/01/01"}))

    def test_bad_webhook(self):
        self.assertIn("webhook_url", validate_config({"webhook_url": "ftp://x"}))

    def test_bad_albums(self):
        self.assertIsNotNone(validate_config({"albums": "photos"}))

    def test_concurrency_range(self):
        self.assertIsNotNone(validate_config({"download_concurrency": 99}))

    def test_custom_dirs_bad_type(self):
        self.assertIsNotNone(validate_config({"custom_photos_dirs": "photos"}))

    def test_custom_dirs_relative_rejected(self):
        self.assertIn("绝对路径",
                      validate_config({"custom_photos_dirs": ["/ok", "photos"]}))

    def test_custom_dirs_cleaned_in_place(self):
        data = {"custom_photos_dirs": ["/a", " /a ", "", "/b"]}
        self.assertIsNone(validate_config(data))
        self.assertEqual(data["custom_photos_dirs"], ["/a", "/b"])


class TestAppConfig(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-cfg-"))
        self.cfg = AppConfig(self.tmp / "config.json", self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_defaults_on_missing(self):
        data = self.cfg.load()
        self.assertEqual(data["timezone"], "Asia/Shanghai")
        self.assertEqual(data["photos_dir"], str(self.tmp / "photos"))

    def test_roundtrip(self):
        self.cfg.save({"username": "13800000000", "albums": ["相册A"], "cron": "30 2 * * *"})
        data = self.cfg.load()
        self.assertEqual(data["username"], "13800000000")
        self.assertEqual(data["albums"], ["相册A"])
        self.assertEqual(data["cron"], "30 2 * * *")

    def test_to_sync_config_mapping(self):
        self.cfg.save({
            "username": "u1", "password": "p1",
            "photos_dir": "/tmp/photos", "albums": ["A"], "exclude_albums": ["B"],
            "created_after": "2024-01-01", "created_before": "2024-12-31",
            "cron": "@daily", "timezone": "Asia/Shanghai",
        })
        cfg = self.cfg.to_sync_config()
        self.assertEqual(str(cfg.directory), "/tmp/photos")
        self.assertEqual(cfg.albums, ["A"])
        self.assertEqual(cfg.exclude_albums, ["B"])
        self.assertIsInstance(cfg.created_after_ms, int)
        self.assertIsInstance(cfg.created_before_ms, int)
        self.assertGreater(cfg.created_before_ms, cfg.created_after_ms)
        self.assertEqual(cfg.cron, "@daily")
        self.assertIsNone(cfg.two_fa_code)

    def test_to_sync_config_dry_run(self):
        cfg = self.cfg.to_sync_config(dry_run=True)
        self.assertTrue(cfg.dry_run)


class TestAppRuntime(TempHomeTest):
    def test_get_config_masks_password(self):
        result = self.rt.save_config({"username": "u1", "password": "secret"})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(self.rt.get_config()["password"], "******")
        # 真实密码仍保留在磁盘
        raw = (self.tmp / "config.json").read_text(encoding="utf-8")
        self.assertIn("secret", raw)

    def test_save_config_masked_post_keeps_password(self):
        self.rt.save_config({"username": "u1", "password": "secret"})
        self.rt.save_config({"password": "******", "username": "u2"})
        raw = (self.tmp / "config.json").read_text(encoding="utf-8")
        self.assertIn("secret", raw)
        self.assertIn("u2", raw)

    def test_save_config_clear_password(self):
        self.rt.save_config({"password": "secret"})
        self.rt.save_config({"password": "__clear__"})
        raw = (self.tmp / "config.json").read_text(encoding="utf-8")
        self.assertNotIn("secret", raw)

    def test_save_config_invalid_rejected(self):
        result = self.rt.save_config({"cron": "bad"})
        self.assertEqual(result["status"], "error")
        # 未写入
        self.assertFalse((self.tmp / "config.json").exists())

    def test_status_snapshot_keys(self):
        snap = self.rt.status_snapshot()
        for key in ("ok", "auth_valid", "last_report", "daemon_running", "uptime_sec",
                    "store_counts", "auth", "version", "app"):
            self.assertIn(key, snap)
        self.assertEqual(snap["app"], "AlbumSync")
        self.assertTrue(snap["daemon_running"])
        self.assertFalse(snap["auth"]["has_session"])

    def test_tail_logs(self):
        import logging
        logging.getLogger("test").warning("冒烟日志行")
        lines = self.rt.tail_logs(10)
        self.assertTrue(any("冒烟日志行" in l for l in lines))

    def test_dry_run_no_auth_fails(self):
        result = self.rt.start_dry_run()
        self.assertEqual(result["status"], "ok")
        deadline = time.time() + 10
        while time.time() < deadline:
            state = self.rt.dry_run_status()
            if not state["running"]:
                break
            time.sleep(0.2)
        self.assertFalse(self.rt.dry_run_status()["running"])
        self.assertIsNotNone(self.rt.dry_run_status()["error"])

    def test_import_curl_garbage(self):
        result = self.rt.import_curl("curl nonsense $$")
        self.assertEqual(result["status"], "error")

    def test_import_curl_empty(self):
        self.assertEqual(self.rt.import_curl("  ")["status"], "error")

    def test_submit_2fa_bad_format(self):
        self.assertEqual(self.rt.submit_2fa("12ab")["status"], "error")
        self.assertEqual(self.rt.submit_2fa("12345")["status"], "error")

    def test_trigger_sync_daemon_alive(self):
        result = self.rt.trigger_sync()
        self.assertEqual(result["status"], "ok")

    def test_add_custom_photos_dir(self):
        d = os.path.normpath(tempfile.mkdtemp(prefix="albumsync-custom-"))
        try:
            result = self.rt.add_custom_photos_dir(d)
            self.assertEqual(result["status"], "ok")
            self.assertIn(d, self.rt.get_config()["custom_photos_dirs"])
            # 重复登记去重（含尾斜杠归一）
            again = self.rt.add_custom_photos_dir(d + "/")
            self.assertEqual(again["status"], "ok")
            self.assertEqual(self.rt.get_config()["custom_photos_dirs"].count(d), 1)
            # 已登记路径 probe 标记 registered
            self.assertTrue(self.rt.probe_single_dir(d)["registered"])
            # 不存在 / 相对路径拒绝
            self.assertEqual(
                self.rt.add_custom_photos_dir(str(self.tmp / "no_such_dir"))["status"],
                "error")
            self.assertEqual(self.rt.add_custom_photos_dir("rel/path")["status"],
                             "error")
            # 登记不得固化 photos_dir 的默认回退语义（保持空值=回退 pkgvar/photos）
            self.assertEqual(self.rt.app_config.load()["photos_dir"],
                             str(self.tmp / "photos"))
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestReportToDict(unittest.TestCase):
    def test_fields(self):
        from hwcloudpd.models import SyncReport

        report = SyncReport()
        report.scanned = 10
        report.downloaded = 3
        report.failed = 1
        report.duration_sec = 1.234
        d = report_to_dict(report)
        self.assertEqual(d["scanned"], 10)
        self.assertEqual(d["downloaded"], 3)
        self.assertEqual(d["duration_sec"], 1.23)
        self.assertIn("summary_text", d)


if __name__ == "__main__":
    unittest.main()
