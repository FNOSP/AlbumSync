#!/usr/bin/env python3
"""AlbumSync 服务壳单元测试（多账号运行时层，不触网）。

运行：PYTHONPATH=app/server python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

SERVER_DIR = Path(__file__).resolve().parent.parent / "app" / "server"
sys.path.insert(0, str(SERVER_DIR))

import app_runtime  # noqa: E402
from app_runtime import (  # noqa: E402
    AccountRuntime,
    AppConfig,
    ConfigMigrationError,
    DEFAULT_ACCOUNT,
    DEFAULT_SETTINGS,
    _SerialSyncGate,
    generate_account_id,
    migrate_config_v1_to_v2,
    report_to_dict,
    sanitize_account_name,
    validate_account,
    validate_settings,
)
from scheduler import SchedulerManager  # noqa: E402


# ---------- 校验拆分 ----------

class TestValidateSettings(unittest.TestCase):
    def test_valid_minimal(self):
        self.assertIsNone(validate_settings({}))

    def test_invalid_timezone(self):
        self.assertIn("timezone", validate_settings({"timezone": "Nowhere/Bad"}) or "")

    def test_invalid_log_level(self):
        self.assertIsNotNone(validate_settings({"log_level": "TRACE"}))

    def test_custom_dirs_bad_type(self):
        self.assertIsNotNone(validate_settings({"custom_photos_dirs": "photos"}))

    def test_custom_dirs_relative_rejected(self):
        self.assertIn("绝对路径",
                      validate_settings({"custom_photos_dirs": ["/ok", "photos"]}))

    def test_custom_dirs_cleaned_in_place(self):
        data = {"custom_photos_dirs": ["/a", " /a ", "", "/b/"]}
        self.assertIsNone(validate_settings(data))
        self.assertEqual(data["custom_photos_dirs"],
                         [os.path.normpath("/a"), os.path.normpath("/b/")])


class TestValidateAccount(unittest.TestCase):
    def test_valid_minimal(self):
        self.assertIsNone(validate_account({}))

    def test_invalid_cron(self):
        err = validate_account({"cron": "not a cron"})
        self.assertIsNotNone(err)
        self.assertIn("cron", err)

    def test_valid_cron_macros(self):
        for cron in ("0 3 * * *", "@daily", "*/10 * * * *"):
            self.assertIsNone(validate_account({"cron": cron}), cron)

    def test_invalid_photo_size(self):
        self.assertIsNotNone(validate_account({"photo_size": "huge"}))

    def test_relative_photos_dir(self):
        self.assertIn("绝对路径", validate_account({"photos_dir": "photos"}))

    def test_bad_date_format(self):
        self.assertIn("YYYY-MM-DD", validate_account({"created_after": "2026/01/01"}))

    def test_bad_webhook(self):
        self.assertIn("webhook_url", validate_account({"webhook_url": "ftp://x"}))

    def test_bad_albums(self):
        self.assertIsNotNone(validate_account({"albums": "photos"}))

    def test_concurrency_range(self):
        self.assertIsNotNone(validate_account({"download_concurrency": 99}))

    def test_enabled_bool(self):
        self.assertIsNotNone(validate_account({"enabled": "yes"}))

    def test_owner_validation(self):
        # 合法：空 / 任意字符串 id
        self.assertIsNone(validate_account({"owner": ""}))
        self.assertIsNone(validate_account({"owner": "1000"}))
        # 类型：非字符串拒绝
        self.assertIsNotNone(validate_account({"owner": 123}))
        # 限长 128
        self.assertIsNotNone(validate_account({"owner": "x" * 129}))
        self.assertIsNone(validate_account({"owner": "x" * 128}))


class TestGenerateAccountId(unittest.TestCase):
    def test_shape_and_uniqueness(self):
        existing = set()
        for _ in range(20):
            aid = generate_account_id("huawei", existing)
            self.assertRegex(aid, r"^acc-huawei-[0-9a-f]{6}$")
            existing.add(aid)


# ---------- AppConfig v2 ----------

class TestAppConfig(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-cfg-"))
        self.cfg = AppConfig(self.tmp / "config.json", self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_defaults_on_missing(self):
        data = self.cfg.load()
        self.assertEqual(data["version"], app_runtime.CONFIG_VERSION)
        self.assertEqual(data["settings"]["timezone"], "Asia/Shanghai")
        self.assertEqual(data["accounts"], [])

    def test_v2_roundtrip(self):
        account = dict(DEFAULT_ACCOUNT)
        account.update({"id": "acc-huawei-abc123", "name": "主号",
                        "username": "13800000000", "albums": ["相册A"],
                        "cron": "30 2 * * *"})
        self.cfg.save({"timezone": "Asia/Shanghai", "log_level": "DEBUG",
                       "custom_photos_dirs": []}, [account])
        raw = json.loads((self.tmp / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(raw["version"], app_runtime.CONFIG_VERSION)
        self.assertIn("settings", raw)
        self.assertIn("accounts", raw)
        # v3：磁盘不允许明文 password 字段
        self.assertNotIn("password", raw["accounts"][0])
        self.assertIn("password_enc", raw["accounts"][0])
        data = self.cfg.load()
        self.assertEqual(len(data["accounts"]), 1)
        acc = data["accounts"][0]
        self.assertEqual(acc["username"], "13800000000")
        self.assertEqual(acc["albums"], ["相册A"])
        # photos_dir 空 → 回退 pkgvar/photos/<id>
        self.assertEqual(acc["photos_dir"], str(self.tmp / "photos" / "acc-huawei-abc123"))

    def test_photos_dir_default_normalized_on_save(self):
        account = dict(DEFAULT_ACCOUNT)
        account["id"] = "acc-huawei-abc123"
        filled = self.cfg._fill_account(account)  # 回退值填充
        self.cfg.save({}, [filled])
        raw = json.loads((self.tmp / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(raw["accounts"][0]["photos_dir"], "")  # 不固化回退值

    def test_v1_flat_fallback(self):
        # 迁移器未跑时的防御性容错：按 v1 平铺解读
        (self.tmp / "config.json").write_text(json.dumps({"username": "u1"}), encoding="utf-8")
        data = self.cfg.load()
        self.assertEqual(len(data["accounts"]), 1)
        self.assertEqual(data["accounts"][0]["username"], "u1")

    def test_owner_backfill_and_roundtrip(self):
        # T30.2：存量 v2 配置无 owner 字段 → load 运行时视图自动补齐 ""
        (self.tmp / "config.json").write_text(json.dumps({
            "version": 2,
            "settings": {"timezone": "Asia/Shanghai", "log_level": "INFO",
                         "custom_photos_dirs": []},
            "accounts": [{"id": "acc-huawei-legacy", "platform": "huawei",
                          "enabled": False, "name": "存量", "username": "u1",
                          "password": "p"}],
        }), encoding="utf-8")
        data = self.cfg.load()
        self.assertEqual(data["accounts"][0]["owner"], "")

        # 保存后 owner 持久化（save 按 DEFAULT_ACCOUNT 键集合输出）
        data["accounts"][0]["owner"] = "1000"
        self.cfg.save(data["settings"], data["accounts"])
        raw = json.loads((self.tmp / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(raw["accounts"][0]["owner"], "1000")

    def test_to_sync_config_mapping(self):
        account = dict(DEFAULT_ACCOUNT)
        account.update({
            "id": "acc-huawei-abc123", "username": "u1", "password": "p1",
            "photos_dir": "/tmp/photos", "albums": ["A"], "exclude_albums": ["B"],
            "created_after": "2024-01-01", "created_before": "2024-12-31",
            "cron": "@daily",
        })
        settings = dict(DEFAULT_SETTINGS)
        cfg = self.cfg.to_sync_config(account, settings)
        self.assertEqual(str(cfg.directory), "/tmp/photos")
        # config_dir 指向账号目录（health/state 隔离）
        self.assertEqual(cfg.config_dir, self.tmp / "accounts" / "acc-huawei-abc123")
        self.assertEqual(cfg.albums, ["A"])
        self.assertEqual(cfg.exclude_albums, ["B"])
        self.assertIsInstance(cfg.created_after_ms, int)
        self.assertGreater(cfg.created_before_ms, cfg.created_after_ms)
        self.assertEqual(cfg.cron, "@daily")

    def test_to_sync_config_dry_run(self):
        cfg = self.cfg.to_sync_config(dict(DEFAULT_ACCOUNT), dict(DEFAULT_SETTINGS), dry_run=True)
        self.assertTrue(cfg.dry_run)


# ---------- v1→v2 迁移器 ----------

def _write_v1_fixture(tmp: Path, *, photos_dir: str = "") -> None:
    """构造典型 v1 布局：平铺 config + 根目录状态文件 + photos/ 内容。"""
    (tmp / "config.json").write_text(json.dumps({
        "username": "13800000000", "password": "secret",
        "photos_dir": photos_dir,
        "albums": ["相机"], "cron": "0 3 * * *",
        "timezone": "Asia/Shanghai", "log_level": "INFO",
        "custom_photos_dirs": ["/vol1/1000/photo"],
    }, ensure_ascii=False), encoding="utf-8")
    (tmp / "auth.json").write_text("{}", encoding="utf-8")
    (tmp / "curl.txt").write_text("curl 'x'", encoding="utf-8")
    (tmp / "cas_state.json").write_text("{}", encoding="utf-8")
    # state.db 须为合法 sqlite（真实场景即如此）；用 StateStore 生成真实 schema
    from hwcloudpd.store import StateStore
    with StateStore(tmp / "state.db"):
        pass
    (tmp / "health.json").write_text("{}", encoding="utf-8")
    photos = tmp / "photos"
    photos.mkdir(exist_ok=True)
    (photos / "IMG_001.jpg").write_bytes(b"jpeg-data")
    (photos / "sub").mkdir(exist_ok=True)
    (photos / "sub" / "IMG_002.jpg").write_bytes(b"jpeg-data-2")


class TestMigration(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-mig-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_fresh_install_untouched(self):
        migrate_config_v1_to_v2(self.tmp)
        self.assertFalse((self.tmp / "config.json").exists())

    def test_v2_idempotent(self):
        cfg = AppConfig(self.tmp / "config.json", self.tmp)
        cfg.save({}, [])
        mtime = (self.tmp / "config.json").stat().st_mtime_ns
        migrate_config_v1_to_v2(self.tmp)
        self.assertEqual((self.tmp / "config.json").stat().st_mtime_ns, mtime)

    def test_full_migration(self):
        _write_v1_fixture(self.tmp)
        migrate_config_v1_to_v2(self.tmp)

        # 备份存在
        self.assertTrue((self.tmp / "config.json.bak-v1").exists())
        # v3 结构 + 账号包装
        raw = json.loads((self.tmp / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(raw["version"], app_runtime.CONFIG_VERSION)
        self.assertEqual(len(raw["accounts"]), 1)
        acc = raw["accounts"][0]
        self.assertEqual(acc["id"], "acc-hw-0")
        self.assertEqual(acc["platform"], "huawei")
        self.assertTrue(acc["enabled"])
        self.assertEqual(acc["username"], "13800000000")
        self.assertNotIn("password", acc)  # v3 只写密文信封
        self.assertIsNotNone(acc["password_enc"])
        self.assertEqual(acc["albums"], ["相机"])
        self.assertEqual(acc["photos_dir"], "")  # 空 → 运行时回退 photos/acc-hw-0
        # settings 拆分
        self.assertEqual(raw["settings"]["custom_photos_dirs"], ["/vol1/1000/photo"])
        self.assertEqual(raw["settings"]["timezone"], "Asia/Shanghai")

        # 状态文件下沉
        acc_dir = self.tmp / "accounts" / "acc-hw-0"
        for name in ("auth.json", "curl.txt", "cas_state.json", "state.db", "health.json"):
            self.assertTrue((acc_dir / name).exists(), name)
            self.assertFalse((self.tmp / name).exists(), name)

        # 照片根下沉（photos_dir 为空场景）
        self.assertTrue((self.tmp / "photos" / "acc-hw-0" / "IMG_001.jpg").exists())
        self.assertTrue((self.tmp / "photos" / "acc-hw-0" / "sub" / "IMG_002.jpg").exists())
        self.assertFalse((self.tmp / "photos" / "IMG_001.jpg").exists())

        # 运行时视图：回退路径正确 + 密码已解密
        data = AppConfig(self.tmp / "config.json", self.tmp).load()
        self.assertEqual(data["accounts"][0]["photos_dir"],
                         str(self.tmp / "photos" / "acc-hw-0"))
        self.assertEqual(data["accounts"][0]["password"], "secret")

    def test_custom_photos_dir_not_moved(self):
        custom = self.tmp / "elsewhere"
        custom.mkdir()
        _write_v1_fixture(self.tmp, photos_dir=str(custom))
        migrate_config_v1_to_v2(self.tmp)
        raw = json.loads((self.tmp / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(raw["accounts"][0]["photos_dir"], str(custom))
        # photos 根没有 acc-hw-0 子目录（无内容迁移）
        self.assertFalse((self.tmp / "photos" / "acc-hw-0").exists())

    def test_rollback_on_save_failure(self):
        _write_v1_fixture(self.tmp)
        original = (self.tmp / "config.json").read_text(encoding="utf-8")
        with patch.object(AppConfig, "save", side_effect=OSError("disk full")):
            with self.assertRaises(ConfigMigrationError):
                migrate_config_v1_to_v2(self.tmp)
        # 配置还原
        self.assertEqual((self.tmp / "config.json").read_text(encoding="utf-8"), original)
        # 状态文件回到根目录
        for name in ("auth.json", "curl.txt", "state.db", "health.json"):
            self.assertTrue((self.tmp / name).exists(), name)
            self.assertFalse((self.tmp / "accounts" / "acc-hw-0" / name).exists(), name)
        # 照片回到根
        self.assertTrue((self.tmp / "photos" / "IMG_001.jpg").exists())
        self.assertFalse((self.tmp / "photos" / "acc-hw-0").exists() and
                         (self.tmp / "photos" / "acc-hw-0" / "IMG_001.jpg").exists())


# ---------- SchedulerManager（运行时编排） ----------

class ManagerTest(unittest.TestCase):
    """SchedulerManager 级测试基座：空 pkgvar。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-mgr-"))
        self.mgr = SchedulerManager(self.tmp)

    def tearDown(self) -> None:
        self.mgr.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _create(self, name="账号A", **extra) -> dict:
        payload = {"name": name, "username": f"user-{name}", "password": "pw-secret"}
        payload.update(extra)
        result = self.mgr.create_account(payload)
        assert result["status"] == "ok", result
        return result["account"]

    def wait_daemon(self, account_id: str, timeout: float = 5.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            rt = self.mgr._runtimes.get(account_id)
            if rt and rt._daemon_thread and rt._daemon_thread.is_alive():
                return True
            time.sleep(0.05)
        return False


class TestManagerBasics(ManagerTest):
    def test_empty_startup(self):
        snap = self.mgr.status_snapshot()
        self.assertEqual(snap["accounts"], [])
        self.assertTrue(self.mgr.service_health()["daemon_running"])

    def test_auth_status_platform_probe_passthrough(self):
        """平台扩展探针字段（小米 pwd_configured/longterm）经 auth_status 透传。"""
        acc = self._create(name="小米号", platform="xiaomi", username="13800000000")
        info = self.mgr.account_auth_status(acc["id"])
        self.assertIn("pwd_configured", info)
        self.assertTrue(info["pwd_configured"])
        self.assertIn("longterm", info)
        # 通用字段不受透传影响
        self.assertFalse(info["has_cas_tgt"])
        self.assertIn("has_session", info)

    def test_create_and_list(self):
        acc = self._create()
        self.assertRegex(acc["id"], r"^acc-huawei-[0-9a-f]{6}$")
        self.assertEqual(acc["password"], "******")  # 脱敏
        self.assertFalse(acc["enabled"])  # 创建强制停用（T29.1）
        items = self.mgr.list_accounts()
        self.assertEqual(len(items), 1)
        # 创建后 daemon 不启动
        rt = self.mgr._runtimes[acc["id"]]
        self.assertFalse(rt.enabled)
        self.assertTrue(rt._daemon_thread is None or not rt._daemon_thread.is_alive())
        # 显式启用后 daemon 启动
        r = self.mgr.set_account_enabled(acc["id"], True)
        self.assertEqual(r["status"], "ok")
        self.assertTrue(self.wait_daemon(acc["id"]))
        # 账号目录与状态文件布局
        acc_dir = self.tmp / "accounts" / acc["id"]
        self.assertTrue((acc_dir / "logs" / "sync.log").exists())
        self.assertTrue((acc_dir / "health.json").exists())
        self.assertFalse((self.tmp / "auth.json").exists())  # 根目录不再有状态文件

    def test_create_forced_disabled_ignores_payload(self):
        # payload 显式 enabled=true 也被忽略：先认证（含 2FA）后启用
        acc = self._create("账号X", enabled=True)
        self.assertFalse(acc["enabled"])
        raw = json.loads((self.tmp / "config.json").read_text(encoding="utf-8"))
        self.assertFalse(raw["accounts"][0]["enabled"])
        rt = self.mgr._runtimes[acc["id"]]
        self.assertTrue(rt._daemon_thread is None or not rt._daemon_thread.is_alive())

    def test_icloud_domain_persisted_and_delete_options_clamped(self):
        acc = self._create(
            "iCloud", platform="icloud", domain="CN", auto_delete=True,
            delete_after_download=True, keep_cloud_recent_days=7,
        )
        self.assertEqual(acc["domain"], "cn")
        raw = json.loads((self.tmp / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(raw["accounts"][0]["domain"], "cn")
        self.assertNotIn("password", raw["accounts"][0])
        cfg = app_runtime.SyncConfig(
            auto_delete=True, delete_after_download=True, keep_cloud_recent_days=7,
        )
        self.mgr._runtimes[acc["id"]]._apply_capabilities(cfg)
        self.assertFalse(cfg.auto_delete)
        self.assertFalse(cfg.delete_after_download)
        self.assertIsNone(cfg.keep_cloud_recent_days)

    def test_create_invalid_rejected(self):
        result = self.mgr.create_account({"cron": "bad cron"})
        self.assertEqual(result["status"], "error")
        self.assertEqual(self.mgr.list_accounts(), [])
        self.assertFalse((self.tmp / "config.json").exists())

    def test_create_with_owner_persisted(self):
        # T30.2：owner 经 DEFAULT_ACCOUNT 键循环自动透传并持久化
        acc = self._create("账号O", owner="2001")
        self.assertEqual(acc["owner"], "2001")
        raw = json.loads((self.tmp / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(raw["accounts"][0]["owner"], "2001")
        # get_account（脱敏视图）同样携带 owner
        self.assertEqual(self.mgr.get_account(acc["id"])["owner"], "2001")
        # update_account 也可修改 owner
        r = self.mgr.update_account(acc["id"], {"owner": ""})
        self.assertEqual(r["status"], "ok")
        self.assertEqual(self.mgr.get_account(acc["id"])["owner"], "")

    def test_get_account_missing(self):
        with self.assertRaises(KeyError):
            self.mgr.get_account("nope")

    def _stored_password(self, account_id: str) -> str:
        cfg = AppConfig(self.tmp / "config.json", self.tmp).load()
        target = [a for a in cfg["accounts"] if a["id"] == account_id][0]
        return target["password"]

    def test_password_mask_flow(self):
        acc = self._create()
        raw = json.loads((self.tmp / "config.json").read_text(encoding="utf-8"))
        self.assertNotIn("password", raw["accounts"][0])
        self.assertIn("password_enc", raw["accounts"][0])
        self.assertNotIn("pw-secret", (self.tmp / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(self._stored_password(acc["id"]), "pw-secret")
        # 掩码回传保留原密码
        r = self.mgr.update_account(acc["id"], {"password": "******", "name": "改名"})
        self.assertEqual(r["status"], "ok")
        raw = json.loads((self.tmp / "config.json").read_text(encoding="utf-8"))
        self.assertNotIn("password", raw["accounts"][0])
        self.assertEqual(self._stored_password(acc["id"]), "pw-secret")
        self.assertEqual(raw["accounts"][0]["name"], "改名")
        # __clear__ 清除
        self.mgr.update_account(acc["id"], {"password": "__clear__"})
        raw = json.loads((self.tmp / "config.json").read_text(encoding="utf-8"))
        self.assertIsNone(raw["accounts"][0]["password_enc"])
        self.assertEqual(self._stored_password(acc["id"]), "")

    def test_update_invalid_rejected(self):
        acc = self._create()
        r = self.mgr.update_account(acc["id"], {"cron": "bad"})
        self.assertEqual(r["status"], "error")
        raw = json.loads((self.tmp / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(raw["accounts"][0]["cron"], DEFAULT_ACCOUNT["cron"])

    def test_delete_account(self):
        acc = self._create()
        acc_dir = self.tmp / "accounts" / acc["id"]
        self.assertTrue(acc_dir.exists())
        r = self.mgr.delete_account(acc["id"])
        self.assertEqual(r["status"], "ok")
        self.assertFalse(acc_dir.exists())
        self.assertEqual(self.mgr.list_accounts(), [])
        self.assertNotIn(acc["id"], self.mgr._runtimes)

    def test_disable_stops_daemon(self):
        acc = self._create()
        self.mgr.set_account_enabled(acc["id"], True)  # 创建默认停用，先启用
        self.assertTrue(self.wait_daemon(acc["id"]))
        r = self.mgr.set_account_enabled(acc["id"], False)
        self.assertEqual(r["status"], "ok")
        rt = self.mgr._runtimes[acc["id"]]
        self.assertFalse(rt.enabled)
        thread = rt._daemon_thread
        self.assertTrue(thread is None or not thread.is_alive())
        # status 接口在停用态不报错
        snap = self.mgr.account_status(acc["id"])
        self.assertFalse(snap["enabled"])

    def test_enable_restarts_daemon(self):
        acc = self._create()
        self.mgr.set_account_enabled(acc["id"], False)
        r = self.mgr.set_account_enabled(acc["id"], True)
        self.assertEqual(r["status"], "ok")
        self.assertTrue(self.wait_daemon(acc["id"]))


class TestPhotosDirDerivation(ManagerTest):
    """photos_dir 子目录派生（0.2.1 缺陷④：多账号目录隔离）。"""

    def _base(self) -> str:
        d = tempfile.mkdtemp(prefix="albumsync-photos-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d

    def _raw_accounts(self) -> list[dict]:
        return json.loads((self.tmp / "config.json").read_text(encoding="utf-8"))["accounts"]

    def test_derive_subdir_sanitized(self):
        base = self._base()
        acc = self._create('a/b\\c:d*e?f"g<h>i|j. ', photos_dir=base)
        expected = os.path.normpath(os.path.join(base, "abcdefghij"))
        self.assertEqual(acc["photos_dir"], expected)
        self.assertEqual(self._raw_accounts()[0]["photos_dir"], expected)

    def test_derive_collision_appends_id_suffix(self):
        base = self._base()
        a = self._create("家人", photos_dir=base)
        b = self._create("家人", photos_dir=base)
        self.assertEqual(a["photos_dir"], os.path.normpath(os.path.join(base, "家人")))
        self.assertEqual(b["photos_dir"],
                         os.path.normpath(os.path.join(base, f"家人-{b['id'][-6:]}")))
        self.assertNotEqual(a["photos_dir"], b["photos_dir"])

    def test_empty_photos_dir_uses_default_root(self):
        acc = self._create("账号D")
        self.assertEqual(self._raw_accounts()[0]["photos_dir"], "")
        data = AppConfig(self.tmp / "config.json", self.tmp).load()
        self.assertEqual(data["accounts"][0]["photos_dir"],
                         str(self.tmp / "photos" / acc["id"]))

    def test_sanitize_rules(self):
        self.assertEqual(sanitize_account_name("///"), "")          # 全非法字符 → 空（回退 id 后缀）
        self.assertEqual(sanitize_account_name("  ..name..  "), "name")
        self.assertEqual(sanitize_account_name("x" * 100), "x" * 48)
        self.assertEqual(sanitize_account_name(None), "")

    def test_relative_photos_dir_rejected(self):
        result = self.mgr.create_account({"name": "账号R", "photos_dir": "rel/path"})
        self.assertEqual(result["status"], "error")
        self.assertEqual(self.mgr.list_accounts(), [])

    def test_update_keeps_derived_photos_dir(self):
        base = self._base()
        acc = self._create("家人", photos_dir=base)
        r = self.mgr.update_account(acc["id"], {"name": "改名不改目录"})
        self.assertEqual(r["status"], "ok")
        self.assertEqual(
            [a for a in self._raw_accounts() if a["id"] == acc["id"]][0]["photos_dir"],
            acc["photos_dir"])

    def test_update_derive_subdir_flag(self):
        # 向导创建流程：PUT + derive_subdir=true → 派生 <目录>/<账号名>
        acc = self._create("家人")
        self.assertEqual(self._raw_accounts()[0]["photos_dir"], "")  # 创建时未给目录
        base = self._base()
        r = self.mgr.update_account(acc["id"], {"photos_dir": base, "derive_subdir": True})
        self.assertEqual(r["status"], "ok")
        self.assertEqual(self._raw_accounts()[0]["photos_dir"],
                         os.path.normpath(os.path.join(base, "家人")))
        # 普通保存（无标记）→ 原样保留，不再派生
        base2 = self._base()
        r = self.mgr.update_account(acc["id"], {"photos_dir": base2})
        self.assertEqual(r["status"], "ok")
        self.assertEqual(self._raw_accounts()[0]["photos_dir"], os.path.normpath(base2))


class TestHotReloadIsolation(ManagerTest):
    def test_update_reloads_only_target(self):
        a = self._create("账号A")
        b = self._create("账号B")
        self.mgr.set_account_enabled(a["id"], True)  # 创建默认停用，先启用
        self.mgr.set_account_enabled(b["id"], True)
        self.assertTrue(self.wait_daemon(a["id"]))
        self.assertTrue(self.wait_daemon(b["id"]))
        rt_a_old = self.mgr._runtimes[a["id"]]
        rt_b_old = self.mgr._runtimes[b["id"]]

        r = self.mgr.update_account(a["id"], {"name": "账号A2"})
        self.assertEqual(r["status"], "ok")

        rt_a_new = self.mgr._runtimes[a["id"]]
        rt_b_new = self.mgr._runtimes[b["id"]]
        self.assertIsNot(rt_a_new, rt_a_old)          # A 重建
        self.assertIs(rt_b_new, rt_b_old)             # B 不动
        self.assertTrue(rt_b_new._daemon_thread.is_alive())  # B daemon 不中断
        self.assertEqual(self.mgr.get_account(a["id"])["name"], "账号A2")
        # 旧 A 运行时已停止（daemon 线程退出或即将退出）
        deadline = time.time() + 6
        while time.time() < deadline and rt_a_old._daemon_thread.is_alive():
            time.sleep(0.1)
        self.assertFalse(rt_a_old._daemon_thread.is_alive())

    def test_settings_change_reloads_all(self):
        a = self._create("账号A")
        b = self._create("账号B")
        rt_a_old = self.mgr._runtimes[a["id"]]
        rt_b_old = self.mgr._runtimes[b["id"]]
        r = self.mgr.save_settings({"log_level": "DEBUG"})
        self.assertEqual(r["status"], "ok")
        self.assertIsNot(self.mgr._runtimes[a["id"]], rt_a_old)
        self.assertIsNot(self.mgr._runtimes[b["id"]], rt_b_old)
        self.assertEqual(self.mgr.get_settings()["log_level"], "DEBUG")

    def test_settings_invalid_rejected(self):
        r = self.mgr.save_settings({"log_level": "TRACE"})
        self.assertEqual(r["status"], "error")


class TestSerialGate(unittest.TestCase):
    def _fake_engine(self, log: list, running: list, lock: threading.Lock):
        class FakeEngine:
            def run_once(self, force_full_scan: bool = False):
                with lock:
                    running.append(1)
                    log.append(("enter", len(running)))
                time.sleep(0.15)
                with lock:
                    running.pop()
                    log.append(("exit", len(running)))
                return "done"
        return FakeEngine()

    def test_no_overlap(self):
        gate_lock = threading.Lock()
        log: list = []
        running: list = []
        lock = threading.Lock()
        engine = self._fake_engine(log, running, lock)
        results = []

        def worker():
            g = _SerialSyncGate(gate_lock, threading.Event())
            results.append(g.run_once(engine))

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results, ["done", "done", "done"])
        enters = [n for kind, n in log if kind == "enter"]
        self.assertTrue(all(n == 1 for n in enters), f"并发进入闸门: {log}")

    def test_cancel_skips_execution(self):
        gate_lock = threading.Lock()
        gate_lock.acquire()  # 闸门被长期占用（模拟其他账号长同步）
        cancelled = threading.Event()
        engine_started = threading.Event()

        class NeverEngine:
            def run_once(self, force_full_scan: bool = False):
                engine_started.set()
                return "ran"

        g = _SerialSyncGate(gate_lock, cancelled, poll_sec=0.05)
        result_holder = {}

        def worker():
            result_holder["r"] = g.run_once(NeverEngine())

        t = threading.Thread(target=worker)
        t.start()
        time.sleep(0.3)  # 让 worker 在闸门外等待
        cancelled.set()
        t.join(timeout=5)
        self.assertFalse(t.is_alive())
        self.assertEqual(result_holder["r"].__class__.__name__, "SyncReport")
        self.assertFalse(engine_started.is_set())
        gate_lock.release()


class TestAccountRuntimeOps(ManagerTest):
    def test_trigger_sync(self):
        acc = self._create()
        self.mgr.set_account_enabled(acc["id"], True)  # 创建默认停用，先启用
        self.assertTrue(self.wait_daemon(acc["id"]))
        self.assertEqual(self.mgr.trigger_sync(acc["id"])["status"], "ok")

    def test_dry_run_no_auth_fails(self):
        acc = self._create()
        self.mgr.set_account_enabled(acc["id"], True)  # 创建默认停用，先启用
        self.assertTrue(self.wait_daemon(acc["id"]))
        result = self.mgr.start_dry_run(acc["id"])
        self.assertEqual(result["status"], "ok")
        deadline = time.time() + 15
        while time.time() < deadline:
            state = self.mgr.dry_run_status(acc["id"])
            if not state["running"]:
                break
            time.sleep(0.2)
        state = self.mgr.dry_run_status(acc["id"])
        self.assertFalse(state["running"])
        self.assertIsNotNone(state["error"])

    def test_per_account_log_isolation(self):
        a = self._create("账号A")
        b = self._create("账号B")
        rt_a = self.mgr._runtimes[a["id"]]
        rt_b = self.mgr._runtimes[b["id"]]
        import logging
        with rt_a._log_ctx():
            logging.getLogger("albumsync.test").warning("A账号专属日志行")
        with rt_b._log_ctx():
            logging.getLogger("albumsync.test").warning("B账号专属日志行")
        lines_a = "".join(rt_a.tail_logs(100))
        lines_b = "".join(rt_b.tail_logs(100))
        self.assertIn("A账号专属日志行", lines_a)
        self.assertNotIn("B账号专属日志行", lines_a)
        self.assertIn("B账号专属日志行", lines_b)
        self.assertNotIn("A账号专属日志行", lines_b)

    def test_auth_ops_error_paths(self):
        acc = self._create()
        # 无凭据登录
        r = self.mgr.web_login(acc["id"])
        self.assertEqual(r["status"], "error")
        # cURL 垃圾/空
        self.assertEqual(self.mgr.import_curl(acc["id"], "curl nonsense $$")["status"], "error")
        self.assertEqual(self.mgr.import_curl(acc["id"], "  ")["status"], "error")
        # 2FA 格式
        self.assertEqual(self.mgr.submit_2fa(acc["id"], "12ab")["status"], "error")

    def test_add_custom_photos_dir(self):
        d = os.path.normpath(tempfile.mkdtemp(prefix="albumsync-custom-"))
        try:
            result = self.mgr.add_custom_photos_dir(d)
            self.assertEqual(result["status"], "ok")
            self.assertIn(d, self.mgr.get_settings()["custom_photos_dirs"])
            again = self.mgr.add_custom_photos_dir(d + "/")
            self.assertEqual(again["status"], "ok")
            self.assertEqual(self.mgr.get_settings()["custom_photos_dirs"].count(d), 1)
            self.assertTrue(self.mgr.probe_single_dir(d)["registered"])
            self.assertEqual(
                self.mgr.add_custom_photos_dir(str(self.tmp / "no_such_dir"))["status"],
                "error")
            self.assertEqual(self.mgr.add_custom_photos_dir("rel/path")["status"], "error")
            # 登记不得固化 photos_dir 默认回退语义
            acc = self._create("账号C")
            raw = json.loads((self.tmp / "config.json").read_text(encoding="utf-8"))
            target = [x for x in raw["accounts"] if x["id"] == acc["id"]][0]
            self.assertEqual(target["photos_dir"], "")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestManagerMigrationOnStartup(unittest.TestCase):
    def test_v1_auto_migrated_then_running(self):
        tmp = Path(tempfile.mkdtemp(prefix="albumsync-mgr2-"))
        try:
            _write_v1_fixture(tmp)
            mgr = SchedulerManager(tmp)
            try:
                self.assertEqual(len(mgr.list_accounts()), 1)
                item = mgr.list_accounts()[0]
                self.assertEqual(item["id"], "acc-hw-0")
                self.assertEqual(item["platform"], "huawei")
                # 状态文件已下沉且 daemon 正常
                self.assertTrue((tmp / "accounts" / "acc-hw-0" / "health.json").exists())
                deadline = time.time() + 5
                alive = False
                while time.time() < deadline:
                    rt = mgr._runtimes.get("acc-hw-0")
                    if rt and rt._daemon_thread and rt._daemon_thread.is_alive():
                        alive = True
                        break
                    time.sleep(0.05)
                self.assertTrue(alive)
            finally:
                mgr.stop()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


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
