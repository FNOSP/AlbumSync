#!/usr/bin/env python3
"""providers 抽象层单测（T25：协议符合性 / 注册表工厂 / 平台校验）。"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app" / "server"))

from hwcloudpd.auth import AuthManager  # noqa: E402
from providers import (  # noqa: E402
    PLATFORMS,
    get_platform_spec,
    known_platforms,
)
from providers.base import AuthStrategy, PhotoProvider  # noqa: E402
from providers.huawei import HuaweiAuthStrategy, HuaweiProvider  # noqa: E402
from app_runtime import validate_account  # noqa: E402


def make_account(**kw):
    base = {
        "id": "acc-huawei-test01", "platform": "huawei", "enabled": True,
        "name": "测试账号", "username": "13800000000", "password": "pw",
        "photos_dir": "", "folder_structure": "{:%Y/%m/%d}",
        "albums": [], "exclude_albums": [], "photo_size": "original",
        "file_match_policy": "name-size-dedup-with-suffix",
        "live_photo_mov_filename_policy": "none",
        "auto_delete": False, "only_favorites": False,
        "cron": "0 3 * * *", "timezone": "Asia/Shanghai",
    }
    base.update(kw)
    return base


class TestProviderProtocols(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-prov-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.am = AuthManager(self.tmp)

    def test_huawei_provider_conforms_protocol(self):
        prov = HuaweiProvider(self.am, "acc-1")
        self.assertIsInstance(prov, PhotoProvider)  # runtime_checkable：方法面完整

    def test_huawei_strategy_conforms_protocol(self):
        strat = HuaweiAuthStrategy(self.am, make_account())
        self.assertIsInstance(strat, AuthStrategy)
        # 有凭据配置（账号密码在 account 中）
        self.assertTrue(strat.has_credentials())
        # 空目录：无会话、无待验证挑战
        self.assertFalse(strat.is_valid())
        self.assertIsNone(strat.pending_challenge())

    def test_strategy_no_credentials(self):
        strat = HuaweiAuthStrategy(self.am, {"id": "acc-x", "username": "", "password": ""})
        self.assertFalse(strat.has_credentials())
        with self.assertRaises(Exception):
            strat.web_login()  # 缺凭据应拒绝登录（AuthExpiredError 族）

    def test_invalidate_clears_session_file(self):
        (self.tmp / "auth.json").write_text("{}", encoding="utf-8")
        strat = HuaweiAuthStrategy(self.am, make_account(id="acc-invalidate"))
        strat.invalidate()
        self.assertFalse((self.tmp / "auth.json").exists())


class TestPlatformRegistry(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-reg-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_huawei_registered_with_full_capabilities(self):
        spec = get_platform_spec("huawei")
        self.assertEqual(spec.platform, "huawei")
        self.assertEqual(spec.display_name, "华为云空间")
        caps = spec.capabilities
        self.assertTrue(caps.supports_delete)
        self.assertTrue(caps.supports_web_login_2fa)
        self.assertTrue(caps.supports_curl_import)

    def test_factories_produce_conforming_objects(self):
        spec = get_platform_spec("huawei")
        account = make_account()
        prov = spec.create_provider(AuthManager(self.tmp), account)
        strat = spec.create_auth_strategy(AuthManager(self.tmp), account)
        self.assertIsInstance(prov, HuaweiProvider)
        self.assertIsInstance(strat, HuaweiAuthStrategy)
        self.assertEqual(prov.account_id, account["id"])

    def test_unknown_platform_rejected(self):
        with self.assertRaises(ValueError):
            get_platform_spec("bogus")
        with self.assertRaises(ValueError):
            get_platform_spec("unknown-platform")

    def test_known_platforms_shape(self):
        items = known_platforms()
        self.assertEqual(items[0]["platform"], "huawei")
        self.assertIn("capabilities", items[0])

    def test_validate_account_platform_check(self):
        self.assertIsNone(validate_account(make_account()))
        self.assertIsNone(validate_account(make_account(platform="xiaomi")))  # T27 已注册
        self.assertIsNotNone(validate_account(make_account(platform="bogus")))


if __name__ == "__main__":
    unittest.main()
