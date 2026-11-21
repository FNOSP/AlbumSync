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
from providers.base import (  # noqa: E402
    AuthStrategy,
    BaseAuthStrategy,
    NoAutoRelogin,
    PhotoProvider,
)
from providers.huawei import HuaweiAuthStrategy, HuaweiProvider  # noqa: E402
from providers.icloud import ICloudAuthStrategy, ICloudProvider  # noqa: E402
from providers.xiaomi import XiaomiAuthStrategy  # noqa: E402
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

    def test_icloud_registered_with_readonly_capabilities(self):
        spec = get_platform_spec("icloud")
        account = make_account(
            id="acc-icloud-test01", platform="icloud", username="user@example.com", domain="cn",
        )
        prov = spec.create_provider(AuthManager(self.tmp), account)
        strat = spec.create_auth_strategy(AuthManager(self.tmp), account)
        self.assertIsInstance(prov, ICloudProvider)
        self.assertIsInstance(strat, ICloudAuthStrategy)
        self.assertIsInstance(prov, PhotoProvider)
        self.assertIsInstance(strat, AuthStrategy)
        self.assertEqual(strat.domain, "cn")
        self.assertFalse(spec.capabilities.supports_delete)
        self.assertFalse(spec.capabilities.supports_curl_import)
        self.assertFalse(spec.capabilities.supports_qr_login)
        self.assertEqual(
            spec.session_files(account["id"]),
            ("icloud_acc-icloud-test01_session.json", "icloud_acc-icloud-test01_cookies.lwp"),
        )

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
        icloud = make_account(platform="icloud", domain="CN")
        self.assertIsNone(validate_account(icloud))
        self.assertEqual(icloud["domain"], "cn")
        self.assertIsNotNone(validate_account(make_account(platform="icloud", domain="jp")))
        self.assertIsNotNone(validate_account(make_account(platform="bogus")))


class TestBaseAuthStrategyContract(unittest.TestCase):
    """平台扩展面收编为 BaseAuthStrategy 显式契约（通用层零鸭子探测）。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-base-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_xiaomi_strategy_inherits_base_defaults(self):
        am = AuthManager(self.tmp)
        strat = XiaomiAuthStrategy(am, {"id": "acc-xiaomi-t1"})
        self.assertIsInstance(strat, BaseAuthStrategy)
        # 无 CAS 语义 → auth_probe 走基类默认
        probe = strat.auth_probe()
        self.assertIsNone(probe["pending_2fa"])
        self.assertFalse(probe["has_cas_tgt"])
        self.assertFalse(probe["credentials_configured"])
        # 不支持自动重登 → build_authenticator 返回 NoAutoRelogin 桩
        auth = strat.build_authenticator()
        self.assertIsInstance(auth, NoAutoRelogin)
        self.assertFalse(auth.can_attempt_login)

    def test_base_default_qr_unsupported(self):
        base = BaseAuthStrategy()
        self.assertEqual(base.start_qr_login().get("status"), "error")
        self.assertEqual(base.qr_login_status().get("status"), "failed")
        # 小米覆写了扫码链路（不触网，仅验证覆写存在）
        self.assertNotEqual(
            XiaomiAuthStrategy.start_qr_login, BaseAuthStrategy.start_qr_login
        )
        self.assertNotEqual(
            XiaomiAuthStrategy.qr_login_status, BaseAuthStrategy.qr_login_status
        )

    def test_session_info_platform_extract(self):
        am = AuthManager(self.tmp)
        xiaomi = XiaomiAuthStrategy(am, {"id": "acc-xiaomi-t3"})
        info = xiaomi.session_info(type("S", (), {
            "user_id": "u-123", "updated_at": 1700000000.0,
        })())
        self.assertEqual(info["user_id"], "u-123")
        self.assertIsNone(info["login_sec_level"])
        self.assertAlmostEqual(info["session_updated_at"], 1700000000.0)
        # 华为：session_info 提取 loginSecLevel（原 app_runtime 探测逻辑下沉）
        hw = HuaweiAuthStrategy(am, make_account(id="acc-hw-t1"))
        info_hw = hw.session_info(type("S", (), {
            "user_id": "hw-1", "cookies": {"loginSecLevel": "2"}, "updated_at": 1.0,
        })())
        self.assertEqual(info_hw["login_sec_level"], "2")
        # 平台元数据归位
        self.assertEqual(hw.platform_label, "华为云空间")
        self.assertEqual(xiaomi.platform_label, "小米云相册")
        self.assertIn("华为账号", hw.credentials_hint)
        self.assertIn("导入登录态", xiaomi.credentials_hint)

    def test_platform_session_files_declared(self):
        from providers import get_platform_spec

        hw = get_platform_spec("huawei").session_files("acc-1")
        self.assertIn("auth.json", hw)
        xm = get_platform_spec("xiaomi").session_files("acc-x-1")
        self.assertEqual(xm, ("xiaomi_acc-x-1_auth.json",))
        ic = get_platform_spec("icloud").session_files("acc-i-1")
        self.assertEqual(
            ic, ("icloud_acc-i-1_session.json", "icloud_acc-i-1_cookies.lwp")
        )


if __name__ == "__main__":
    unittest.main()
