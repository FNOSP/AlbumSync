#!/usr/bin/env python3
"""iCloud 会话落盘、可信会话恢复与二次验证单测。"""
import json
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app" / "server"))

from hwcloudpd.models import HwCloudError, TwoFactorRequiredError  # noqa: E402
from providers.icloud import (  # noqa: E402
    ICloudAuthStrategy,
    ICloudSessionStore,
)
from providers.icloud.icloud_client import ICloudClient  # noqa: E402


class _CookieJar:
    def save(self, filename, ignore_discard=False, ignore_expires=False):
        self.saved_with = (ignore_discard, ignore_expires)
        Path(filename).write_text("# mock iCloud cookies\n", encoding="utf-8")


def _session(token="trusted-token"):
    return {
        "platform": "icloud",
        "apple_id": "user@example.com",
        "domain": "com",
        "client_id": "auth-test-client",
        "session_token": token,
    }


class _FakeService:
    """只模拟 PyiCloudService 的本地状态机，不访问 Apple。"""

    def __init__(self, session_path, flow=None, push_result=True):
        path = Path(session_path)
        self.session_data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        self.session = SimpleNamespace(cookies=_CookieJar())
        # 语义对齐生产：磁盘会话已是可信令牌时，重建不再要求二次验证。
        trusted_on_disk = self.session_data.get("session_token") == "challenge-trusted-token"
        self.requires_2fa = flow == "2fa" and not trusted_on_disk
        self.requires_2sa = flow == "2sa" and not trusted_on_disk
        self.trusted_devices = [{"id": 7, "phoneNumber": "+86 138****0000"}]
        self.sent_devices = []
        self.validation_attempts = []
        self.trust_calls = 0
        self.push_calls = 0
        self.push_result = push_result
        self.trusted_phones = [SimpleNamespace(id=11, obfuscated_number="+86 138****1111")]
        self.sms_sent = []
        self.sms_validation_attempts = []

    def send_verification_code(self, device):
        self.sent_devices.append(dict(device))
        return True

    def trigger_push_notification(self):
        self.push_calls += 1
        return self.push_result

    def get_trusted_phone_numbers(self):
        return list(self.trusted_phones)

    def send_2fa_code_sms(self, device_id):
        self.sms_sent.append(device_id)
        return True

    def validate_2fa_code_sms(self, device_id, code):
        self.sms_validation_attempts.append((device_id, code))
        return self._validate(code)

    def _validate(self, code):
        self.validation_attempts.append(code)
        if code != "123456":
            return False
        self.requires_2fa = False
        self.requires_2sa = False
        self.session_data["session_token"] = "challenge-trusted-token"
        return True

    def validate_2fa_code(self, code):
        return self._validate(code)

    def validate_verification_code(self, device, code):
        self.last_validated_device = device
        return self._validate(code)

    def trust_session(self):
        self.trust_calls += 1
        return True


class SessionTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-icloud-session-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.auth_file = self.tmp / "icloud_test_session.json"
        self.cookie_file = self.tmp / "icloud_test_cookies.lwp"
        self.store = ICloudSessionStore(self.auth_file, self.cookie_file)

    def make_client(self, *, flow=None, password=None, on_session_update=None, push_result=True):
        services = []

        def service_factory(domain, apple_id, password_provider, **kwargs):
            self.last_service_args = (domain, apple_id, password_provider, kwargs)
            service = _FakeService(kwargs["session_path"], flow=flow, push_result=push_result)
            services.append(service)
            return service

        client = ICloudClient(
            apple_id="user@example.com",
            password=password,
            domain="com",
            session_path=self.auth_file,
            cookiejar_path=self.cookie_file,
            store=self.store,
            on_session_update=on_session_update,
            service_factory=service_factory,
        )
        return client, services


class TestICloudSessionStore(SessionTestBase):
    def test_atomic_save_preserves_old_file_until_replace(self):
        self.store.save(_session("old"))
        with patch.object(Path, "replace", side_effect=OSError("simulated replace failure")):
            with self.assertRaises(OSError):
                self.store.save(_session("new"))
        self.assertEqual(self.store.load()["session_token"], "old")

        self.store.save(_session("new"))
        self.assertEqual(self.store.load()["session_token"], "new")
        self.assertFalse(self.auth_file.with_suffix(".json.tmp").exists())
        self.assertEqual(stat.S_IMODE(self.auth_file.stat().st_mode), 0o600)

        cookies = _CookieJar()
        self.store.save_cookies(cookies)
        self.assertEqual(cookies.saved_with, (True, True))
        self.assertIn("mock iCloud cookies", self.cookie_file.read_text(encoding="utf-8"))
        self.assertFalse(self.cookie_file.with_suffix(".lwp.tmp").exists())
        self.assertEqual(stat.S_IMODE(self.cookie_file.stat().st_mode), 0o600)

    def test_corrupt_or_non_object_json_is_not_a_session(self):
        for raw in ("{broken", "[]", "null"):
            with self.subTest(raw=raw):
                self.auth_file.write_text(raw, encoding="utf-8")
                self.assertIsNone(self.store.load())
                self.assertFalse(self.store.has_session())

    def test_clear_removes_sessions_cookies_and_temp_files(self):
        paths = (
            self.auth_file,
            self.cookie_file,
            self.auth_file.with_suffix(".json.tmp"),
            self.cookie_file.with_suffix(".lwp.tmp"),
            self.store.pending_file,
        )
        for path in paths:
            path.write_text("secret", encoding="utf-8")
        self.store.clear()
        for path in paths:
            self.assertFalse(path.exists())
        self.store.clear()  # 幂等，不应因文件不存在而失败。

    def test_pending_marker_expires_and_is_cleaned(self):
        self.store.save_pending({"flow": "2fa", "created_at": time.time(), "channels": []})
        self.assertIsNotNone(self.store.load_pending())
        self.store.clear_pending()
        self.assertFalse(self.store.pending_file.exists())

        stale = time.time() - 601
        self.store.save_pending({"flow": "2fa", "created_at": stale, "channels": []})
        self.assertIsNone(self.store.load_pending())
        self.assertFalse(self.store.pending_file.exists(), "过期标记应自动清理")

    def test_identical_session_is_not_rewritten(self):
        self.store.save(_session())
        before = self.auth_file.stat().st_mtime_ns
        time.sleep(0.01)
        self.store.save(_session())
        self.assertEqual(
            self.auth_file.stat().st_mtime_ns,
            before,
            "内容未变必须跳过落盘，否则会触发其他实例重建并反复认证 Apple",
        )


class TestTrustedSessionRecovery(SessionTestBase):
    def test_trusted_session_is_reused_locally_without_password(self):
        self.store.save(_session())
        client, services = self.make_client(password=None)

        self.assertIs(client.login(), client)
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0].session_data["session_token"], "trusted-token")
        self.assertEqual(services[0].session_data["client_id"], "auth-test-client")
        self.assertEqual(self.last_service_args[0:2], ("com", "user@example.com"))
        self.assertEqual(self.store.load()["session_token"], "trusted-token")

        # 模拟进程重启：新 client 仍读到同一 token/client_id，而非生成新身份。
        fresh, fresh_services = self.make_client(password=None)
        fresh.login()
        self.assertEqual(fresh_services[0].session_data["client_id"], "auth-test-client")
        self.assertEqual(fresh.store.load()["session_token"], "trusted-token")


class TestChallengeRetry(SessionTestBase):
    def _assert_pending_not_persisted(self):
        data = self.store.load()
        self.assertIsNotNone(data)
        json.dumps(data)  # 落盘内容必须始终可序列化。
        self.assertTrue({"pending", "pending_challenge", "service", "device", "channels"}.isdisjoint(data))

    def test_daemon_login_does_not_push_and_web_login_pushes_once(self):
        self.store.save(_session())
        client, services = self.make_client(flow="2fa", password="pw")
        with self.assertRaises(TwoFactorRequiredError):
            client.login()  # daemon：interactive=False
        self.assertEqual(services[0].push_calls, 0, "后台重登不得额外打扰用户的 Apple 设备")
        self.assertTrue(self.store.load_pending())

        with self.assertRaises(TwoFactorRequiredError) as ctx:
            client.login(interactive=True)  # 网页点击登录
        self.assertIn("推送", str(ctx.exception))
        self.assertEqual(services[0].push_calls, 1, "网页登录必须触发一次推送")
        self.assertTrue(self.store.load_pending())

    def test_2fa_wrong_code_can_retry_and_pending_is_memory_only(self):
        self.store.save(_session())
        client, services = self.make_client(flow="2fa", password="pw")
        with self.assertRaises(TwoFactorRequiredError) as ctx:
            client.login(interactive=True)
        self.assertIn("推送", str(ctx.exception))
        self.assertEqual(services[0].push_calls, 1, "必须显式触发 Apple 推送，否则设备收不到验证码")
        self.assertEqual(services[0].sms_sent, [], "推送成功时不应额外发短信")
        self.assertEqual(client.pending_challenge()["flow"], "2fa")
        self.assertEqual(client.pending_challenge()["channels"][0]["type"], "push")
        self._assert_pending_not_persisted()
        self.assertTrue(self.store.load_pending(), "验证码等待期间必须落盘暂停标记")

        with self.assertRaises(TwoFactorRequiredError):
            client.submit_challenge("000000")
        self.assertIsNotNone(client.pending_challenge())
        self._assert_pending_not_persisted()

        self.assertIs(client.submit_challenge("123456"), client)
        self.assertEqual(services[0].validation_attempts, ["000000", "123456"])
        self.assertIsNone(client.pending_challenge())
        self.assertIsNone(self.store.load_pending(), "验证成功后必须清除暂停标记")
        self.assertEqual(self.store.load()["session_token"], "challenge-trusted-token")
        self.assertEqual(len(services), 1, "重试必须复用 pending service，不能重新登录")

    def test_2fa_push_failure_falls_back_to_sms_code(self):
        self.store.save(_session())
        client, services = self.make_client(flow="2fa", password="pw", push_result=False)
        with self.assertRaises(TwoFactorRequiredError) as ctx:
            client.login(interactive=True)
        service = services[0]
        self.assertEqual(service.push_calls, 1)
        self.assertEqual(service.sms_sent, [11], "推送失败必须改用受信任手机短信")
        self.assertIn("短信", str(ctx.exception))
        self.assertEqual(
            [(c["id"], c["type"]) for c in client.pending_challenge()["channels"]],
            [("trusted_device", "push"), ("11", "sms")],
        )

        with self.assertRaises(TwoFactorRequiredError):
            client.submit_challenge("000000")
        client.submit_challenge("123456")
        self.assertEqual(service.sms_validation_attempts, [(11, "000000")])
        self.assertIsNone(client.pending_challenge())
        self.assertIsNone(self.store.load_pending())

    def test_pending_marker_blocks_other_instances_until_completed(self):
        self.store.save(_session())
        client, services = self.make_client(flow="2fa", password="pw")
        with self.assertRaises(TwoFactorRequiredError):
            client.login(interactive=True)
        self.assertTrue(self.store.load_pending())

        other, other_services = self.make_client(flow=None, password="pw")
        with self.assertRaises(TwoFactorRequiredError):
            other.ensure_service()
        self.assertEqual(other_services, [], "验证码等待期间不得重复登录 Apple，避免刷新挑战")

        client.submit_challenge("123456")
        self.assertIsNone(self.store.load_pending())
        other.ensure_service()
        self.assertEqual(len(other_services), 1)

    def test_frozen_daemon_pending_adopts_session_completed_by_web_flow(self):
        """复现 0.3.20 真机缺陷：daemon 客户端卡在旧 pending，web 完成验证后必须自动恢复。"""
        self.store.save(_session())
        daemon, daemon_services = self.make_client(flow="2fa", password="pw")
        with self.assertRaises(TwoFactorRequiredError):
            daemon.login()  # daemon 后台重登：挑战 + 暂停标记（created_at=T0）
        daemon_created = daemon.pending_challenge()["created_at"]
        self.assertTrue(self.store.load_pending())

        time.sleep(0.02)
        web, _web_services = self.make_client(flow="2fa", password="pw")
        with self.assertRaises(TwoFactorRequiredError):
            web.login(interactive=True)  # 新流程：标记 created_at 更新
        self.assertGreater(
            web.pending_challenge()["created_at"], daemon_created,
            "web 流程的标记必须晚于 daemon 的内存 pending",
        )

        web.submit_challenge("123456")  # web 完成验证：会话落盘 + 标记清除
        self.assertIsNone(self.store.load_pending())
        self.assertFalse(web.pending_challenge())

        # daemon 心跳：必须识别磁盘新状态，丢弃内存 pending 并用可信会话重建。
        daemon.ensure_service()
        self.assertEqual(
            len(daemon_services), 2,
            "daemon 必须丢弃过时 pending 并从磁盘可信会话重建，而不是永久冻结",
        )
        self.assertFalse(daemon.pending_challenge())

    def test_2sa_wrong_code_can_retry_and_pending_is_memory_only(self):
        self.store.save(_session())
        client, services = self.make_client(flow="2sa", password="pw")
        with self.assertRaises(TwoFactorRequiredError):
            client.login()
        pending = client.pending_challenge()
        self.assertEqual(pending["flow"], "2sa")
        self.assertEqual(pending["channels"], [
            {"id": "7", "name": "+86 138****0000", "type": "sms"}
        ])
        self.assertEqual(len(services[0].sent_devices), 1)
        self._assert_pending_not_persisted()

        with self.assertRaises(TwoFactorRequiredError):
            client.submit_challenge("000000")
        self.assertIsNotNone(client.pending_challenge())
        client.submit_challenge("123456")

        self.assertEqual(services[0].validation_attempts, ["000000", "123456"])
        self.assertEqual(len(services[0].sent_devices), 1, "验证码重试不应重复发短信")
        self.assertIsNone(client.pending_challenge())
        self.assertEqual(self.store.load()["session_token"], "challenge-trusted-token")
        self._assert_pending_not_persisted()


class _StrategyClient:
    def __init__(self, *, store, **kwargs):
        self.store = store
        self.token = (store.load() or {}).get("session_token")
        self.invalidated = False

    def pending_challenge(self):
        return None

    def ensure_service(self):
        return self

    def invalidate(self):
        self.invalidated = True


class TestCrossInstanceSessionFiles(SessionTestBase):
    def test_mtime_or_size_change_rebuilds_cached_client(self):
        self.store.save(_session("aa"))
        external_store = ICloudSessionStore(self.auth_file, self.cookie_file)
        with patch("providers.icloud.ICloudClient", _StrategyClient):
            strategy = ICloudAuthStrategy(
                SimpleNamespace(auth_file=str(self.tmp / "auth.json")),
                {"id": "acc", "username": "user@example.com", "domain": "com"},
                session_file=str(self.auth_file),
                cookie_file=str(self.cookie_file),
            )
            first = strategy.ensure_session()

            # 另一实例改变文件大小，但强制保持 mtime_ns 不变。
            old_stat = self.auth_file.stat()
            external_store.save(_session("bbbb"))
            os.utime(self.auth_file, ns=(old_stat.st_atime_ns, old_stat.st_mtime_ns))
            second = strategy.ensure_session()
            self.assertIsNot(second, first)
            self.assertTrue(first.invalidated)
            self.assertEqual(second.token, "bbbb")

            # 再改变 mtime_ns，但保持 JSON 内容和文件大小不变。
            same_size_token = "cccc"
            old_stat = self.auth_file.stat()
            external_store.save(_session(same_size_token))
            self.assertEqual(self.auth_file.stat().st_size, old_stat.st_size)
            os.utime(
                self.auth_file,
                ns=(old_stat.st_atime_ns, old_stat.st_mtime_ns + 1_000_000_000),
            )
            third = strategy.ensure_session()
            self.assertIsNot(third, second)
            self.assertTrue(second.invalidated)
            self.assertEqual(third.token, same_size_token)


class TestDaemonAuthenticator(SessionTestBase):
    def test_authenticator_properties_cover_credentials_and_trusted_session(self):
        auth_manager = SimpleNamespace(auth_file=str(self.tmp / "auth.json"))
        account = {"id": "acc", "username": "user@example.com", "domain": "com"}
        strategy = ICloudAuthStrategy(
            auth_manager,
            account,
            session_file=str(self.auth_file),
            cookie_file=str(self.cookie_file),
        )
        authenticator = strategy.build_authenticator()
        self.assertFalse(authenticator.has_credentials)
        self.assertFalse(authenticator.can_attempt_login)

        self.store.save(_session())
        self.assertTrue(authenticator.can_attempt_login, "无密码的可信会话也应允许 daemon 尝试恢复")
        self.assertFalse(authenticator.has_credentials)

        self.store.save_pending({"flow": "2fa", "created_at": time.time(), "channels": []})
        self.assertFalse(authenticator.can_attempt_login, "网页二次验证进行中不得让 daemon 另行登录")
        self.store.clear_pending()

        with_password = ICloudAuthStrategy(
            auth_manager,
            dict(account, password="pw"),
            session_file=str(self.tmp / "other.json"),
            cookie_file=str(self.tmp / "other.lwp"),
        ).build_authenticator()
        self.assertTrue(with_password.has_credentials)
        self.assertTrue(with_password.can_attempt_login)


class TestHardAuthFailureBackoff(SessionTestBase):
    def test_signin_rejection_backs_off_and_manual_login_still_attempts(self):
        self.store.save(_session())
        attempts = []

        def failing_factory(*args, **kwargs):
            attempts.append(1)
            raise KeyError("salt")  # Apple 拒绝 signin/init 时缺 salt 字段

        client = ICloudClient(
            apple_id="user@example.com",
            password="pw",
            domain="com",
            session_path=self.auth_file,
            cookiejar_path=self.cookie_file,
            store=self.store,
            service_factory=failing_factory,
        )
        with self.assertRaises(HwCloudError) as ctx:
            client.ensure_service()
        self.assertIn("Apple 登录响应异常", str(ctx.exception))
        self.assertTrue(client.auth_backoff_active())

        with self.assertRaises(HwCloudError):
            client.ensure_service()
        self.assertEqual(len(attempts), 1, "退避期间心跳不得继续请求 Apple")

        with self.assertRaises(HwCloudError):
            client.login()
        self.assertEqual(len(attempts), 2, "网页手动登录必须能立即重试")


if __name__ == "__main__":
    unittest.main()
