#!/usr/bin/env python3
"""华为 CAS cookie jar 运行期落盘单测（T28.3，补丁 0004）。

缺口：cas_cookies.lwp 仅登录节点落盘；keepalive 心跳期间服务端轮替的
CASTGC 只进内存 jar，进程重启后轮替丢失。0004 在 HuaweiCasAuthenticator
增加 persist_cookie_jar_if_changed()（与磁盘有差异才写），并在 daemon
keepalive 成功后与静默重登成功后挂钩调用。
"""
import asyncio
import shutil
import sys
import tempfile
import unittest
from http.cookiejar import Cookie
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app" / "server"))

from hwcloudpd.auth import AuthManager  # noqa: E402
from hwcloudpd.cas_auth import HuaweiCasAuthenticator  # noqa: E402
from hwcloudpd.daemon import SyncDaemon  # noqa: E402
from hwcloudpd.models import SyncConfig  # noqa: E402
from hwcloudpd.store import StateStore  # noqa: E402


def _mk_cookie(name: str, value: str, domain="login.cloud.huawei.com") -> Cookie:
    return Cookie(
        version=0, name=name, value=value, port=None, port_specified=False,
        domain=domain, domain_specified=True, domain_initial_dot=True,
        path="/", path_specified=True, secure=False,
        expires=4102444800.0,  # 2100 年，避免 ignore_expires=False 时被丢
        discard=False, comment=None, comment_url=None, rest={}, rfc2109=False,
    )


class _StubNotifier:
    def notify(self, category, title, msg):
        pass

    def reset_auth_cooldown(self):
        pass


class TestPersistCookieJarIfChanged(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-cas28-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.am = AuthManager(self.tmp)
        self.jar_path = self.tmp / "cas_cookies.lwp"
        self.auth = HuaweiCasAuthenticator(self.am, cookie_jar_path=self.jar_path)

    def _disk_has(self, value: str) -> bool:
        return self.jar_path.exists() and value in self.jar_path.read_text(encoding="utf-8")

    def test_empty_jar_no_write(self):
        self.assertFalse(self.auth.persist_cookie_jar_if_changed())
        self.assertFalse(self.jar_path.exists(), "空 jar 不得写盘")

    def test_first_persist_writes(self):
        self.auth._cookie_jar.set_cookie(_mk_cookie("CASTGC", "tgt-v1"))
        self.assertTrue(self.auth.persist_cookie_jar_if_changed())
        self.assertTrue(self._disk_has("tgt-v1"))

    def test_no_diff_no_rewrite(self):
        self.auth._cookie_jar.set_cookie(_mk_cookie("CASTGC", "tgt-v1"))
        self.assertTrue(self.auth.persist_cookie_jar_if_changed())
        before = self.jar_path.read_text(encoding="utf-8")
        # 内容无变化时不得重写（T28.3b，避免心跳周期无谓 IO）
        self.assertFalse(self.auth.persist_cookie_jar_if_changed())
        self.assertEqual(before, self.jar_path.read_text(encoding="utf-8"))

    def test_castgc_rotation_persisted(self):
        """T28.3c：CASTGC 运行期轮替 → 差异落盘，重启加载不丢失。"""
        self.auth._cookie_jar.set_cookie(_mk_cookie("CASTGC", "tgt-v1"))
        self.auth.persist_cookie_jar_if_changed()
        # 模拟心跳响应轮替 CASTGC
        self.auth._cookie_jar.set_cookie(_mk_cookie("CASTGC", "tgt-v2-rotated"))
        self.assertTrue(self.auth.persist_cookie_jar_if_changed())
        self.assertTrue(self._disk_has("tgt-v2-rotated"))
        self.assertFalse(self._disk_has("tgt-v1"))

        # 重启语义：新 authenticator 从磁盘加载到轮替后的值
        fresh = HuaweiCasAuthenticator(self.am, cookie_jar_path=self.jar_path)
        values = {c.name: c.value for c in fresh._cookie_jar}
        self.assertEqual(values.get("CASTGC"), "tgt-v2-rotated")


class _RecordingAuthenticator:
    """daemon 挂钩验证桩：记录 persist 调用；can_attempt_login 控制重登分支。"""

    def __init__(self, can_login: bool):
        self.can_attempt_login = can_login
        self.has_credentials = can_login  # getattr default 分支求值需要
        self.persist_calls = 0
        self.login_calls = 0

    def persist_cookie_jar_if_changed(self) -> bool:
        self.persist_calls += 1
        return False

    def login(self, interactive=False):
        self.login_calls += 1


class TestDaemonHooks(unittest.TestCase):
    """T28.3a：keepalive 成功后与静默重登成功后必须调用 jar 落盘钩子。"""

    def _make_daemon(self, authenticator, heartbeat_fn) -> SyncDaemon:
        tmp = Path(tempfile.mkdtemp(prefix="albumsync-casd-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        client = type("StubClient", (), {"heartbeat_check": staticmethod(heartbeat_fn)})
        return SyncDaemon(
            SyncConfig(config_dir=tmp, directory=tmp),
            AuthManager(tmp),
            client(),
            StateStore(tmp / "state.db"),
            _StubNotifier(),
            authenticator=authenticator,
        )

    def test_keepalive_success_calls_persist(self):
        auth = _RecordingAuthenticator(can_login=False)

        def heartbeat():
            return True

        d = self._make_daemon(auth, heartbeat)
        ok = asyncio.run(d.keepalive_step())
        self.assertTrue(ok)
        self.assertEqual(auth.persist_calls, 1, "心跳成功后应调用 jar 落盘钩子")

    def test_silent_relogin_calls_persist(self):
        auth = _RecordingAuthenticator(can_login=True)

        def heartbeat():
            return True

        d = self._make_daemon(auth, heartbeat)
        # 直接走 _try_silent_auto_relogin：authenticator 可登录 → login → persist → heartbeat
        ok = asyncio.run(d._try_silent_auto_relogin())
        self.assertTrue(ok)
        self.assertEqual(auth.login_calls, 1)
        self.assertEqual(auth.persist_calls, 1, "静默重登成功后应调用 jar 落盘钩子")


if __name__ == "__main__":
    unittest.main()
