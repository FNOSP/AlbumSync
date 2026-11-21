#!/usr/bin/env python3
"""小米会话轮替落盘单测（T28.1）。

端到端链路：本地 HTTP 服务在响应头携带 Set-Cookie 模拟小米服务端轮替
serviceToken → XiaomiClient cookiejar 经 HTTPCookieProcessor 自动更新
→ 会话观察器比对快照发现变化 → 回调（生产中为 store.save 原子落盘）
→ 新建 client（进程重启语义）从磁盘加载到新 token。

域注入：测试服务器 cookie 域为 127.0.0.1，构造 client 时以
session_cookie_domain="127.0.0.1" 让导入 cookie 与观察快照同域。
"""
import asyncio
import json
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app" / "server"))

from providers.xiaomi import XiaomiAuthStrategy, XiaomiProvider, XiaomiSessionStore  # noqa: E402
from providers.xiaomi.xiaomi_client import (  # noqa: E402
    XiaomiAPIError,
    XiaomiAuthExpiredError,
    XiaomiClient,
    validate_session_cookies,
)
from hwcloudpd.models import AuthExpiredError, SyncConfig  # noqa: E402
from hwcloudpd.auth import AuthManager  # noqa: E402
from hwcloudpd.daemon import SyncDaemon  # noqa: E402
from hwcloudpd.store import StateStore  # noqa: E402

TEST_DOMAIN = "127.0.0.1"
INITIAL = {"userId": "196519672", "serviceToken": "token-v1"}
ROTATED = "token-v2"


def _make_handler(set_cookie_value: str | None):
    """构造模拟小米 API 的 handler：set_cookie_value=None 不轮替，否则回发该值。"""

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps({"result": "ok", "data": {"albums": []}}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if set_cookie_value is not None:
                self.send_header("Set-Cookie", f"serviceToken={set_cookie_value}; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # 静默测试输出
            pass

    return _Handler


class XiaomiRotationTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-mi28-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.auth_file = self.tmp / "xiaomi_acc-t28_auth.json"
        self.store = XiaomiSessionStore(self.auth_file)
        self.store.save(INITIAL)
        self.events: list[dict] = []

        def observer(cookies):
            self.events.append(dict(cookies))
            self.store.save(cookies)  # 与生产 XiaomiAuthStrategy._on_session_rotated 同构

        self.observer = observer

    def _start_server(self, set_cookie_value: str | None) -> str:
        srv = ThreadingHTTPServer((TEST_DOMAIN, 0), _make_handler(set_cookie_value))
        self.addCleanup(srv.server_close)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        self.addCleanup(srv.shutdown)
        return f"http://{TEST_DOMAIN}:{srv.server_port}"

    def _disk_token(self) -> str:
        return self.store.load_cookies().get("serviceToken", "")


class TestSessionRotationPersistence(XiaomiRotationTestBase):
    def test_rotation_persisted_to_disk(self):
        """T28.1a/b：轮替响应 → 观察器触发 → 磁盘更新（userId 等未变键保留）。"""
        base = self._start_server(set_cookie_value=ROTATED)
        client = XiaomiClient(
            INITIAL, session_observer=self.observer, session_cookie_domain=TEST_DOMAIN,
        )
        client._get(f"{base}/gallery/user/album/list", {"pageNum": 0})

        self.assertEqual(len(self.events), 1, "轮替应触发恰好一次观察器回调")
        self.assertEqual(self.events[0]["serviceToken"], ROTATED)
        self.assertEqual(self.events[0]["userId"], "196519672", "未轮替的键必须保留")
        self.assertEqual(self._disk_token(), ROTATED)

    def test_reload_picks_new_token_after_restart(self):
        """T28.1c：落盘后「重启」——从磁盘重建 client 加载新 token。"""
        base = self._start_server(set_cookie_value=ROTATED)
        client = XiaomiClient(
            INITIAL, session_observer=self.observer, session_cookie_domain=TEST_DOMAIN,
        )
        client._get(f"{base}/gallery/user/album/list", {"pageNum": 0})

        fresh = XiaomiClient(self.store.load_cookies(), session_cookie_domain=TEST_DOMAIN)
        self.assertEqual(fresh.get_cookie_value("serviceToken"), ROTATED)
        ok, err = validate_session_cookies(self.store.load_cookies())
        self.assertTrue(ok, err)

    def test_no_rotation_no_write(self):
        """无 Set-Cookie 的正常响应不得触发观察器/写盘。"""
        base = self._start_server(set_cookie_value=None)
        client = XiaomiClient(
            INITIAL, session_observer=self.observer, session_cookie_domain=TEST_DOMAIN,
        )
        client._get(f"{base}/gallery/user/album/list", {"pageNum": 0})
        client._get(f"{base}/gallery/user/album/list", {"pageNum": 1})

        self.assertEqual(self.events, [])
        self.assertEqual(self._disk_token(), "token-v1")

    def test_rotation_same_value_not_rewritten(self):
        """Set-Cookie 值与现有相同（服务端重发）不视为轮替。"""
        base = self._start_server(set_cookie_value="token-v1")
        client = XiaomiClient(
            INITIAL, session_observer=self.observer, session_cookie_domain=TEST_DOMAIN,
        )
        client._get(f"{base}/gallery/user/album/list", {"pageNum": 0})
        self.assertEqual(self.events, [])
        self.assertEqual(self._disk_token(), "token-v1")

    def test_observer_failure_does_not_break_request(self):
        """观察器回调抛异常只告警，不影响本次请求结果。"""
        base = self._start_server(set_cookie_value=ROTATED)

        def bad_observer(_cookies):
            raise RuntimeError("disk on fire")

        client = XiaomiClient(
            INITIAL, session_observer=bad_observer, session_cookie_domain=TEST_DOMAIN,
        )
        data = client._get(f"{base}/gallery/user/album/list", {"pageNum": 0})
        self.assertEqual(data.get("result"), "ok")


class TestStrategyWiring(XiaomiRotationTestBase):
    def test_strategy_client_carries_observer(self):
        """策略构造的 client 必须挂上轮替观察器（接线不回归）。"""
        strat = XiaomiAuthStrategy(None, {"id": "acc-t28", "auth_file": str(self.auth_file)})
        client = strat._client_or_raise()
        self.assertIsNotNone(client._session_observer)
        self.assertTrue(client._session_observer == strat._on_session_rotated)

    def test_strategy_callback_persists_rotation(self):
        """策略回调 → store 落盘（生产接线即 client 观察器 → 本回调）。"""
        strat = XiaomiAuthStrategy(None, {"id": "acc-t28", "auth_file": str(self.auth_file)})
        rotated_full = dict(INITIAL, serviceToken=ROTATED, slh="abc")
        strat._on_session_rotated(rotated_full)

        on_disk = self.store.load_cookies()
        self.assertEqual(on_disk["serviceToken"], ROTATED)
        self.assertEqual(on_disk["userId"], "196519672")
        self.assertEqual(on_disk["slh"], "abc")

    def test_import_wired_client_uses_observer(self):
        """import_session 构造的 client 同样走 _new_client（观察器接线）。"""
        strat = XiaomiAuthStrategy(None, {"id": "acc-t28", "auth_file": str(self.auth_file)})
        # 绕过探活网络调用：直接模拟 import_session 的 client 构造分支
        strat._client = strat._new_client(INITIAL)
        self.assertTrue(strat._client._session_observer == strat._on_session_rotated)


class TestAuthExpiredHierarchy(unittest.TestCase):
    """T28.2a：异常类型对齐引擎——引擎 sync/daemon 的 AuthExpiredError
    专断分支必须能捕获小米失效。"""

    def test_xiaomi_auth_expired_is_engine_auth_expired(self):
        from hwcloudpd.models import HwCloudError

        self.assertTrue(issubclass(XiaomiAuthExpiredError, AuthExpiredError))
        self.assertTrue(issubclass(XiaomiAuthExpiredError, HwCloudError))
        # 引擎下载循环 `except AuthExpiredError: raise` 捕获面验证
        with self.assertRaises(AuthExpiredError):
            try:
                raise XiaomiAuthExpiredError("serviceToken 已失效")
            except AuthExpiredError:
                raise


class _StubNotifier:
    def __init__(self):
        self.notifications = []

    def notify(self, category, title, msg):
        self.notifications.append((category, title, str(msg)))

    def reset_auth_cooldown(self):
        pass


class TestDaemonAuthHandling(unittest.TestCase):
    """T28.2b：daemon 对小米账号 auth 失效的处理路径。

    小米 authenticator=None（build_authenticator 桩 can_attempt_login=False），
    keepalive_step 收到 AuthExpiredError 必须走「标记失效 + 通知」，而非
    transient 分支静默保持。"""

    def _make_daemon(self, heartbeat_fn) -> SyncDaemon:
        tmp = Path(tempfile.mkdtemp(prefix="albumsync-mid-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        client = type("StubClient", (), {"heartbeat_check": staticmethod(heartbeat_fn)})
        notifier = _StubNotifier()
        daemon = SyncDaemon(
            SyncConfig(config_dir=tmp, directory=tmp),
            AuthManager(tmp),
            client(),
            StateStore(tmp / "state.db"),
            notifier,
            authenticator=None,  # 小米路径：无静默重登
        )
        return daemon

    def test_auth_expired_marks_invalid_and_notifies(self):
        def heartbeat():
            raise XiaomiAuthExpiredError("serviceToken 已失效")

        d = self._make_daemon(heartbeat)
        ok = asyncio.run(d.keepalive_step())
        self.assertFalse(ok)
        self.assertFalse(d._auth_valid, "失效必须标记 _auth_valid=False")
        cats = [c for c, *_ in d.notifier.notifications]
        self.assertIn("auth_expired", cats, "失效必须发出通知")

    def test_transient_error_does_not_notify_auth_expired(self):
        def heartbeat():
            raise XiaomiAPIError(0, "网络错误")

        d = self._make_daemon(heartbeat)
        ok = asyncio.run(d.keepalive_step())
        self.assertFalse(ok)  # 初始 _auth_valid=False，transient 保持原状
        self.assertEqual(d.notifier.notifications, [], "网络错误不得触发失效通知")
        self.assertIn("网络错误", d._last_error)


class TestDaemonStopAbortNoise(unittest.TestCase):
    """T31.9：停止/热重载后残留同步线程触碰已关闭 state.db → 降噪处理。

    停止语义（0.1.7）：join(5s) 后不再等待同步周期跑完；随后触碰已关闭的
    state.db 抛 sqlite3.ProgrammingError 属预期中止——数据无损（WAL 原子），
    不得发 sync_error 通知、不得写 _last_error、不得留 exception 裸 traceback。
    """

    def _make_daemon(self, engine) -> SyncDaemon:
        tmp = Path(tempfile.mkdtemp(prefix="albumsync-mid2-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        daemon = SyncDaemon(
            SyncConfig(config_dir=tmp, directory=tmp),
            AuthManager(tmp),
            type("StubClient", (), {"heartbeat_check": staticmethod(lambda: True)})(),
            StateStore(tmp / "state.db"),
            _StubNotifier(),
            engine_factory=lambda: engine,
        )
        return daemon

    def _closed_db_engine(self):
        def run_once(force_full_scan=False):
            raise sqlite3.ProgrammingError("Cannot operate on a closed database.")
        return type("StubEngine", (), {"run_once": staticmethod(run_once)})()

    def test_closed_db_aborts_quietly(self):
        d = self._make_daemon(self._closed_db_engine())
        with self.assertLogs("hwcloudpd.daemon", level="INFO") as logs:
            report = asyncio.run(d.execute_sync_once())
        self.assertIsNone(report)
        self.assertEqual(d.notifier.notifications, [],
                         "停止中止不得发 sync_error 通知")
        self.assertEqual(d._last_error, "", "停止中止不得写 _last_error")
        self.assertTrue(any("aborted" in m for m in logs.output),
                        f"应记录降噪 INFO 而非 exception: {logs.output}")


class TestHeartbeatSemantics(XiaomiRotationTestBase):
    """T28.2b：XiaomiProvider.heartbeat_check 对齐华为语义（True 或抛 AuthExpiredError）。"""

    def _provider(self, auth_file: Path) -> XiaomiProvider:
        return XiaomiProvider(None, {"id": "acc-t28", "auth_file": str(auth_file)})

    def test_no_session_raises_auth_expired(self):
        prov = self._provider(self.tmp / "missing.json")
        with self.assertRaises(AuthExpiredError):
            prov.heartbeat_check()

    def test_expired_session_raises_xiaomi_auth_expired(self):
        prov = self._provider(self.auth_file)  # setUp 已写入 INITIAL 会话
        client = prov.auth_strategy._client_or_raise()
        client.get_album_list = lambda: (_ for _ in ()).throw(
            XiaomiAuthExpiredError("expired"))

        with self.assertRaises(AuthExpiredError):
            prov.heartbeat_check()

    def test_healthy_session_returns_true(self):
        prov = self._provider(self.auth_file)
        client = prov.auth_strategy._client_or_raise()
        client.get_album_list = lambda: []

        self.assertTrue(prov.heartbeat_check())


class TestProbeConvergence(XiaomiRotationTestBase):
    """T28.5a：探活收敛——下载循环不再逐张探活，失效由异常驱动 + 一次重试。"""

    def _provider(self) -> XiaomiProvider:
        return XiaomiProvider(None, {"id": "acc-t28", "auth_file": str(self.auth_file)})

    def test_ensure_session_no_probe_by_default(self):
        prov = self._provider()
        client = prov.auth_strategy.ensure_session()
        calls = []
        client.probe_session = lambda: calls.append(1) or True

        prov.auth_strategy.ensure_session()
        prov.auth_strategy.ensure_session()
        self.assertEqual(calls, [], "默认不探活：下载循环逐张探活必须收敛")

    def test_ensure_session_probe_flag(self):
        prov = self._provider()
        client = prov.auth_strategy.ensure_session()
        client.probe_session = lambda: False

        with self.assertRaises(AuthExpiredError):
            prov.auth_strategy.ensure_session(probe=True)
        self.assertIsNone(prov.auth_strategy._client, "探活失败必须重置缓存 client")

    def test_auth_retry_retries_after_successful_probe(self):
        prov = self._provider()
        client = prov.auth_strategy._client_or_raise()
        client.probe_session = lambda: True

        attempts = []

        def flaky():
            attempts.append(1)
            if len(attempts) == 1:
                raise XiaomiAuthExpiredError("中途轮替 401")
            return "ok"

        self.assertEqual(prov._auth_retry(flaky), "ok")
        self.assertEqual(len(attempts), 2, "探活通过后应重试一次")

    def test_auth_retry_raises_when_probe_fails(self):
        prov = self._provider()
        client = prov.auth_strategy._client_or_raise()
        client.probe_session = lambda: False

        def always_expired():
            raise XiaomiAuthExpiredError("真失效")

        with self.assertRaises(AuthExpiredError):
            prov._auth_retry(always_expired)


class TestAuthFileExternalUpdate(unittest.TestCase):
    """auth_file 被外部更新时内存 client 必须失效重建（NAS 真机 401 根因回归）。

    案发链路：import API 与 daemon 各持一个 XiaomiAuthStrategy 实例（共享
    同一 auth_file）。import 只刷新了 API 侧实例的内存 client，daemon 侧
    实例永远缓存旧 token client → 探活 401 至天荒地老，尽管文件已是新值。
    """

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="xiaomi-authfile-")
        self.auth_file = str(Path(self._tmp) / "xiaomi_t_auth.json")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _strategy(self) -> XiaomiAuthStrategy:
        return XiaomiAuthStrategy(None, {"id": "acc-t", "auth_file": self.auth_file})

    def test_external_store_write_rebuilds_cached_client(self):
        store = XiaomiSessionStore(self.auth_file)
        store.save({"userId": "111", "serviceToken": "old"})
        s = self._strategy()
        c1 = s.ensure_session()
        self.assertEqual(c1.get_cookie_value("serviceToken"), "old")

        store.save({"userId": "222", "serviceToken": "new"})  # 另一实例写入
        c2 = s.ensure_session()
        self.assertIsNot(c2, c1, "文件变更后必须重建 client")
        self.assertEqual(c2.get_cookie_value("serviceToken"), "new")
        self.assertEqual(c2.get_cookie_value("userId"), "222")

    def test_two_strategies_share_file_see_each_others_import(self):
        # provider 侧 strategy 先持有旧 token client（daemon 长驻语义）
        XiaomiSessionStore(self.auth_file).save(
            {"userId": "111", "serviceToken": "old"}
        )
        s_provider = self._strategy()
        c_old = s_provider.ensure_session()
        self.assertEqual(c_old.get_cookie_value("serviceToken"), "old")

        # runtime 侧 strategy（import API 用）导入新会话 → 落盘
        # （import_session 内部会探活打网络，测试桩掉）
        s_runtime = self._strategy()
        orig_new = s_runtime._new_client

        def fake_new(cookies):
            c = orig_new(cookies)
            c.probe_session = lambda: True
            return c

        s_runtime._new_client = fake_new
        s_runtime.import_session("userId=222; serviceToken=new")

        # daemon 侧下一次取 client 必须拿到新 token，而非继续用旧缓存
        c_new = s_provider.ensure_session()
        self.assertEqual(c_new.get_cookie_value("serviceToken"), "new")

    def test_rotation_write_does_not_spuriously_rebuild(self):
        s = self._strategy()
        XiaomiSessionStore(self.auth_file).save(
            {"userId": "111", "serviceToken": "t1"}
        )
        c1 = s.ensure_session()
        # 本实例观察器落盘（mtime 变化）后取 client：同一对象，不重建
        # （直接调观察器不经过 HTTP Set-Cookie，内存 jar 保持 t1）
        s._on_session_rotated({"userId": "111", "serviceToken": "t2"})
        c2 = s._client_or_raise()
        self.assertIs(c2, c1, "自身轮替落盘不应触发重建")
        self.assertEqual(c1.get_cookie_value("serviceToken"), "t1")

    def test_file_deleted_invalidates_cached_client(self):
        XiaomiSessionStore(self.auth_file).save(
            {"userId": "111", "serviceToken": "t1"}
        )
        s = self._strategy()
        s.ensure_session()
        s.store.clear()  # 外部删除（invalidate 语义）
        with self.assertRaises(AuthExpiredError):
            s.ensure_session()

    def test_client_user_id_property(self):
        c = XiaomiClient({"userId": "196519672", "serviceToken": "x"},
                         session_cookie_domain=TEST_DOMAIN)
        self.assertEqual(c.user_id, "196519672")
        self.assertEqual(XiaomiClient(session_cookie_domain=TEST_DOMAIN).user_id, "")


if __name__ == "__main__":
    unittest.main()
