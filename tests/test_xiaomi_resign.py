#!/usr/bin/env python3
"""passToken 静默重签单测（T31.7）。

场景（对齐真机故障：扫码会话 ~35 分钟后服务端作废 serviceToken）：
album/list 401 + Set-Cookie 清除 serviceToken → XiaomiClient._get 捕获鉴权
失效 → 凭登录域 passToken 走 serviceLogin(_json) → STS 302 链换新 token →
写回 jar + 观察器落盘（保留 passToken）→ 重试原请求成功。

域注入：测试服务器 host 127.0.0.1，client 以 session_cookie_domain 与
account_cookie_domain 均注入 127.0.0.1（生产默认 i.mi.com / .account.xiaomi.com）。
"""
import hashlib
import json
import shutil
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app" / "server"))

from providers.xiaomi import XiaomiProvider, XiaomiSessionStore  # noqa: E402
from providers.xiaomi.qr_login import (  # noqa: E402
    XiaomiQRLoginError,
    resign_session_cookies,
)
from providers.xiaomi.xiaomi_client import (  # noqa: E402
    XiaomiAPIError,
    XiaomiAuthExpiredError,
    XiaomiClient,
)

GOOD = "token-good"
DEAD = "token-dead"
PASS = "V1:passtoken-test"
UID = "196519672"


def _make_handler(port_holder: list[int], sl_counter: list[int] | None = None):
    """模拟小米：无效 token → 401+清除 cookie+D；有效 → 200。

    sl_counter：/pass/serviceLogin 命中计数（冷却语义测试用）。
    """

    class _Handler(BaseHTTPRequestHandler):
        def _json(self, status: int, payload: dict, *set_cookies: str) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            for sc in set_cookies:
                self.send_header("Set-Cookie", sc)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlparse(self.path).path
            port = port_holder[0]
            cookie = self.headers.get("Cookie", "")
            if path == "/gallery/user/album/list":
                if f"serviceToken={GOOD}" in cookie:
                    self._json(200, {"result": "ok",
                                     "data": {"albums": [{"albumId": "0"}]}})
                elif "serviceToken=LIMITED" in cookie:
                    # 真机实测形态（T31.10）：高频扫码+重签触发限流，业务接口
                    # 返回 10001 系统错误
                    self._json(200, {"result": "error", "code": 10001,
                                     "desc": "系统错误"})
                else:
                    d = (f"http://127.0.0.1:{port}/pass/serviceLogin"
                         f"?callback=http%3A%2F%2F127.0.0.1%3A{port}%2Fsts"
                         f"%3Fsign%3DSIG&sid=i.mi.com"
                         f"&_group=DEFAULT&checkSafePhone=true&_bal=true")
                    self._json(
                        401, {"R": 401, "S": "Err", "D": d},
                        f"serviceToken=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                    )
            elif path == "/pass/serviceLogin":
                if sl_counter is not None:
                    sl_counter[0] += 1
                if "checkSafePhone=true" in self.path:
                    # 真机实测形态（T31.9）：D URL（含 checkSafePhone/_bal）对任何
                    # 凭据都返回 code=0 成功但无 location（不签发 STS）
                    self._json(200, {"code": 0, "desc": "成功", "result": "ok"})
                elif f"passToken={PASS}" in cookie and f"userId={UID}" in cookie:
                    self._json(200, {"code": 0,
                                     "location": f"http://127.0.0.1:{port}/sts?sign=NEW"})
                elif "passToken=V1:EXPIRED" in cookie:
                    # 真机实测形态（T31.9）：passToken 失效 → 70016 + 登录页 location
                    self._json(200, {"code": 70016, "desc": "登录验证失败",
                                     "result": "error",
                                     "location": f"http://127.0.0.1:{port}/fe/service/login"})
                elif "passToken=V1:BOTHFAIL" in cookie:
                    # 两个入口都 code=0 无 location 的极端形态
                    self._json(200, {"code": 0, "desc": "成功", "result": "ok"})
                else:
                    self._json(200, {"code": 10025, "desc": "Callback连接不合法"})
            elif path == "/sts":
                self.send_response(302)
                self.send_header("Set-Cookie", f"serviceToken={GOOD}; Path=/")
                self.send_header("Set-Cookie", f"userId={UID}; Path=/")
                self.send_header("Location", f"http://127.0.0.1:{port}/final")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif path == "/final":
                self._json(200, {"ok": 1})
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

        def log_message(self, *args):  # 静默测试输出
            pass

    return _Handler


class ResignTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-mi317-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.auth_file = self.tmp / "xiaomi_acc-t317_auth.json"
        self.store = XiaomiSessionStore(self.auth_file)
        self.events: list[dict] = []

        def observer(cookies):
            self.events.append(dict(cookies))
            self.store.save(cookies)  # 与生产 _on_session_rotated 同构

        port_holder: list[int] = [0]
        self.sl_counter = [0]
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(port_holder, self.sl_counter))
        self.addCleanup(srv.server_close)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        self.addCleanup(srv.shutdown)
        port_holder[0] = srv.server_port
        self.base = f"http://127.0.0.1:{srv.server_port}"

        self.client = XiaomiClient(
            {"userId": UID, "serviceToken": DEAD, "passToken": PASS},
            session_observer=observer,
            session_cookie_domain="127.0.0.1",
            account_cookie_domain="127.0.0.1",
            request_delay_ms=0,
            service_login_base=self.base,
            probe_base=self.base,
        )

    def _disk(self) -> dict[str, str]:
        return self.store.load_cookies()


class TestAutoResign(ResignTestBase):
    def _list(self) -> dict:
        """直调 _get 指向本地服务器（get_album_list 硬编码 API_BASE=i.mi.com）。"""
        return self.client._get(f"{self.base}/gallery/user/album/list", {"pageNum": 0})

    def test_dead_token_resigned_and_retried(self):
        """死 token + passToken → 自动重签 → 重试成功，磁盘更新且保留 passToken。"""
        data = self._list()
        self.assertEqual((data.get("data") or {}).get("albums"), [{"albumId": "0"}],
                         "重签后重试应成功")
        self.assertEqual(self.client.get_cookie_value("serviceToken"), GOOD)
        self.assertEqual(self.client.get_cookie_value("passToken"), PASS)
        self.assertEqual(len(self.events), 1, "重签应触发恰好一次观察器落盘")
        self.assertEqual(self.events[0]["serviceToken"], GOOD)
        self.assertEqual(self.events[0]["passToken"], PASS, "落盘必须保留 passToken")
        self.assertEqual(self._disk().get("serviceToken"), GOOD)
        self.assertEqual(self._disk().get("passToken"), PASS)

    def test_no_passthoken_keeps_raise(self):
        """无 passToken（浏览器导入语义）→ 401 原样抛出，行为不变。"""
        client = XiaomiClient(
            {"userId": UID, "serviceToken": DEAD},
            session_cookie_domain="127.0.0.1",
            account_cookie_domain="127.0.0.1",
            request_delay_ms=0,
            service_login_base=self.base,
        )
        with self.assertRaises(XiaomiAuthExpiredError):
            client._get(f"{self.base}/gallery/user/album/list", {"pageNum": 0})

    def test_wrong_passtoken_resign_fails_raises(self):
        """passToken 无效（serviceLogin 拒绝）→ 重签失败 → 原样抛出。"""
        client = XiaomiClient(
            {"userId": UID, "serviceToken": DEAD, "passToken": "V1:WRONG"},
            session_cookie_domain="127.0.0.1",
            account_cookie_domain="127.0.0.1",
            request_delay_ms=0,
            service_login_base=self.base,
        )
        with self.assertRaises(XiaomiAuthExpiredError):
            client._get(f"{self.base}/gallery/user/album/list", {"pageNum": 0})

    def test_probe_session_recovers_via_resign(self):
        """daemon 探活语义：probe_session 在死 token + passToken 下应恢复为 True。"""
        import unittest.mock as mock
        with mock.patch("providers.xiaomi.xiaomi_client.API_BASE", self.base):
            self.assertTrue(self.client.probe_session())

    def test_auto_resign_recovers_via_fallback(self):
        """端到端（T31.9）：401 D URL 为「code=0 无 location」形态时，自动重签
        走标准入口回退拿 STS，重试原请求成功。"""
        data = self._list()
        self.assertEqual((data.get("data") or {}).get("albums"), [{"albumId": "0"}])
        self.assertEqual(self.client.get_cookie_value("serviceToken"), GOOD)

    def test_cookie_domain_routing(self):
        """set_cookies 域分流：passToken 仅登录域；userId 双域；其余会话域。"""
        client = XiaomiClient(
            {"userId": UID, "serviceToken": DEAD, "passToken": PASS},
            session_cookie_domain="i.mi.com",
        )
        domains: dict[str, set[str]] = {}
        for c in client.cookiejar:
            domains.setdefault(c.name, set()).add(c.domain or "")
        self.assertEqual(domains["passToken"], {".account.xiaomi.com"})
        self.assertEqual(domains["userId"], {"i.mi.com", ".account.xiaomi.com"})
        self.assertEqual(domains["serviceToken"], {"i.mi.com"})


class TestResignHelper(ResignTestBase):
    def test_helper_success_flow(self):
        """resign_session_cookies 直接调用：D URL → location → STS → 新 token。"""
        d = (f"{self.base}/pass/serviceLogin"
             f"?callback=http%3A%2F%2F127.0.0.1%3A{urlparse(self.base).port}%2Fsts"
             f"%3Fsign%3DSIG&sid=i.mi.com")
        cookies = resign_session_cookies(PASS, UID, d, account_domain="127.0.0.1")
        self.assertEqual(cookies["serviceToken"], GOOD)
        self.assertEqual(cookies["userId"], UID)
        self.assertEqual(cookies["passToken"], PASS)

    def test_helper_requires_credentials(self):
        with self.assertRaises(XiaomiQRLoginError):
            resign_session_cookies("", UID, account_domain="127.0.0.1")

    def test_helper_rejected_without_valid_passtoken(self):
        """passToken 错误 → serviceLogin code 10025 → 抛错。"""
        with self.assertRaises(XiaomiQRLoginError):
            resign_session_cookies(
                "V1:WRONG", UID, f"{self.base}/pass/serviceLogin?x=1",
                account_domain="127.0.0.1")

    def test_helper_expired_passtoken_names_70016_and_action(self):
        """失效形态（真机 70016）→ 文案指明出路，不再打出自相矛盾的成功码。"""
        with self.assertRaises(XiaomiQRLoginError) as cm:
            resign_session_cookies(
                "V1:EXPIRED", UID, f"{self.base}/pass/serviceLogin?x=1",
                account_domain="127.0.0.1")
        msg = str(cm.exception)
        self.assertIn("70016", msg)
        self.assertIn("重新扫码", msg)
        self.assertNotIn("成功", msg)

    def test_helper_fallback_recovers_when_d_url_has_no_sts(self):
        """真机实测形态（T31.9）：D URL（含 checkSafePhone/_bal）返回 code=0 无
        location → 自动回退标准入口拿 STS，重签成功。"""
        d = (f"{self.base}/pass/serviceLogin?callback=x&sid=i.mi.com"
             f"&_group=DEFAULT&checkSafePhone=true&_bal=true")
        cookies = resign_session_cookies(PASS, UID, d, account_domain="127.0.0.1")
        self.assertEqual(cookies["serviceToken"], GOOD)
        self.assertEqual(cookies["userId"], UID)
        self.assertEqual(cookies["passToken"], PASS)

    def test_helper_both_entries_without_sts_raises_with_action(self):
        """两个入口都 code=0 无 location → 文案指明出路，不再打「失败: code=0 成功」。"""
        with self.assertRaises(XiaomiQRLoginError) as cm:
            resign_session_cookies(
                "V1:BOTHFAIL", UID, f"{self.base}/pass/serviceLogin?x=1",
                account_domain="127.0.0.1")
        msg = str(cm.exception)
        self.assertIn("STS", msg)
        self.assertIn("重新扫码", msg)
        self.assertNotIn("code=0 成功", msg)


class TestProactiveRefreshAndCooldown(ResignTestBase):
    """T31.9：预防性续期（心跳主动续签）+ 重签失败冷却。

    真机实测：失效后被动重签会被小米风控逐步升级（安全验证 → passToken
    作废），而签发后短窗口内重签可成功——故会话超龄即在心跳中预防性续签
    （对齐浏览器持续续期语义），失败则冷却停止轰炸。
    """

    def test_refresh_session_success_bumps_age(self):
        """refresh_session（无 pending，仅标准入口）→ serviceToken 更新 + 年龄归零。"""
        self.client.updated_at -= 700
        self.assertTrue(self.client.refresh_session())
        self.assertEqual(self.client.get_cookie_value("serviceToken"), GOOD)
        self.assertLess(self.client.session_age_sec(), 10)
        self.assertEqual(self._disk().get("serviceToken"), GOOD)

    def test_resign_failure_enters_cooldown(self):
        """重签失败进入冷却：冷却期内不再发 serviceLogin 请求（防风控升级）。"""
        client = XiaomiClient(
            {"userId": UID, "serviceToken": DEAD, "passToken": "V1:BOTHFAIL"},
            session_cookie_domain="127.0.0.1",
            account_cookie_domain="127.0.0.1",
            request_delay_ms=0,
            service_login_base=self.base,
        )
        base_n = self.sl_counter[0]
        with self.assertRaises(XiaomiAuthExpiredError):
            client._get(f"{self.base}/gallery/user/album/list", {"pageNum": 0})
        first = self.sl_counter[0] - base_n
        self.assertGreaterEqual(first, 2, "首次重签应尝试 D URL + 标准入口两个候选")
        with self.assertRaises(XiaomiAuthExpiredError):
            client._get(f"{self.base}/gallery/user/album/list", {"pageNum": 0})
        self.assertEqual(self.sl_counter[0], base_n + first,
                         "冷却期内不得再发 serviceLogin 请求")

    def _provider_with_session(self, service_token: str) -> XiaomiProvider:
        """Provider + 本地域 client（生产域 cookie 不会发往 127.0.0.1 mock，
        故直接注入与 ResignTestBase 同构的 client，策略 mtime 基线对齐）。"""
        self.store.save({"userId": UID, "serviceToken": service_token,
                         "passToken": PASS})
        prov = XiaomiProvider(None, {"id": "acc-t319", "auth_file": str(self.auth_file)})
        strategy = prov.auth_strategy
        client = XiaomiClient(
            {"userId": UID, "serviceToken": service_token, "passToken": PASS},
            session_observer=lambda c: self.store.save(c),
            session_cookie_domain="127.0.0.1",
            account_cookie_domain="127.0.0.1",
            request_delay_ms=0,
            service_login_base=self.base,
            probe_base=self.base,
        )
        client.get_album_list = lambda: client._get(
            f"{self.base}/gallery/user/album/list", {"pageNum": 0})
        strategy._client = client
        strategy._client_file_mtime = strategy._auth_file_mtime()
        return prov

    def test_heartbeat_proactively_refreshes_old_session(self):
        """会话超龄（>30 天，等效停用阈值以上）→ 心跳仍走预防性重签路径。"""
        prov = self._provider_with_session(GOOD)
        client = prov.auth_strategy._client_or_raise()
        client.updated_at -= 2592001
        n0 = self.sl_counter[0]
        self.assertTrue(prov.heartbeat_check())
        self.assertGreater(self.sl_counter[0], n0, "超龄会话应在心跳中预防性重签")
        self.assertLess(client.session_age_sec(), 10)
        self.assertEqual(client.get_cookie_value("serviceToken"), GOOD)

    def test_heartbeat_skips_refresh_for_fresh_session(self):
        """新鲜会话 → 心跳只探活，不发 serviceLogin。"""
        prov = self._provider_with_session(GOOD)
        client = prov.auth_strategy._client_or_raise()
        n0 = self.sl_counter[0]
        self.assertTrue(prov.heartbeat_check())
        self.assertEqual(self.sl_counter[0], n0, "新鲜会话不得触发预防性重签")


class TestRiskState(ResignTestBase):
    """T31.10：小米风控限流检测 → auth_status/UI 倒计时数据链。"""

    def test_10001_sets_rate_limited_risk(self):
        """album/list 返回 10001 → 记录 rate_limited + 恢复时间戳。"""
        self.client.set_cookies({"userId": UID, "serviceToken": "LIMITED",
                                 "passToken": PASS})
        with self.assertRaises(XiaomiAPIError):
            self.client._get(f"{self.base}/gallery/user/album/list", {"pageNum": 0})
        risk = self.client.risk_state()
        self.assertEqual(risk["kind"], "rate_limited")
        self.assertGreater(risk["retry_after_ts"], time.time())

    def test_success_clears_risk_state(self):
        """限流解除后一次成功请求即清除风控状态（避免倒计时误导）。"""
        self.client.set_cookies({"userId": UID, "serviceToken": "LIMITED",
                                 "passToken": PASS})
        with self.assertRaises(XiaomiAPIError):
            self.client._get(f"{self.base}/gallery/user/album/list", {"pageNum": 0})
        self.client.set_cookies({"userId": UID, "serviceToken": GOOD,
                                 "passToken": PASS})
        self.client._get(f"{self.base}/gallery/user/album/list", {"pageNum": 0})
        self.assertEqual(self.client.risk_state()["kind"], "")

    def test_strategy_session_info_carries_risk(self):
        """strategy.session_info 透传 risk；risk_state 从当前 client 读取。"""
        self.store.save({"userId": UID, "serviceToken": GOOD, "passToken": PASS})
        prov = XiaomiProvider(None, {"id": "acc-t310c", "auth_file": str(self.auth_file)})
        stub = type("StubClient", (), {
            "user_id": UID, "updated_at": 123.0,
            "risk_state": staticmethod(
                lambda: {"kind": "rate_limited", "retry_after_ts": 99.0}),
        })()
        info = prov.auth_strategy.session_info(stub)
        self.assertEqual(info["risk"]["kind"], "rate_limited")
        # risk_state：注入带风险的 client 到策略缓存
        prov.auth_strategy._client = stub
        prov.auth_strategy._client_file_mtime = \
            prov.auth_strategy._auth_file_mtime()
        self.assertEqual(prov.auth_strategy.risk_state()["kind"], "rate_limited")


    def test_download_to_part_matches_engine_contract(self):
        """download_to_part 返回对象满足引擎 DownloadResult 契约——
        bytes_written/sha256_hex 缺失曾导致所有下载被判失败（0.3.15）。"""
        self.store.save({"userId": UID, "serviceToken": GOOD, "passToken": PASS})
        prov = XiaomiProvider(None, {"id": "acc-t310d", "auth_file": str(self.auth_file)})
        part = self.tmp / "photo.jpg.part"
        payload = b"hello-xiaomi"

        stub = type("StubClient", (), {
            "get_download_meta": staticmethod(lambda pid: ("http://u", "m")),
            "download_to_file": staticmethod(
                lambda url, meta, path, resume=True:
                Path(path).write_bytes(payload) or "downloaded"),
        })()
        prov._client = lambda: stub
        res = prov.download_to_part(
            json.dumps({"url": "http://u", "meta": "m"}), part)
        self.assertTrue(res.success)
        self.assertEqual(res.bytes_written, len(payload))
        self.assertEqual(res.size, len(payload))
        self.assertEqual(res.sha256_hex, hashlib.sha256(payload).hexdigest())
        self.assertEqual(res.md5_hex, "")


if __name__ == "__main__":
    unittest.main()
