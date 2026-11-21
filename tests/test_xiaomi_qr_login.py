#!/usr/bin/env python3
"""T31.5 扫码登录单测：qr_login 状态机 + strategy 集成（T31.2）。"""
from __future__ import annotations

import json
import shutil
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app" / "server"))

from providers.xiaomi.qr_login import (  # noqa: E402
    XiaomiQRLogin,
    XiaomiQRLoginError,
    parse_set_cookie_pairs,
    strip_jsonp,
)
from providers.xiaomi import XiaomiAuthStrategy  # noqa: E402


def _jsonp(payload: dict) -> bytes:
    return ("&&&START&&&" + json.dumps(payload)).encode("utf-8")


D_401 = {
    "R": 401, "S": "Err",
    "D": ("https://account.xiaomi.com/pass/serviceLogin?callback=https%3A%2F%2Fi.mi.com"
          "%2Fsts%3Fsign%3DIb3horUmfhQFoQV2LgZ1BLPKbRg%253D%26followup%3D%252F"
          "&sid=i.mi.com&_group=DEFAULT&checkSafePhone=true&_bal=true"),
}

LOGIN_URL_RESP = {
    "code": 0, "result": "ok",
    "qr": "https://account.xiaomi.com/pass/qr/login?ticket=lp_TEST&dc=c3&sid=i.mi.com",
    "lp": "https://c3.lp.account.xiaomi.com/lp/s?k=lp_TEST",
    "loginUrl": "https://c3.account.xiaomi.com/longPolling/login?ticket=lp_TEST",
    "timeout": 300, "timeInterval": 0, "sl": "",
}

CONFIRM = {
    "code": 0, "result": "ok",
    "passToken": "V1:TESTPASS", "userId": 196519672,
    "cUserId": "cU", "securityStatus": 0, "psecurity": "p==", "nonce": 1,
    "ssecurity": "s==", "pwd": 1, "child": 0, "miDemo": 0, "captchaUrl": None,
    "notificationUrl": "", "desc": "成功", "description": "成功",
    "location": "https://i.mi.com/sts?sign=OLD&auth=ONCE",
}

SERVICE_LOGIN_RESP = {
    "code": 0, "result": "ok",
    "location": "https://i.mi.com/sts?sign=NEW&followup=%2F&auth=A1",
    "ssecurity": "s2==", "passToken": "V1:TESTPASS2",
}


class ScriptedQR(XiaomiQRLogin):
    """脚本化 _http_get 的 QR 状态机（不触网）。"""

    def __init__(self, script, **kw):
        super().__init__(**kw)
        self._script = list(script)
        self._calls: list[str] = []

    def _http_get(self, url, *, headers=None, timeout=30):
        self._calls.append(url)
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        st, headers_d, body, setc = item
        return st, headers_d, body, setc


class TestQrHelpers(unittest.TestCase):
    def test_strip_jsonp(self):
        self.assertEqual(strip_jsonp(b'&&&START&&&{"a":1}'), '{"a":1}')
        self.assertEqual(strip_jsonp('&&&START&&& x'), 'x')

    def test_parse_set_cookie_pairs_skips_empty_values(self):
        pairs = parse_set_cookie_pairs([
            "serviceToken=abc123; Path=/; Secure",
            "userId=196519672; Domain=.i.mi.com",
            "i.mi.com_slh=; Expires=Thu, 01 Jan 1970",
            "broken-no-equals",
        ])
        self.assertEqual(pairs, {"serviceToken": "abc123",
                                 "userId": "196519672"})


class TestQRStateMachine(unittest.TestCase):
    def _qr_with_ticket(self) -> ScriptedQR:
        qr = ScriptedQR([
            (200, {}, json.dumps(D_401).encode(), []),
            (200, {}, _jsonp(LOGIN_URL_RESP), []),
        ])
        qr.start()
        return qr

    def test_start_returns_ticket(self):
        qr = self._qr_with_ticket()
        self.assertIn("ticket=lp_TEST", qr.qr_content)
        self.assertEqual(qr.lp_url, LOGIN_URL_RESP["lp"])
        self.assertGreater(qr.expire_at, time.time())
        # loginUrl 请求带签名 callback（来自 401.D）
        self.assertIn("callback=https%3A%2F%2Fi.mi.com", qr._calls[1])

    def test_start_encodes_login_url_not_qr_image_url(self):
        """扫码内容必须是 loginUrl（可扫通道）；qr 字段是官方二维码图片的 URL，
        误编码它会导致手机扫开后只展示图片里的真二维码（0.3.7 真机反馈）。"""
        qr = self._qr_with_ticket()
        self.assertEqual(qr.qr_content, LOGIN_URL_RESP["loginUrl"])
        self.assertNotEqual(qr.qr_content, LOGIN_URL_RESP["qr"])

    def test_start_fails_without_D_field(self):
        qr = ScriptedQR([(200, {}, b'{"R":200,"S":"Ok"}', [])])
        with self.assertRaises(XiaomiQRLoginError):
            qr.start()

    def test_poll_before_start_is_failed(self):
        qr = ScriptedQR([])
        r = qr.poll()
        self.assertEqual(r["status"], "failed")

    def test_poll_after_expiry_without_network(self):
        qr = self._qr_with_ticket()
        qr.expire_at = time.time() - 1
        r = qr.poll()
        self.assertEqual(r["status"], "expired")
        self.assertEqual(qr._calls[2:], [], "过期后不得再发网络请求")

    def test_poll_timeout_means_waiting(self):
        qr = self._qr_with_ticket()
        qr._script.append(socket.timeout("lp hang"))
        self.assertEqual(qr.poll()["status"], "waiting")

    def test_poll_business_error_is_expired(self):
        qr = self._qr_with_ticket()
        qr._script.append((200, {}, _jsonp({"code": 810, "desc": "ticket 已使用"}), []))
        r = qr.poll()
        self.assertEqual(r["status"], "expired")
        self.assertIn("810", r.get("error", ""))

    def test_full_confirm_exchanges_cookies(self):
        qr = self._qr_with_ticket()
        qr._script += [
            # lp 确认载荷
            (200, {}, _jsonp(CONFIRM), []),
            # serviceLogin(_json)
            (200, {}, _jsonp(SERVICE_LOGIN_RESP), []),
            # STS hop1: 302 种 cookie
            (302, {"Location": "http://i.mi.com/"}, b"", [
                "serviceToken=ST1; Path=/; Secure",
                "userId=196519672; Domain=.i.mi.com; Secure",
                "i.mi.com_slh=SLH1; Path=/",
                "i.mi.com_ph=PH1; Path=/",
            ]),
            # STS hop2: 301 http->https
            (301, {"Location": "https://i.mi.com/"}, b"", []),
            # STS hop3: 200 终点
            (200, {}, b"<html></html>", []),
        ]
        r = qr.poll()
        self.assertEqual(r["status"], "confirmed", r)
        cookies = r["cookies"]
        self.assertEqual(cookies["serviceToken"], "ST1")
        self.assertEqual(cookies["userId"], "196519672")
        self.assertEqual(cookies["i.mi.com_slh"], "SLH1")
        # T31.7：passToken 必须一并返回落盘（serviceToken 作废后静默重签凭据）
        self.assertEqual(cookies["passToken"], "V1:TESTPASS")
        self.assertEqual(r["user_id"], "196519672")
        # serviceLogin 请求带 passToken cookie（jar 注入，URL 不含凭证）
        jar_names = {c.name: c.value for c in qr._jar}
        self.assertEqual(jar_names.get("passToken"), "V1:TESTPASS")
        self.assertEqual(jar_names.get("userId"), "196519672")

    def test_exchange_missing_location_is_failed(self):
        qr = self._qr_with_ticket()
        qr._script += [
            (200, {}, _jsonp(CONFIRM), []),
            (200, {}, _jsonp({"code": 8, "desc": "error"}), []),
        ]
        r = qr.poll()
        self.assertEqual(r["status"], "failed")
        self.assertIn("serviceLogin", r["error"])


class TestStrategyQRIntegration(unittest.TestCase):
    """strategy.start_qr_login / qr_login_status：落盘 + 探活接线。"""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="xiaomi-qr-")
        self.auth_file = str(Path(self._tmp) / "xiaomi_qr_auth.json")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _strategy(self) -> XiaomiAuthStrategy:
        return XiaomiAuthStrategy(None, {"id": "qr-acc", "auth_file": self.auth_file})

    def _patch_qr(self, fake_qr):
        return patch("providers.xiaomi.XiaomiQRLogin", lambda **kw: fake_qr)

    def test_start_returns_qr_content(self):
        fake = ScriptedQR([
            (200, {}, json.dumps(D_401).encode(), []),
            (200, {}, _jsonp(LOGIN_URL_RESP), []),
        ])
        with self._patch_qr(fake):
            r = self._strategy().start_qr_login()
        self.assertIn("lp_TEST", r["qr_content"])
        self.assertGreater(r["expire_at"], time.time())

    def test_confirmed_saves_session_and_probes(self):
        fake = ScriptedQR([])
        fake.qr_content = "qr"
        fake.lp_url = "lp"
        fake.expire_at = time.time() + 100
        fake._script += [
            (200, {}, _jsonp(CONFIRM), []),
            (200, {}, _jsonp(SERVICE_LOGIN_RESP), []),
            (302, {}, b"", [
                "serviceToken=ST1; Path=/",
                "userId=196519672; Path=/",
            ]),
        ]
        s = self._strategy()
        s._qr = fake
        with patch.object(XiaomiAuthStrategy, "_new_client",
                          lambda self_, ck: _ProbeClient(ck, ok=True)):
            r = s.qr_login_status()
        self.assertEqual(r["status"], "confirmed")
        self.assertEqual(r["user_id"], "196519672")
        stored = json.loads(Path(self.auth_file).read_text(encoding="utf-8"))
        self.assertEqual(stored["cookies"]["serviceToken"], "ST1")
        self.assertIsNone(s._qr, "confirmed 后扫码会话必须清空")

    def test_confirmed_probe_failure_clears_store(self):
        fake = ScriptedQR([
            (200, {}, _jsonp(CONFIRM), []),
            (200, {}, _jsonp(SERVICE_LOGIN_RESP), []),
            (302, {"Location": ""}, b"", [
                "serviceToken=ST1; Path=/",
                "userId=196519672; Path=/",
            ]),
        ])
        fake.qr_content = "qr"
        fake.lp_url = "lp"
        fake.expire_at = time.time() + 100
        s = self._strategy()
        s._qr = fake
        with patch.object(XiaomiAuthStrategy, "_new_client",
                          lambda self_, ck: _ProbeClient(ck, ok=False)):
            r = s.qr_login_status()
        self.assertEqual(r["status"], "failed")
        self.assertFalse(Path(self.auth_file).exists(), "探活失败须清 store")
        self.assertFalse(s.is_valid())

    def test_no_session_in_progress_is_expired(self):
        r = self._strategy().qr_login_status()
        self.assertEqual(r["status"], "expired")


class _ProbeClient:
    """probe 可编程的 client 替身（含 user_id property）。"""

    def __init__(self, cookies: dict, ok: bool):
        self.cookies = cookies
        self._ok = ok

    @property
    def user_id(self) -> str:
        return self.cookies.get("userId", "")

    def probe_session(self) -> bool:
        return self._ok


if __name__ == "__main__":
    unittest.main()
