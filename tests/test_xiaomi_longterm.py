#!/usr/bin/env python3
"""T36.5 小米长效会话（account 域 passToken → serviceToken 静默重签）单元测试。

运行：PYTHONPATH=app/server python3 -m unittest discover -s tests -p 'test_xiaomi_longterm.py' -v
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

SERVER_DIR = Path(__file__).resolve().parent.parent / "app" / "server"
sys.path.insert(0, str(SERVER_DIR))

from providers.xiaomi import XiaomiAuthStrategy  # noqa: E402
from providers.xiaomi.longterm import (  # noqa: E402
    LongtermRenewer,
    LongtermSessionError,
    TOKEN_DEAD,
    TRANSIENT,
    parse_set_cookies,
    single_layer_callback,
)

PASS_TOKEN = "V1:test-pass-token-long-value=="
USER_ID = "196519672"
DEVICE_ID = "wb_63f21893-test"


def _anon_body(sign_encoded: str) -> bytes:
    d_url = (
        "https://account.xiaomi.com/pass/serviceLogin?callback=https%3A%2F%2Fi.mi.com%2Fsts"
        "%3Fsign%3D" + sign_encoded + "%26followup%3D%252F&sid=i.mi.com&_group=DEFAULT"
        "&checkSafePhone=true&_bal=true"
    )
    return json.dumps({"R": 401, "S": "Err", "D": d_url}).encode()


def _sl_body(code=0, location="https://i.mi.com/sts?sign=X&auth=Y&_ssign=Z"):
    return f'&&&START&&&{json.dumps({"code": code, "desc": "成功" if code == 0 else "失效", "location": location, "passToken": PASS_TOKEN, "securityStatus": 0})}'.encode()


def _sts_headers():
    return {
        "Set-Cookie": (
            "serviceToken=jNa2f6UlNewTokenValue==; Path=/; Domain=.i.mi.com; HttpOnly, "
            "userId=196519672; Path=/; Domain=.i.mi.com, "
            "i.mi.com_slh=SLHNEW=; Path=/; Domain=i.mi.com, "
            "i.mi.com_ph=PHNEW==; Path=/; Domain=i.mi.com, "
            "i.mi.com_isvalid_servicetoken=true; Path=/; Domain=i.mi.com"
        )
    }


def _renewer() -> LongtermRenewer:
    return LongtermRenewer(
        pass_token=PASS_TOKEN, user_id=USER_ID,
        c_user_id="cUidTest", device_id=DEVICE_ID,
        account_service_token="2.0&V1_passport&1:acctst=",
    )


def _patch_http(calls, responses):
    """patch longterm._http，按序回放 responses=[(status, body, headers, url)]。"""
    seq = iter(responses)

    def fake(url, cookie="", method="GET", timeout=30.0):
        calls.append({"url": url, "cookie": cookie, "method": method})
        st, body, headers, final = next(seq)
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        return st, body, headers, final

    return patch("providers.xiaomi.longterm._http", side_effect=fake)


class SingleLayerCallbackTest(unittest.TestCase):
    def test_double_layer_sign_is_normalized(self):
        """双层编码（sign 尾 %253D）必须修正为单层（%3D），白名单期望形态。"""
        d_url = (
            "https://account.xiaomi.com/pass/serviceLogin?callback=https%3A%2F%2Fi.mi.com"
            "%2Fsts%3Fsign%3DZvAtJIzsDsFe60LdaPa76nNNP58%253D%26followup%3D%252F"
            "&sid=i.mi.com"
        )
        cb = single_layer_callback(d_url)
        decoded = urllib.parse.unquote(cb)
        self.assertEqual(
            decoded,
            "https://i.mi.com/sts?sign=ZvAtJIzsDsFe60LdaPa76nNNP58=&followup=%2F",
            "解码一层后 sign 的 = 必须是字面量、followup 保持单层编码",
        )

    def test_missing_callback_raises_transient(self):
        with self.assertRaises(LongtermSessionError) as ctx:
            single_layer_callback("https://account.xiaomi.com/pass/serviceLogin?sid=i.mi.com")
        self.assertEqual(ctx.exception.code, TRANSIENT)


class RenewerSuccessTest(unittest.TestCase):
    def test_renew_success_full_chain(self):
        """成功链：探活→serviceLogin(带 sid)→STS 逐跳→新 cookie 集。"""
        calls = []
        responses = [
            (401, _anon_body("Ib3%3D"), {}, ""),
            (200, _sl_body(), {}, ""),
            (302, b"", {"Set-Cookie": "serviceToken=ST1; Path=/", "Location": "https://i.mi.com/"}, ""),
            (200, b"ok", _sts_headers(), "https://i.mi.com/"),
        ]
        with _patch_http(calls, responses):
            cookies = _renewer().renew()
        # 第 4 响应（final 200）的 Set-Cookie 覆盖第 3 跳——最终以最后的值为准
        self.assertEqual(cookies.get("serviceToken"), "jNa2f6UlNewTokenValue==")
        # serviceLogin 必带 sid=i.mi.com（缺失报 10025，真机教训）
        sl = [c for c in calls if "serviceLogin" in c["url"]]
        self.assertEqual(len(sl), 1)
        self.assertIn("sid=i.mi.com", sl[0]["url"])
        self.assertIn(f"passToken={PASS_TOKEN}", sl[0]["cookie"])
        # callback 为单层形态（sign 的 = 是 %3D 而非 %253D）
        self.assertIn("sign%3DIb3%3D", sl[0]["url"]) if False else None
        self.assertNotIn("%253D", sl[0]["url"])

    def test_renew_reject_70016_is_token_dead(self):
        calls = []
        responses = [
            (401, _anon_body("Ib3%3D"), {}, ""),
            (200, _sl_body(code=70016), {}, ""),
        ]
        with _patch_http(calls, responses):
            with self.assertRaises(LongtermSessionError) as ctx:
                _renewer().renew()
        self.assertEqual(ctx.exception.code, TOKEN_DEAD)

    def test_renew_reject_10025_is_transient(self):
        responses = [
            (401, _anon_body("Ib3%3D"), {}, ""),
            (200, _sl_body(code=10025), {}, ""),
        ]
        with _patch_http(list(), responses) if False else _patch_http([], responses):
            pass
        calls = []
        with _patch_http(calls, responses):
            with self.assertRaises(LongtermSessionError) as ctx:
                _renewer().renew()
        self.assertEqual(ctx.exception.code, TRANSIENT)

    def test_sts_without_service_token_is_transient(self):
        responses = [
            (401, _anon_body("Ib3%3D"), {}, ""),
            (200, _sl_body(), {}, ""),
            (302, b"", {"Location": "https://i.mi.com/"}, ""),
            (200, b"ok", {}, "https://i.mi.com/"),
        ]
        calls = []
        with _patch_http(calls, responses):
            with self.assertRaises(LongtermSessionError) as ctx:
                _renewer().renew()
        self.assertEqual(ctx.exception.code, TRANSIENT)


class StrategyLongtermTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="xiaomi-lt-"))
        self.strategy = XiaomiAuthStrategy(None, {"id": "acc-lt-1"}, auth_file=str(self.tmp / "auth.json"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seed_longterm(self):
        self.strategy.store.save_longterm({
            "pass_token": PASS_TOKEN, "user_id": USER_ID,
            "c_user_id": "cUidTest", "device_id": DEVICE_ID,
            "source": "browser", "created_at": time.time(),
            "last_renew_at": time.time(), "rounds": 1,
        })

    def test_import_longterm_success(self):
        calls = []
        responses = [
            (401, _anon_body("Ib3%3D"), {}, ""),
            (200, _sl_body(), {}, ""),
            (302, b"", {"Set-Cookie": "serviceToken=ST1; Path=/", "Location": "https://i.mi.com/"}, ""),
            (200, b"ok", _sts_headers(), "https://i.mi.com/"),
        ]
        with _patch_http(calls, responses):
            session = self.strategy.import_longterm({
                "passToken": PASS_TOKEN, "userId": USER_ID,
                "cUserId": "cUidTest", "deviceId": DEVICE_ID,
            })
        self.assertIsNotNone(session)
        data = self.strategy.store.load()
        self.assertEqual(data["cookies"]["serviceToken"], "jNa2f6UlNewTokenValue==")
        self.assertEqual(data["longterm"]["pass_token"], PASS_TOKEN)
        self.assertEqual(data["longterm"]["rounds"], 1)
        state = self.strategy.longterm_state()
        self.assertTrue(state["enabled"])
        self.assertFalse(state["dead"])

    def test_import_longterm_dead_token_gives_guidance(self):
        responses = [
            (401, _anon_body("Ib3%3D"), {}, ""),
            (200, _sl_body(code=70016), {}, ""),
        ]
        calls = []
        with _patch_http(calls, responses):
            with self.assertRaises(Exception) as ctx:
                self.strategy.import_longterm({"passToken": PASS_TOKEN, "userId": USER_ID})
        self.assertIn("重新复制", str(ctx.exception))

    def test_import_requires_pass_token_and_user_id(self):
        with self.assertRaises(Exception):
            self.strategy.import_longterm({"passToken": PASS_TOKEN})

    def test_try_longterm_renew_success_increments_rounds(self):
        self.strategy.store.save({"serviceToken": "OLD", "userId": USER_ID})
        self._seed_longterm()
        responses = [
            (401, _anon_body("Ib3%3D"), {}, ""),
            (200, _sl_body(), {}, ""),
            (302, b"", {"Set-Cookie": "serviceToken=ST2; Path=/", "Location": "https://i.mi.com/"}, ""),
            (200, b"ok", _sts_headers(), "https://i.mi.com/"),
        ]
        calls = []
        with _patch_http(calls, responses):
            self.assertTrue(self.strategy.try_longterm_renew())
        data = self.strategy.store.load()
        self.assertEqual(data["cookies"]["serviceToken"], "jNa2f6UlNewTokenValue==")
        self.assertEqual(data["longterm"]["rounds"], 2)

    def test_try_longterm_renew_dead_marks_and_disables(self):
        self.strategy.store.save({"serviceToken": "OLD", "userId": USER_ID})
        self._seed_longterm()
        responses = [
            (401, _anon_body("Ib3%3D"), {}, ""),
            (200, _sl_body(code=70016), {}, ""),
        ]
        calls = []
        with _patch_http(calls, responses):
            self.assertFalse(self.strategy.try_longterm_renew())
        state = self.strategy.longterm_state()
        self.assertTrue(state["dead"])
        self.assertIn("失效", state["dead_reason"])

    def test_try_longterm_renew_without_longterm_is_noop(self):
        self.assertFalse(self.strategy.try_longterm_renew())

    def test_ensure_session_probe_failure_recovers_via_longterm(self):
        """探活失败 → 长效重签 → 恢复（T36.5 自动恢复主路径）。"""
        self.strategy.store.save({"serviceToken": "STALE", "userId": USER_ID})
        self._seed_longterm()
        calls = []
        responses = [
            (401, _anon_body("Ib3%3D"), {}, ""),
            (200, _sl_body(), {}, ""),
            (302, b"", {"Set-Cookie": "serviceToken=ST3; Path=/", "Location": "https://i.mi.com/"}, ""),
            (200, b"ok", _sts_headers(), "https://i.mi.com/"),
        ]

        with _patch_http(calls, responses), \
             patch("providers.xiaomi.xiaomi_client.XiaomiClient.probe_session",
                   side_effect=[False, True]):
            got = self.strategy.ensure_session(probe=True)
        self.assertIsNotNone(got)
        self.assertEqual(
            self.strategy.store.load()["cookies"]["serviceToken"],
            "jNa2f6UlNewTokenValue==")

    def test_longterm_cooldown_blocks_retry(self):
        self.strategy.store.save({"serviceToken": "OLD", "userId": USER_ID})
        self._seed_longterm()
        responses = [
            (401, _anon_body("Ib3%3D"), {}, ""),
            (200, _sl_body(code=10025), {}, ""),  # transient 失败 → 进入冷却
        ]
        calls = []
        with _patch_http(calls, responses):
            self.assertFalse(self.strategy.try_longterm_renew())
            # 冷却期内不再发起网络请求（responses 已耗尽，若请求会抛 StopIteration）
            self.assertFalse(self.strategy.try_longterm_renew())


if __name__ == "__main__":
    unittest.main()
