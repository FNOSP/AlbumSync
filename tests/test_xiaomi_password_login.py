#!/usr/bin/env python3
"""T38.2-4 小米密码登录状态机单元测试（mock _req，无真实网络）。

运行：PYTHONPATH=app/server python3 -m pytest tests/test_xiaomi_password_login.py -q
"""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SERVER_DIR = Path(__file__).resolve().parent.parent / "app" / "server"
sys.path.insert(0, str(SERVER_DIR))

import crypto_box  # noqa: E402
from providers.xiaomi import XiaomiAuthStrategy  # noqa: E402
from providers.xiaomi.longterm import parse_set_cookies  # noqa: E402
from providers.xiaomi.password_login import (  # noqa: E402
    PasswordLoginError,
    PasswordLoginSession,
)

PASSWORD = "s3cret!"


def _jp(obj: dict) -> bytes:
    return ("&&&START&&&" + json.dumps(obj)).encode()


def _sign_body() -> bytes:
    return _jp({"code": 70016, "desc": "登录验证失败", "_sign": "S1", "qs": "%3Fsid%3Di.mi.com",
                "callback": "https://i.mi.com/sts", "sid": "i.mi.com", "captchaUrl": ""})


def _ok_auth2(pass_token="PT1", user_id="123", c_user_id="CU") -> bytes:
    return _jp({"code": 0, "desc": "成功", "passToken": pass_token, "userId": user_id,
                "cUserId": c_user_id, "ssecurity": "SS",
                "location": "https://i.mi.com/sts?sign=X"})


def _patch_http(responses):
    seq = iter(responses)
    calls = []

    def fake(session_cookies, url, method="GET", data=None, timeout=30.0):
        calls.append({"url": url, "method": method, "data": data,
                      "cookie": dict(session_cookies)})
        status, body, headers = next(seq)
        if isinstance(body, (dict, list)):
            body = _jp(body)
        if isinstance(headers, dict) and headers.get("Set-Cookie"):
            session_cookies.update(
                parse_set_cookies({"Set-Cookie": headers["Set-Cookie"]}))
        return status, body, headers

    return patch("providers.xiaomi.password_login._req", side_effect=fake), calls


class PasswordLoginDirectTest(unittest.TestCase):
    """T38.2：直登成功分支（code=0 + JSON passToken）。"""

    def test_success_direct(self):
        p, calls = _patch_http([
            (200, _sign_body(), {}),
            (200, _ok_auth2(), {}),
        ])
        s = PasswordLoginSession("13800000000", PASSWORD)
        with p:
            res = s.start()
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["passToken"], "PT1")
        self.assertEqual(res["userId"], "123")
        self.assertTrue(res["deviceId"].startswith("wb_"))
        # 即用即弃
        self.assertEqual(s.password, "")
        self.assertEqual(s.stage, "done")
        # Auth2 请求形态
        auth2 = [c for c in calls if "serviceLoginAuth2" in c["url"]]
        self.assertEqual(len(auth2), 1)
        form = auth2[0]["data"]
        self.assertEqual(form["user"], "13800000000")
        self.assertEqual(form["hash"], hashlib.md5(PASSWORD.encode()).hexdigest().upper())
        self.assertEqual(form["_sign"], "S1")
        self.assertEqual(form["sid"], "i.mi.com")
        self.assertEqual(auth2[0]["cookie"].get("sdkVersion"), "4.2.29")
        self.assertEqual(auth2[0]["cookie"].get("deviceId"), res["deviceId"])

    def test_wrong_password_raises(self):
        p, _ = _patch_http([
            (200, _sign_body(), {}),
            (200, _jp({"code": 70016, "desc": "登录验证失败", "captchaUrl": ""}), {}),
        ])
        s = PasswordLoginSession("u", "badpw")
        with p:
            with self.assertRaises(PasswordLoginError) as ctx:
                s.start()
        self.assertIn("登录被拒绝", str(ctx.exception))


class PasswordLoginCaptchaTest(unittest.TestCase):
    """T38.3：Auth2 图形验证码分支（captchaUrl → ick → captCode 重提）。"""

    def test_captcha_roundtrip(self):
        p, calls = _patch_http([
            (200, _sign_body(), {}),                                    # 取签
            (200, _jp({"code": 70016, "captchaUrl": "/pass/captcha?tic=1",
                       "desc": "需要验证码"}), {}),                      # Auth2 → 验证码
            (200, b"\x89PNG fake", {"Set-Cookie": "ick=ICK1; Path=/"}),  # 取验证码图
            (200, _sign_body(), {}),                                    # 重提交取签
            (200, _ok_auth2(pass_token="PT2", user_id="99"), {}),        # Auth2 重提成功
        ])
        s = PasswordLoginSession("u", PASSWORD)
        with p:
            res = s.start()
        self.assertEqual(res["status"], "captcha")
        self.assertTrue(res["image"].startswith("data:image/png;base64,"))
        self.assertEqual(s.cookies.get("ick"), "ICK1")

        with p:
            res = s.submit_captcha("ab12")
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["passToken"], "PT2")
        auth2 = [c for c in calls if "serviceLoginAuth2" in c["url"]]
        self.assertEqual(len(auth2), 2)
        self.assertEqual(auth2[1]["data"].get("captCode"), "ab12")
        self.assertEqual(auth2[1]["cookie"].get("ick"), "ICK1")


class PasswordLogin2FATest(unittest.TestCase):
    """T38.4：identity 2FA 分支（flag 识别 → 发码 → trust=true 校验）。"""

    def _2fa_setup_responses(self):
        return [
            (200, _sign_body(), {}),                                     # 取签
            (200, _jp({"code": 70016,
                       "notificationUrl": "https://account.xiaomi.com/fe/service"
                                        "/identity/authStart?context=ABC",
                       "securityStatus": 16}), {}),                      # Auth2 → 2FA
            (200, _jp({"code": 2, "flag": 4}),
             {"Set-Cookie": "identity_session=IS1; Path=/"}),            # identity/list
            (200, _jp({"code": 0, "maskedPhone": "138****1234"}), {}),   # verifyPhone 脱敏目标
            (200, _jp({"code": 0, "desc": "发送成功"}), {}),              # sendPhoneTicket
        ]

    def test_2fa_send_ticket(self):
        p, calls = _patch_http(self._2fa_setup_responses())
        s = PasswordLoginSession("u", PASSWORD)
        with p:
            res = s.start()
        self.assertEqual(res["status"], "2fa")
        self.assertEqual(res["target"], "138****1234")
        self.assertEqual(res["channel"], "phone")
        self.assertEqual(s.stage, "2fa_wait")
        lst = [c for c in calls if "/identity/list" in c["url"]]
        self.assertEqual(len(lst), 1)
        self.assertIn("context=ABC", lst[0]["url"])  # authStart→list 改写保留 context

    def test_2fa_verify_trust_true(self):
        p, calls = _patch_http(self._2fa_setup_responses() + [
            (200, _jp({"code": 0, "location": "https://i.mi.com/sts?sign=X"}), {}),
            (302, b"", {"Set-Cookie": "passToken=PT9; Path=/, userId=123; Path=/",
                        "Location": "https://i.mi.com/"}),
            (200, b"ok", {"Set-Cookie": "serviceToken=ST9; Path=/"}),
        ])
        s = PasswordLoginSession("u", PASSWORD)
        with p:
            s.start()
            res = s.submit_verify("654321")
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["passToken"], "PT9")
        self.assertEqual(res["userId"], "123")
        verify = [c for c in calls if "/identity/auth/verifyPhone" in c["url"]
                  and "ticket=" in c["url"]]
        self.assertEqual(len(verify), 1)
        self.assertIn("trust=true", verify[0]["url"])
        self.assertIn("ticket=654321", verify[0]["url"])
        self.assertIn("_flag=4", verify[0]["url"])
        self.assertEqual(verify[0]["cookie"].get("identity_session"), "IS1")

    def test_2fa_ticket_nested_captcha(self):
        p, calls = _patch_http(self._2fa_setup_responses()[:4] + [
            (200, _jp({"code": 70016, "captchaUrl": "/identity/auth/captcha?ick=1",
                       "desc": "需要验证码"}), {}),                      # 发码 → 嵌套验证码
            (200, b"\x89PNG fake", {"Set-Cookie": "ick=ICK2; Path=/"}),
            (200, _jp({"code": 0, "maskedPhone": "138****1234"}), {}),   # 重发前再次取脱敏目标
            (200, _jp({"code": 0, "desc": "发送成功"}), {}),              # 重发成功
        ])
        s = PasswordLoginSession("u", PASSWORD)
        with p:
            res = s.start()
        self.assertEqual(res["status"], "captcha")
        self.assertEqual(s.stage, "2fa_captcha")
        with p:
            res = s.submit_captcha("ic9")
        self.assertEqual(res["status"], "2fa")
        send = [c for c in calls if "sendPhoneTicket" in c["url"]]
        self.assertEqual(len(send), 2)
        self.assertEqual(send[1]["data"].get("icode"), "ic9")
        self.assertEqual(send[1]["cookie"].get("ick"), "ICK2")

    def test_2fa_wrong_code_raises(self):
        p, _ = _patch_http(self._2fa_setup_responses() + [
            (200, _jp({"code": 70016, "desc": "校验失败"}), {}),
        ])
        s = PasswordLoginSession("u", PASSWORD)
        with p:
            s.start()
            with self.assertRaises(PasswordLoginError):
                s.submit_verify("000000")


class StrategyPasswordLoginTest(unittest.TestCase):
    """T38.5：策略层接入——凭据读自账号配置 + 旧版「记住密码」密文迁移 + 失败冷却。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="xiaomi-pwd-"))
        # auth_file 放在 tmp/acc/ 下 → parent.parent=tmp，secret.key 落在 tmp 内
        auth_file = self.tmp / "acc" / "xiaomi_acc-pw-1_auth.json"
        self.strategy = XiaomiAuthStrategy(
            None, {"id": "acc-pw-1", "username": "13800000000",
                   "password": PASSWORD},
            auth_file=str(auth_file))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _renew_responses(self):
        """import_longterm 双次换发所需的 longterm._http mock 序列。"""
        def anon(sign):
            d_url = ("https://account.xiaomi.com/pass/serviceLogin?callback="
                     "https%3A%2F%2Fi.mi.com%2Fsts%3Fsign%3D" + sign +
                     "%26followup%3D%252F&sid=i.mi.com&_group=DEFAULT")
            return (401, json.dumps({"R": 401, "S": "Err", "D": d_url}).encode(), {}, "")
        def sl():
            return (200, _jp({"code": 0, "desc": "成功",
                              "location": "https://i.mi.com/sts?sign=X&auth=Y&_ssign=Z"}), {}, "")
        def hops(token):
            return [
                (302, b"", {"Set-Cookie": f"serviceToken={token}; Path=/",
                            "Location": "https://i.mi.com/"}, ""),
                (200, b"ok", {"Set-Cookie": f"serviceToken={token}; Path=/; Domain=.i.mi.com, "
                                           "userId=123; Path=/; Domain=.i.mi.com"}, "https://i.mi.com/"),
            ]
        return [anon("Ib3%3D"), sl(), *hops("ST1"), anon("Ib3%3D"), sl(), *hops("ST2")]

    def _renew_patch(self):
        seq = iter(self._renew_responses())
        return patch("providers.xiaomi.longterm._http",
                     side_effect=lambda *a, **k: next(seq))

    def test_success_uses_config_credentials(self):
        p_login, calls = _patch_http([
            (200, _sign_body(), {}),
            (200, _ok_auth2(pass_token="PTX", user_id="123", c_user_id="CU1"), {}),
        ])
        with p_login, self._renew_patch():
            res = self.strategy.password_login_start({})
        self.assertEqual(res["status"], "ok")
        # 票据已导入（双次换发后落盘）
        self.assertTrue(self.strategy.store.has_session())
        self.assertTrue((self.strategy.longterm_state() or {}).get("enabled"))
        # Auth2 使用配置中的账号密码
        auth2 = [c for c in calls if "serviceLoginAuth2" in c["url"]]
        self.assertEqual(len(auth2), 1)
        self.assertEqual(auth2[0]["data"]["user"], "13800000000")
        self.assertEqual(auth2[0]["data"]["hash"],
                         hashlib.md5(PASSWORD.encode()).hexdigest().upper())
        # 不再写「记住密码」密文（密码持久化只走账号配置保存路径）
        self.assertEqual(self.strategy.store.load_login_secret(), ("", None))
        self.assertIsNone(self.strategy._pwd_login)

    def test_missing_credentials_returns_hint(self):
        bare = XiaomiAuthStrategy(
            None, {"id": "acc-pw-1"},
            auth_file=str(self.tmp / "acc" / "xiaomi_acc-pw-1_auth.json"))
        p_login, calls = _patch_http([(200, _sign_body(), {})])
        with p_login:
            res = bare.password_login_start({})
        self.assertEqual(res["status"], "error")
        self.assertIn("同步设置", res["message"])
        # 未发起任何网络请求
        self.assertEqual(len(calls), 0)

    def test_legacy_saved_password_migrated_once(self):
        bare = XiaomiAuthStrategy(
            None, {"id": "acc-pw-1"},
            auth_file=str(self.tmp / "acc" / "xiaomi_acc-pw-1_auth.json"))
        enc = crypto_box.seal_text(bare._pwd_key(), PASSWORD,
                                   aad="albumsync:password:acc-pw-1")
        bare.store.save_login_secret("saveduser", enc)
        p_login, calls = _patch_http([
            (200, _sign_body(), {}),
            (200, _ok_auth2(pass_token="PTY", user_id="123", c_user_id=""), {}),
        ])
        with p_login, self._renew_patch():
            res = bare.password_login_start({})
        self.assertEqual(res["status"], "ok")
        # 旧密文中的账号密码被迁移使用
        auth2 = [c for c in calls if "serviceLoginAuth2" in c["url"]]
        self.assertEqual(auth2[0]["data"]["user"], "saveduser")
        self.assertEqual(auth2[0]["data"]["hash"],
                         hashlib.md5(PASSWORD.encode()).hexdigest().upper())
        # 迁移成功提示去「同步设置」保存，且旧密文清除
        self.assertIn("同步设置", res["message"])
        self.assertEqual(bare.store.load_login_secret(), ("", None))

    def test_failure_cooldown(self):
        p_login, _ = _patch_http([
            (200, _sign_body(), {}),
            (200, _jp({"code": 70016, "desc": "登录验证失败", "captchaUrl": ""}), {}),
        ])
        with p_login:
            res = self.strategy.password_login_start({})
        self.assertEqual(res["status"], "error")
        # 冷却期内再次发起被拒（不消耗任何网络调用）
        with patch("providers.xiaomi.password_login._req",
                   side_effect=AssertionError("cooldown must block requests")) as guard:
            res2 = self.strategy.password_login_start({})
        self.assertEqual(res2["status"], "error")
        self.assertIn("冷却", res2["message"])
        self.assertEqual(guard.call_count, 0)
        status = self.strategy.password_login_status()
        self.assertGreater(status["cooldown_remaining_sec"], 0)
        self.assertTrue(status["has_saved"])


if __name__ == "__main__":
    unittest.main()
