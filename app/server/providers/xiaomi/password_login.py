#!/usr/bin/env python3
"""小米账号密码登录（T38.2-4）：serviceLoginAuth2 + 图形验证码 + identity 2FA。

协议（docs/xiaomi-cloud-api-research.md §8.5，源参考 XiaomiGateway3 xiaomi_cloud.py）：
  ① GET  /pass/serviceLogin?_json=true&sid=i.mi.com（Cookie: sdkVersion+deviceId）
     → 未登录 code=70016 属正常应答，_sign/qs/callback 照常返回（无需探活取签）
  ② POST /pass/serviceLoginAuth2（form: user + hash=MD5(pw).upper() + ①回传四件套）
     ├─ captchaUrl 非空 → 取验证码图（Set-Cookie ick）→ 用户输 captCode 重提 ②
     ├─ notificationUrl（securityStatus:16）→ identity 2FA：
     │    /identity/list{code:2,flag:4|8} + identity_session cookie
     │    → GET verify{Phone|Email} 取脱敏目标 → POST send{key}Ticket（可嵌套验证码）
     │    → POST verify{key}?ticket&trust=true → code=0 + location
     │    → 302 链 Set-Cookie 抓 passToken/userId
     └─ code=0 → JSON 直接含 passToken/userId
产出统一交 XiaomiAuthStrategy.import_longterm 落盘（双次换发校验+身份回填）。
密码仅存活于本会话内存（验证码重提需要），流程结束/过期即弃；落盘与否由策略层决定。
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any

from providers.xiaomi.longterm import (
    DEFAULT_USER_AGENT,
    _NoRedirect,
    parse_set_cookies,
)

logger = logging.getLogger("albumsync.providers.xiaomi.password_login")

SID = "i.mi.com"
SDK_VERSION = "4.2.29"
PASSPORT = "https://account.xiaomi.com"
FLAG_PHONE = 4
FLAG_EMAIL = 8
PENDING_TTL_SEC = 600


class PasswordLoginError(Exception):
    """密码登录流程错误（用户可读 message）。"""


def _prefix_json(body: bytes) -> dict[str, Any]:
    text = body.decode("utf-8", "replace").strip()
    if text.startswith("&&&START&&&"):
        text = text[len("&&&START&&&"):]
    return json.loads(text)


def _req(session_cookies: dict[str, str], url: str, method: str = "GET",
         data: dict[str, str] | None = None,
         timeout: float = 30.0) -> tuple[int, bytes, Any]:
    """不跟随重定向的单请求；Set-Cookie 收割进 session_cookies（name→value）。

    password_login 全程只与 account.xiaomi.com 交互（location 链的 i.mi.com
    cookie 同样收割进 dict，供成功后透传），故无需区分域。
    """
    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
    }
    cookie = "; ".join(f"{k}={v}" for k, v in session_cookies.items())
    if cookie:
        headers["Cookie"] = cookie
    body = urllib.parse.urlencode(data).encode() if data else None
    if body:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, headers=headers, data=body, method=method)
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        resp = opener.open(req, timeout=timeout)
        status, resp_body, resp_headers = resp.status, resp.read(), resp.headers
    except urllib.error.HTTPError as e:
        status, resp_body, resp_headers = e.code, e.read(), e.headers
    harvested = parse_set_cookies(resp_headers)
    if harvested:
        session_cookies.update(harvested)
    return status, resp_body, resp_headers


class PasswordLoginSession:
    """一次密码登录流程的全部上下文（即用即弃）。stage 流转：

    auth → captcha（Auth2 图形码）→ auth
         → 2fa_wait（已发码）→ done
         → 2fa_captcha（发码嵌套图形码）→ 2fa_wait
    """

    def __init__(self, user: str = "", password: str = "",
                 device_id: str | None = None) -> None:
        self.user = user
        self.password = password
        self.device_id = device_id or ("wb_" + str(uuid.uuid4()))
        self.cookies: dict[str, str] = {
            "sdkVersion": SDK_VERSION,
            "deviceId": self.device_id,
        }
        self.created_at = time.time()
        self.stage = "auth"
        self.result: dict[str, str] = {}
        self.flag: int | None = None
        self.verify_key = ""
        self.identity_session = ""

    # -- 状态 --

    def expired(self) -> bool:
        return time.time() - self.created_at > PENDING_TTL_SEC

    def state(self) -> dict[str, Any]:
        return {"stage": self.stage, "created_at": self.created_at}

    # -- 主入口 --

    def start(self) -> dict[str, Any]:
        """账号+密码发起登录，返回 {status: captcha|2fa|ok, ...}。"""
        if self.stage != "auth":
            raise PasswordLoginError("登录流程已在进行中")
        return self._auth2_attempt()

    def submit_captcha(self, code: str) -> dict[str, Any]:
        if self.stage == "captcha":
            return self._auth2_attempt(captcha_code=code)
        if self.stage == "2fa_captcha":
            return self._send_ticket(captcha_code=code)
        raise PasswordLoginError("当前无需图形验证码")

    def submit_verify(self, ticket: str) -> dict[str, Any]:
        if self.stage != "2fa_wait":
            raise PasswordLoginError("当前不在二次验证阶段")
        return self._verify(ticket)

    # -- 内部步骤 --

    def _auth2_attempt(self, captcha_code: str | None = None) -> dict[str, Any]:
        _, body, _ = _req(
            self.cookies,
            f"{PASSPORT}/pass/serviceLogin?_json=true&sid={SID}",
        )
        sign = _prefix_json(body)
        for key in ("_sign", "qs", "callback", "sid"):
            if not sign.get(key):
                raise PasswordLoginError(f"serviceLogin 取签失败：缺 {key}")

        form = {
            "_json": "true",
            "sid": str(sign["sid"]),
            "callback": str(sign["callback"]),
            "_sign": str(sign["_sign"]),
            "qs": str(sign["qs"]),
            "user": self.user,
            "hash": hashlib.md5(self.password.encode()).hexdigest().upper(),
        }
        if captcha_code:
            if not self.cookies.get("ick"):
                raise PasswordLoginError("验证码会话丢失，请重新开始登录")
            form["captCode"] = captcha_code
        _, body, _ = _req(
            self.cookies,
            f"{PASSPORT}/pass/serviceLoginAuth2",
            method="POST",
            data=form,
        )
        res = _prefix_json(body)

        if res.get("captchaUrl"):
            return self._captcha_image(str(res["captchaUrl"]), stage="captcha")
        if res.get("notificationUrl"):
            return self._identity_2fa(str(res["notificationUrl"]))
        if res.get("code") == 0 and res.get("passToken"):
            return self._finish(str(res["passToken"]), str(res.get("userId") or ""),
                                str(res.get("cUserId") or ""))
        desc = str(res.get("desc") or res.get("description") or "")
        code = res.get("code")
        raise PasswordLoginError(f"登录被拒绝（code={code} {desc}），请检查账号密码")

    def _captcha_image(self, captcha_url: str, stage: str) -> dict[str, Any]:
        if not captcha_url.startswith("http"):
            captcha_url = PASSPORT + captcha_url
        _, image, _ = _req(self.cookies, captcha_url)
        self.stage = stage
        data_url = "data:image/png;base64," + base64.b64encode(image).decode()
        return {"status": "captcha", "image": data_url}

    def _identity_2fa(self, notification_url: str) -> dict[str, Any]:
        if "/fe/service/identity/authStart" not in notification_url:
            raise PasswordLoginError(f"未知二次验证形态：{notification_url[:80]}")
        list_url = notification_url.replace(
            "/fe/service/identity/authStart", "/identity/list")
        _, body, _ = _req(self.cookies, list_url)
        res = _prefix_json(body)
        if res.get("code") != 2 or res.get("flag") not in (FLAG_PHONE, FLAG_EMAIL):
            raise PasswordLoginError(
                f"二次验证类型异常（code={res.get('code')} flag={res.get('flag')}）")
        self.flag = int(res["flag"])
        self.verify_key = "Phone" if self.flag == FLAG_PHONE else "Email"
        self.identity_session = self.cookies.get("identity_session", "")
        if not self.identity_session:
            raise PasswordLoginError("二次验证会话缺失（identity_session）")
        return self._send_ticket()

    def _send_ticket(self, captcha_code: str | None = None) -> dict[str, Any]:
        key = self.verify_key
        _, body, _ = _req(
            self.cookies,
            f"{PASSPORT}/identity/auth/verify{key}"
            f"?_flag={self.flag}&_json=true",
        )
        res = _prefix_json(body)
        if res.get("code") != 0:
            raise PasswordLoginError(f"二次验证信息获取失败（{res.get('desc')}）")
        masked = str(res.get(f"masked{key}") or "")

        data: dict[str, str] = {"retry": "0", "icode": captcha_code or "",
                                "_json": "true"}
        _, body, _ = _req(
            self.cookies,
            f"{PASSPORT}/identity/auth/send{key}Ticket",
            method="POST",
            data=data,
        )
        res2 = _prefix_json(body)
        if res2.get("captchaUrl"):
            return self._captcha_image(str(res2["captchaUrl"]), stage="2fa_captcha")
        if res2.get("code") != 0:
            raise PasswordLoginError(
                f"验证码发送失败（code={res2.get('code')} {res2.get('desc')}）")
        self.stage = "2fa_wait"
        return {"status": "2fa", "target": masked,
                "channel": "phone" if key == "Phone" else "email"}

    def _verify(self, ticket: str) -> dict[str, Any]:
        key = self.verify_key
        url = (f"{PASSPORT}/identity/auth/verify{key}"
               f"?_flag={self.flag}&ticket={urllib.parse.quote(ticket)}"
               f"&trust=true&_json=true")
        _, body, _ = _req(self.cookies, url, method="POST")
        res = _prefix_json(body)
        if res.get("code") != 0:
            raise PasswordLoginError(
                f"验证码校验失败（code={res.get('code')} {res.get('desc')}）")
        # passToken/userId 经 location 302 链的 Set-Cookie 下发（非 JSON）
        harvested: dict[str, str] = {}
        url = str(res.get("location") or "")
        hops = 0
        while url and hops < 6:
            hops += 1
            _, hop_body, headers = _req(self.cookies, url)
            harvested.update(parse_set_cookies(headers))
            nxt = headers.get("Location") or headers.get("location") or ""
            url = urllib.parse.urljoin(url, nxt) if nxt else None
        pass_token = str(harvested.get("passToken") or "")
        user_id = str(harvested.get("userId") or "")
        if not pass_token or not user_id:
            raise PasswordLoginError("二次验证成功但未取到票据（trust 未生效？）")
        return self._finish(pass_token, user_id,
                            str(harvested.get("cUserId") or ""))

    def _finish(self, pass_token: str, user_id: str, c_user_id: str) -> dict[str, Any]:
        if not pass_token or not user_id:
            raise PasswordLoginError("登录成功但票据缺失")
        self.result = {
            "passToken": pass_token,
            "userId": user_id,
            "cUserId": c_user_id,
            "deviceId": self.device_id,
        }
        self.stage = "done"
        # 即用即弃：流程结束不再保留账号密码（落盘与否由策略层决定）
        self.user = ""
        self.password = ""
        return {"status": "ok", **self.result}
