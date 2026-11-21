#!/usr/bin/env python3
"""小米长效会话：account 域 passToken → serviceToken 静默重签链（T36.5）。

机制（docs/xiaomi-cloud-api-research.md §7，2026-11-21 WSL 两轮实测）：
- account.xiaomi.com 域的 passToken（浏览器「信任设备」登录签发）可**无限次
  换发** i.mi.com 的 serviceToken 且自身不轮替——与扫码 passToken（一次性特权，
  换发即作废 70016）本质不同。
- serviceToken 本身短命（~15-30 分钟，重签后旧值 15 分钟并存窗口作废），故需
  周期性静默重签保持可用。

重签链（纯标准库，T36 实验 WSL 复现成功）：
  1. 匿名 GET album/list → 401 响应 `D` URL（内含新鲜 `sign` 的 callback）
  2. ⚠️ callback 编码层次：D 里的 callback 为双层编码（sign 的 `=` 是 `%253D`），
     serviceLogin 白名单要求单层（`%3D`）——解码一层后把 sign 尾部字面 `%3D`
     还原为 `=`，再单层 quote
  3. ⚠️ `sid=i.mi.com` 必带（缺失报 10025「Callback 连接不合法」）
  4. GET /pass/serviceLogin?sid=...&callback=...&_group=DEFAULT&_json=true
     （Cookie：account 域集）
  5. 响应 `location` → 逐跳跟随 302 至 i.mi.com/，收集全程 Set-Cookie
"""
from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger("albumsync.providers.xiaomi.longterm")

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
)

# 失败类别
TOKEN_DEAD = "token_dead"      # passToken 已失效（需重新导入）
TRANSIENT = "transient"        # 服务端波动/网络问题（可重试）


class LongtermSessionError(Exception):
    """长效重签失败。code: TOKEN_DEAD（放弃并清票）/ TRANSIENT（可重试）。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a: Any, **k: Any) -> None:
        return None


def _http(url: str, cookie: str = "", method: str = "GET",
          timeout: float = 30.0) -> tuple[int, bytes, dict[str, str], str]:
    """不跟随重定向的 GET/POST；返回 (status, body, headers_dict, final_url)。"""
    req = urllib.request.Request(url, headers={
        "Cookie": cookie,
        "Referer": "https://i.mi.com/gallery/h5",
        "User-Agent": DEFAULT_USER_AGENT,
    }, method=method)
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        resp = opener.open(req, timeout=timeout)
        return resp.status, resp.read(), dict(resp.headers), resp.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers), e.url


def _strip_json_prefix(body: bytes) -> dict[str, Any]:
    text = body.decode("utf-8", "replace")
    if text.startswith("&&&START&&&"):
        text = text[len("&&&START&&&"):]
    return json.loads(text)


def parse_set_cookies(headers: dict[str, str]) -> dict[str, str]:
    """从 Set-Cookie 原始头手工解析 name=value（cookiejar 会丢部分域/属性）。"""
    out: dict[str, str] = {}
    for key, val in headers.items():
        if key.lower() != "set-cookie":
            continue
        for part in val.split("Path=/,"):
            kv = part.strip().split(";")[0]
            if "=" in kv:
                name, _, value = kv.partition("=")
                out[name.strip()] = value.strip()
    return out


def single_layer_callback(d_url: str) -> str:
    """从匿名探活的 D URL 提取 callback 并修正为 serviceLogin 白名单的单层编码。

    D 里的 callback 是双层编码（sign 的 `=` 为 `%253D`）；白名单期望单层
    （`%3D`）——解码一层后把 sign 尾部字面 `%3D` 还原为 `=`，再单层 quote。
    """
    m = re.search(r"callback=([^&]+)", d_url)
    if not m:
        raise LongtermSessionError(TRANSIENT, "跳转指令缺 callback")
    cb_plain = urllib.parse.parse_qs(urllib.parse.urlparse(d_url).query)["callback"][0]
    cb_fixed = cb_plain.replace("%3D", "=")
    return urllib.parse.quote(cb_fixed, safe="")


def _fresh_callback_sign() -> str:
    """匿名探活拿 i.mi.com 签发的 sts callback（含新鲜 sign），返回单层编码形态。"""
    ts = int(time.time() * 1000)
    url = (
        "https://i.mi.com/gallery/user/album/list"
        f"?ts={ts}&pageNum=0&pageSize=5&isShared=false&numOfThumbnails=1"
    )
    st, body, _, _ = _http(url)
    try:
        d = json.loads(body.decode("utf-8", "replace"))
    except json.JSONDecodeError as exc:
        raise LongtermSessionError(TRANSIENT, f"探活响应非 JSON: {st}") from exc
    d_url = str(d.get("D") or "")
    if st != 401 or not d_url:
        raise LongtermSessionError(TRANSIENT, f"探活未返回跳转指令: {st} {body[:60]!r}")
    return single_layer_callback(d_url)


class LongtermRenewer:
    """持有 account 域长效票据，向 i.mi.com 换发新 serviceToken 会话。"""

    def __init__(
        self,
        *,
        pass_token: str,
        user_id: str,
        c_user_id: str = "",
        device_id: str = "",
        account_service_token: str = "",
        passport_slh: str = "",
        passport_ph: str = "",
        timeout: float = 30.0,
    ) -> None:
        self.pass_token = (pass_token or "").strip()
        self.user_id = (user_id or "").strip()
        self.c_user_id = (c_user_id or "").strip()
        self.device_id = (device_id or "").strip()
        self.account_service_token = (account_service_token or "").strip()
        self.passport_slh = (passport_slh or "").strip()
        self.passport_ph = (passport_ph or "").strip()
        self.timeout = timeout

    def _account_cookie(self) -> str:
        parts = [
            f"passToken={self.pass_token}",
            f"userId={self.user_id}",
        ]
        if self.c_user_id:
            parts.append(f"cUserId={self.c_user_id}")
        if self.device_id:
            parts.append(f"deviceId={self.device_id}")
        parts.append("pass_ua=web")
        parts.append("passInfo=login-end")
        if self.account_service_token:
            parts.append(f"serviceToken={self.account_service_token}")
        if self.passport_slh:
            parts.append(f"passport_slh={self.passport_slh}")
        if self.passport_ph:
            parts.append(f"passport_ph={self.passport_ph}")
        return "; ".join(parts)

    def renew(self) -> dict[str, str]:
        """执行重签链，返回新 i.mi.com 域 cookie dict（含 serviceToken）。

        失败抛 LongtermSessionError（code=TOKEN_DEAD/TRANSIENT）。
        """
        if not self.pass_token or not self.user_id:
            raise LongtermSessionError(TOKEN_DEAD, "passToken/userId 缺失")

        # ① 新鲜 callback sign
        cb = _fresh_callback_sign()

        # ② serviceLogin（sid 必带）
        ts = int(time.time() * 1000)
        login_url = (
            "https://account.xiaomi.com/pass/serviceLogin?sid=i.mi.com&callback="
            + cb + "&_group=DEFAULT&_json=true&ts=" + str(ts)
        )
        st, body, headers, _ = _http(login_url, cookie=self._account_cookie(),
                                     timeout=self.timeout)
        try:
            payload = _strip_json_prefix(body)
        except json.JSONDecodeError as exc:
            raise LongtermSessionError(TRANSIENT, f"serviceLogin 响应非 JSON: {st}") from exc
        code = payload.get("code")
        if code not in (0, None):
            desc = str(payload.get("desc") or "")
            if str(code) == "70016" or "passToken" in desc and "失效" in desc:
                raise LongtermSessionError(
                    TOKEN_DEAD, f"passToken 已失效({code})，请重新从浏览器复制长效票据")
            raise LongtermSessionError(
                TRANSIENT, f"serviceLogin 拒绝(code={code} {desc})，稍后重试")
        location = str(payload.get("location") or "")
        if not location:
            raise LongtermSessionError(TRANSIENT, "serviceLogin 未签发 STS 跳转")

        # ③ STS 逐跳跟随，收集全程 Set-Cookie
        cookies: dict[str, str] = {}
        st, body, headers, cur_url = _http(location, timeout=self.timeout)
        cookies.update(parse_set_cookies(headers))
        hops = 0
        while st in (301, 302, 303, 307) and hops < 6:
            hops += 1
            nxt = headers.get("Location") or headers.get("location") or ""
            if not nxt:
                break
            st, body, headers, cur_url = _http(nxt, timeout=self.timeout)
            cookies.update(parse_set_cookies(headers))
        if not cookies.get("serviceToken"):
            raise LongtermSessionError(
                TRANSIENT, f"STS 链未签发 serviceToken（{st}, {hops} 跳）")
        logger.info("xiaomi longterm renew ok, hops=%d token_len=%d",
                    hops, len(cookies["serviceToken"]))
        return cookies
