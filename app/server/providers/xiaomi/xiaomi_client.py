#!/usr/bin/env python3
"""小米云相册 Web API 客户端（urllib 纯标准库实现，T27）。

设计约束：引擎零第三方依赖——所有接口用 urllib + http.cookiejar 复现。
调研与复现验证：docs/xiaomi-cloud-api-research.md（T26）。

三跳下载链路（T26.5 实测）：
  ① GET /gallery/storage?id={photoId}&callBack=dl_img_cb_{ts}_{n}
     → data.url = kss_web/rd?i=...&cb=...&fn=...
  ② GET kss_web/rd url（JSONP 脚本，正则/字符串截取提取回调体）
     → {"meta":"<一次性 meta 串>","url":"...download_file?ts=<过期毫秒>&sig=<预签名>..."}
  ③ POST download_file url，form-urlencoded meta=<②中 meta>
     → 200 application/octet-stream（原图字节）
     注意：GET 直接访问 download_file 会返回 {"msg":"require meta","stat":"ERR_BAD_PARAMS"}

相册名称：相册 API 响应不含名称（前端按 albumId 本地映射），本模块内置常用
系统相册字典 + 自定义相册兜底名 "相册{albumId}"。
"""
from __future__ import annotations

import http.cookiejar
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

logger = logging.getLogger("albumsync.providers.xiaomi.client")


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

API_BASE = "https://i.mi.com"
API_ORIGIN = "https://i.mi.com"
API_REFERER = "https://i.mi.com/gallery/h5#/"

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# 相册 API 不含名称，前端按 albumId 本地映射。T26 实拍照库里的常用值。
# 自定义相册兜底："相册{albumId}"。
ALBUM_NAME_MAP: dict[str, str] = {
    "1": "相机",
    "2": "截屏",
    "3": "所有视频",
    "4": "私密相册",
    "5": "屏幕录制",
    "0": "全部照片",
    # 社交媒体导入（按用户实测）
    "180": "QQ",
    "222": "微信",
    "223": "微信_65",
    "224": "微信_66",
    "300": "下载",
    "400": "百度云",
}

# 媒体文件类型 → MediaStub/MediaItem 的 file_type 字段（对齐华为语义）
# 华为："1"=photo, "4"=video, "5"=live photo, "9"=heic
# 小米：type="image"/"video"/"heic"，mimeType="image/jpeg"/"video/mp4"/...
def _mimetype_to_file_type(mime: str, photo_type: str) -> str:
    mime = (mime or "").lower()
    photo_type = (photo_type or "").lower()
    if photo_type == "heic" or mime.startswith("image/heic"):
        return "9"
    if photo_type == "live" or "live" in mime:
        return "5"
    if mime.startswith("video/") or photo_type == "video":
        return "4"
    return "1"


# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------

class XiaomiAuthExpiredError(Exception):
    """serviceToken 已失效 / 会话无效。"""


class XiaomiAPIError(Exception):
    """小米云 API 返回非 ok 或 HTTP 错误。"""

    def __init__(self, code: int, description: str, url: str = "") -> None:
        self.code = code
        self.description = description
        self.url = url
        super().__init__(f"[xiaomi {code}] {description} ({url})")


# ---------------------------------------------------------------------------
# 会话解析
# ---------------------------------------------------------------------------

def parse_cookie_string(text: str) -> dict[str, str]:
    """从浏览器 document.cookie 字符串或 cURL cookie header 解析 cookie dict。

    接受两种格式：
    - "userId=196519672; serviceToken=xxx; i.mi.com_isvalid_servicetoken=true"
    - "cookie: userId=196519672; serviceToken=xxx" （cURL -H 前缀）
    """
    text = (text or "").strip()
    if text.lower().startswith("cookie:"):
        text = text[len("cookie:"):].strip()
    cookies: dict[str, str] = {}
    for part in text.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        k = k.strip()
        v = v.strip()
        if k:
            cookies[urlparse.unquote(k)] = urlparse.unquote(v)
    return cookies


def validate_session_cookies(cookies: dict[str, str]) -> tuple[bool, str]:
    """检查 cookie dict 是否含 serviceToken（会话有效性最低要求）。"""
    if not cookies:
        return False, "cookie 为空"
    if not cookies.get("serviceToken"):
        return False, "缺失 serviceToken"
    if not cookies.get("userId"):
        return False, "缺失 userId"
    return True, ""


# ---------------------------------------------------------------------------
# XiaomiClient
# ---------------------------------------------------------------------------

class XiaomiClient:
    """小米云相册 API 客户端（urllib 纯标准库实现）。

    会话管理：内部维护 http.cookiejar.CookieJar，导入 cookie 后自动
    附加到后续所有请求。serviceToken 失效时 XiaomiAuthExpiredError。
    """

    def __init__(
        self,
        cookies: dict[str, str] | None = None,
        *,
        user_agent: str = DEFAULT_USER_AGENT,
        request_delay_ms: int = 1000,
        timeout: int = 30,
    ) -> None:
        self.cookiejar = http.cookiejar.CookieJar()
        self.user_agent = user_agent
        self.request_delay_ms = request_delay_ms  # 保守限速，降低封禁风险
        self.timeout = timeout
        self._last_request_ts: float = 0.0

        if cookies:
            self.set_cookies(cookies)

    # -- 会话管理 --

    def set_cookies(self, cookies: dict[str, str]) -> None:
        """解析 cookie dict 写入 cookiejar（i.mi.com 域）。"""
        now = time.time()
        expires = now + 30 * 86400  # 30 天
        for name, value in cookies.items():
            self.cookiejar.set_cookie(
                http.cookiejar.Cookie(
                    version=0,
                    name=name,
                    value=value,
                    port=None,
                    port_specified=False,
                    domain="i.mi.com",
                    domain_specified=True,
                    domain_initial_dot=False,
                    path="/",
                    path_specified=True,
                    secure=False,
                    expires=expires,
                    discard=False,
                    comment=None,
                    comment_url=None,
                    rest={},
                    rfc2109=False,
                )
            )

    def clear_cookies(self) -> None:
        self.cookiejar.clear()

    def get_cookie_value(self, name: str) -> str:
        for c in self.cookiejar:
            if c.name == name:
                return c.value
        return ""

    # -- 底层请求 --

    def _throttle(self) -> None:
        """保守限速。"""
        if self.request_delay_ms > 0:
            now = time.time()
            elapsed = (now - self._last_request_ts) * 1000
            if elapsed < self.request_delay_ms:
                time.sleep((self.request_delay_ms - elapsed) / 1000.0)

    def _build_opener(self) -> urlrequest.OpenerDirector:
        """构造带 cookiejar 的 opener（urllib 原生方式）。"""
        cookie_handler = urlrequest.HTTPCookieProcessor(self.cookiejar)
        return urlrequest.build_opener(cookie_handler)

    def _default_headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Origin": API_ORIGIN,
            "Referer": API_REFERER,
            "X-Requested-With": "XMLHttpRequest",
        }

    def _get(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET 请求，返回 JSON dict；鉴权失败抛 XiaomiAuthExpiredError。"""
        self._throttle()
        query = {k: str(v) for k, v in (params or {}).items()}
        query.setdefault("ts", str(int(time.time() * 1000)))
        full_url = f"{url}?{urlparse.urlencode(query)}" if "?" not in url else url

        headers = self._default_headers()
        req = urlrequest.Request(full_url, headers=headers, method="GET")

        try:
            opener = self._build_opener()
            with opener.open(req, timeout=self.timeout) as resp:
                self._last_request_ts = time.time()
                body = resp.read().decode("utf-8", errors="replace")
        except urlerror.HTTPError as e:
            if e.code in (401, 403):
                raise XiaomiAuthExpiredError(f"HTTP {e.code} 会话失效") from e
            raise XiaomiAPIError(e.code, str(e.reason or e), url=full_url) from e
        except urlerror.URLError as e:
            raise XiaomiAPIError(0, f"网络错误: {e.reason}", url=full_url) from e

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            raise XiaomiAPIError(0, f"响应非 JSON: {body[:200]}", url=full_url)

        # 统一错误判断：小米 API 顶层 code/result
        result = str(data.get("result") or "").lower()
        code = int(data.get("code") or -1)
        if code == 401 or result in ("auth_expired", "need_login", "unauthorized"):
            raise XiaomiAuthExpiredError(f"API 鉴权失效 (code={code})")
        if result != "ok" and code != 0:
            raise XiaomiAPIError(
                code, str(data.get("description") or data.get("msg") or result),
                url=full_url,
            )
        return data

    def _post_form(self, url: str, fields: dict[str, str]) -> bytes:
        """POST application/x-www-form-urlencoded，返回原始字节（原图下载用）。"""
        self._throttle()
        headers = self._default_headers()
        # POST form 不需要 X-Requested-With
        headers.pop("X-Requested-With", None)
        body = urlparse.urlencode(fields).encode("utf-8")
        req = urlrequest.Request(url, data=body, headers=headers, method="POST")
        # 小米 kss_web 下载要求 Content-Type，且不处理 3xx 自动重定向 urllib 默认处理
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        try:
            opener = self._build_opener()
            with opener.open(req, timeout=self.timeout) as resp:
                self._last_request_ts = time.time()
                return resp.read()
        except urlerror.HTTPError as e:
            if e.code in (401, 403):
                raise XiaomiAuthExpiredError(f"HTTP {e.code} 会话失效") from e
            try:
                err_body = e.read().decode("utf-8", errors="replace")
            except Exception:
                err_body = ""
            raise XiaomiAPIError(
                e.code, f"{e.reason}: {err_body[:300]}", url=url,
            ) from e
        except urlerror.URLError as e:
            raise XiaomiAPIError(0, f"网络错误: {e.reason}", url=url) from e

    # ------------------------------------------------------------------
    # 公开 API（相册列表 / 时间线 / 照片列表 / 下载链路）
    # ------------------------------------------------------------------

    def probe_session(self) -> bool:
        """探活：调 album/list 看是否返回 ok。"""
        try:
            self.get_album_list()
            return True
        except XiaomiAuthExpiredError:
            return False
        except Exception:
            return False

    def get_album_list(self) -> list[dict[str, Any]]:
        """GET /gallery/user/album/list → 相册原始 dict 列表（含 albumId/mediaCount）。"""
        data = self._get(
            f"{API_BASE}/gallery/user/album/list",
            {"pageNum": 0, "pageSize": 100, "isShared": "false",
             "numOfThumbnails": 1},
        )
        return list((data.get("data") or {}).get("albums") or [])

    def get_timeline(self, album_id: str | None = None) -> dict[str, int]:
        """GET /gallery/user/timeline → {YYYYMMDD: count, ...}。"""
        params: dict[str, Any] = {}
        if album_id:
            params["albumId"] = album_id
        data = self._get(f"{API_BASE}/gallery/user/timeline", params)
        return dict((data.get("data") or {}).get("dayCount") or {})

    def get_photo_page(
        self,
        start_date: str,
        end_date: str,
        *,
        page_num: int = 0,
        page_size: int = 30,
        album_id: str | None = None,
    ) -> dict[str, Any]:
        """GET /gallery/user/galleries → 分页响应。"""
        params: dict[str, Any] = {
            "startDate": start_date,
            "endDate": end_date,
            "pageNum": page_num,
            "pageSize": page_size,
        }
        if album_id:
            params["albumId"] = album_id
        return self._get(f"{API_BASE}/gallery/user/galleries", params)

    # -- 相册名称映射辅助 --

    @staticmethod
    def resolve_album_name(album_id: str) -> str:
        album_id = str(album_id or "")
        return ALBUM_NAME_MAP.get(album_id, f"相册{album_id}")

    # -- 三跳下载链路（T26.5） --

    def get_download_meta(self, photo_id: str) -> tuple[str, str]:
        """执行 ①②，返回 (download_file_url, meta)。

        调用方自行决定是否调用 download_with_meta() 取字节。
        """
        photo_id = str(photo_id)
        cb_id = f"dl_img_cb_{int(time.time() * 1000)}"

        # ① /gallery/storage
        step1 = self._get(
            f"{API_BASE}/gallery/storage",
            {"id": photo_id, "callBack": cb_id},
        )
        data_url = (step1.get("data") or {}).get("url")
        if not data_url:
            raise XiaomiAPIError(
                int(step1.get("code") or 0),
                "storage 响应无 data.url",
                url=f"{API_BASE}/gallery/storage?id={photo_id}",
            )

        # ② kss_web/rd（JSONP 脚本，需要剥离回调）
        self._throttle()
        headers = self._default_headers()
        headers.pop("X-Requested-With", None)  # 第三方域 kss_web 不需要
        req = urlrequest.Request(data_url, headers=headers, method="GET")
        try:
            opener = self._build_opener()
            with opener.open(req, timeout=self.timeout) as resp:
                self._last_request_ts = time.time()
                jsonp_body = resp.read().decode("utf-8", errors="replace")
        except urlerror.HTTPError as e:
            if e.code in (401, 403):
                raise XiaomiAuthExpiredError(f"HTTP {e.code} kss_web 失效") from e
            raise XiaomiAPIError(e.code, str(e.reason or e), url=data_url) from e
        except urlerror.URLError as e:
            raise XiaomiAPIError(0, f"网络错误: {e.reason}", url=data_url) from e

        # 剥离 JSONP 回调体：dl_img_cb_xxx({...})
        cb_match = re.search(r"dl_img_cb_\w+\((\{.+?\})\)\s*;?\s*$", jsonp_body, re.DOTALL)
        if not cb_match:
            raise XiaomiAPIError(
                0, f"JSONP 解析失败: {jsonp_body[:200]}", url=data_url,
            )
        try:
            cb_data = json.loads(cb_match.group(1))
        except json.JSONDecodeError:
            raise XiaomiAPIError(
                0, f"JSONP 内部 JSON 解析失败: {cb_match.group(1)[:200]}", url=data_url,
            )

        meta = cb_data.get("meta")
        download_url = cb_data.get("url")
        if not meta or not download_url:
            raise XiaomiAPIError(
                0,
                f"kss_web 响应缺 meta/url: {cb_data}",
                url=data_url,
            )

        return str(download_url), str(meta)

    def download_with_meta(self, download_url: str, meta: str,
                           *, sink: Callable[[bytes], None] | None = None,
                           chunk_size: int = 65536) -> bytes:
        """执行 ③：POST download_file url 取原图字节。

        sink：可选流式写入回调（避免大文件一次性载入内存）；不传时返回完整 bytes。
        """
        if sink is None:
            return self._post_form(download_url, {"meta": meta})

        # 流式版本：手动发起 POST 然后逐 chunk 读
        self._throttle()
        headers = self._default_headers()
        headers.pop("X-Requested-With", None)
        body = urlparse.urlencode({"meta": meta}).encode("utf-8")
        req = urlrequest.Request(download_url, data=body, headers=headers, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        try:
            opener = self._build_opener()
            with opener.open(req, timeout=self.timeout) as resp:
                self._last_request_ts = time.time()
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    sink(chunk)
        except urlerror.HTTPError as e:
            if e.code in (401, 403):
                raise XiaomiAuthExpiredError(f"HTTP {e.code} 会话失效") from e
            raise XiaomiAPIError(e.code, str(e.reason or e), url=download_url) from e
        except urlerror.URLError as e:
            raise XiaomiAPIError(0, f"网络错误: {e.reason}", url=download_url) from e
        return b""
