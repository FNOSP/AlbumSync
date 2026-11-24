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

会话轮替观察（T28.1，对齐 icloudpd 每请求捕获语义）：服务端可能在任意响应中
轮替 serviceToken 等会话 cookie。构造时传入 session_observer 回调后，每次请求
前后对会话域 cookie 做快照比对，有变化即回调（调用方负责落盘，见
XiaomiAuthStrategy._on_session_rotated）。
"""
from __future__ import annotations

import http.cookiejar
import json
import logging
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator
from hwcloudpd.models import AuthExpiredError
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

# 登录域：passToken 属于 account.xiaomi.com（serviceToken 失效后凭它静默
# 重签，T31.7）；与 i.mi.com 会话域分离。测试可注入本地域。
ACCOUNT_COOKIE_DOMAIN = ".account.xiaomi.com"

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

class XiaomiAuthExpiredError(AuthExpiredError):
    """serviceToken 已失效 / 会话无效。

    T28.2：继承引擎 AuthExpiredError（vendor hwcloudpd 纯标准库，无三方依赖）。
    引擎 sync 下载循环与 daemon keepalive 对该类型有专断分支——中断整轮、
    标记 auth 失效并通知，而不是逐张计 failed 继续空转。
    """


class XiaomiAPIError(Exception):
    """小米云 API 返回非 ok 或 HTTP 错误。"""

    def __init__(self, code: int, description: str, url: str = "") -> None:
        self.code = code
        self.description = description
        self.url = url
        super().__init__(f"[xiaomi {code}] {description} ({url})")


class _XiaomiRangeNotSatisfiable(Exception):
    """下载续传 Range 起点越界（HTTP 416）——内部信号，download_to_file 捕获后删 part 重下。"""


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
        session_observer: Callable[[dict[str, str]], None] | None = None,
        session_cookie_domain: str = "i.mi.com",
        account_cookie_domain: str = ACCOUNT_COOKIE_DOMAIN,
        service_login_base: str = "",
        probe_base: str = "https://i.mi.com",
    ) -> None:
        self.cookiejar = http.cookiejar.CookieJar()
        self.user_agent = user_agent
        self.request_delay_ms = request_delay_ms  # 保守限速，降低封禁风险
        self.timeout = timeout
        # 会话加载时间（auth_status 的 session_updated_at 展示用；近似值，
        # 重签成功后刷新 → session_age_sec 由此起算）
        self.updated_at = time.time()
        self._last_request_ts: float = 0.0
        # T28.1 会话轮替观察：session_cookie_domain 同时决定导入 cookie 的
        # 归属域与观察器快照的过滤域（测试注入 localhost 域）。
        self._session_observer = session_observer
        self._session_cookie_domain = session_cookie_domain
        # T31.7：登录域（passToken）与会话域分离；测试注入与登录域一致
        self._account_cookie_domain = account_cookie_domain
        # T31.9：重签标准入口 origin（空 = 生产 account.xiaomi.com；测试注入
        # 本地 mock，避免测试凭据触达真实小米域名）
        self._service_login_base = service_login_base
        # T31.9：匿名探活 origin（取新鲜签名 callback 用；测试注入本地 mock）
        self._probe_base = probe_base
        self._session_before: dict[str, str] | None = None
        self._obs_lock = threading.Lock()
        self._resign_lock = threading.Lock()
        # 重签失败冷却（T31.9）：真机实测失效后每 15s 被动重签会被风控逐步
        # 升级（安全验证 → passToken 作废），轰炸式重试适得其反
        self._resign_blocked_until: float = 0.0
        # 风控状态（T31.10，auth_status/UI 倒计时用）：kind="" | "rate_limited"
        self.risk_until: float = 0.0
        self.risk_kind: str = ""
        # 最近一次鉴权失败响应 body 的 serviceLogin D URL（重签复用，一次性）
        self._pending_resign_url: str = ""

        if cookies:
            self.set_cookies(cookies)

    # -- 会话管理 --

    def set_cookies(self, cookies: dict[str, str]) -> None:
        """解析 cookie dict 写入 cookiejar。

        域分流（T31.7）：passToken 落登录域（重签凭据，不随 i.mi.com 请求
        发送）；userId 双域都需要（会话 API 与 account 域重签）；其余落会话域。
        """
        now = time.time()
        expires = now + 30 * 86400  # 30 天
        domain = self._session_cookie_domain
        for name, value in cookies.items():
            domains = [domain]
            if name == "passToken":
                domains = [self._account_cookie_domain]
            elif name == "userId":
                domains = [domain, self._account_cookie_domain]
            for dm in domains:
                self.cookiejar.set_cookie(
                    http.cookiejar.Cookie(
                        version=0,
                        name=name,
                        value=value,
                        port=None,
                        port_specified=False,
                        domain=dm,
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

    @property
    def user_id(self) -> str:
        """cookie 中的 userId（import_curl API 响应与日志用）。"""
        return self.get_cookie_value("userId")

    # -- 会话轮替观察（T28.1） --

    def _snapshot_session_cookies(self) -> dict[str, str]:
        """会话相关 cookie 的 name→value 快照（观察器比对用）。

        T31.7 起包含登录域 passToken/userId（轮替落盘时保留重签凭据）。
        """
        snap: dict[str, str] = {}
        account_d = self._account_cookie_domain.lstrip(".")
        for c in self.cookiejar:
            d = (c.domain or "").lstrip(".")
            if d == self._session_cookie_domain or d == account_d:
                snap[c.name] = c.value or ""
        return snap

    def _observe_request(self) -> None:
        """请求前快照会话 cookie，供响应后比对轮替。"""
        if self._session_observer is None:
            return
        with self._obs_lock:
            self._session_before = self._snapshot_session_cookies()

    def _observe_response(self) -> None:
        """响应后比对快照；会话域 cookie 有轮替时回调观察器。

        回调收到当前会话域完整 cookie dict（含未变化的键），由调用方整体落盘。
        观察器异常只告警，不影响请求结果。未变化的响应（绝大多数）零开销。
        """
        if self._session_observer is None or self._session_before is None:
            return
        with self._obs_lock:
            before = self._session_before
            self._session_before = None
            now = self._snapshot_session_cookies()
        changed = {k: v for k, v in now.items() if before.get(k) != v}
        if not changed:
            return
        logger.debug("xiaomi session cookie rotated: %s", ", ".join(sorted(changed)))
        try:
            self._session_observer(now)
        except Exception as e:
            logger.warning("xiaomi session observer callback failed: %s", e)

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
        """GET 请求，返回 JSON dict；鉴权失败抛 XiaomiAuthExpiredError。

        T31.7：鉴权失效时若 jar 中有 passToken（扫码/重签会话），先静默重签
        新 serviceToken 再重试一次；重签失败原样抛出（每次请求至多重签一次）。
        """
        try:
            return self._get_once(url, params)
        except XiaomiAuthExpiredError:
            if self._try_resign():
                return self._get_once(url, params)
            raise

    @staticmethod
    def _extract_service_login_url(body: bytes) -> str:
        """从鉴权失败响应 body 提取 serviceLogin D URL（重签 callback 复用）。"""
        try:
            return str(json.loads(body.decode("utf-8", errors="replace")).get("D") or "")
        except (ValueError, AttributeError):
            return ""

    def _get_once(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """单次 GET（无重签重试）。鉴权失败前暂存 401 body 的 D URL。"""
        self._throttle()
        query = {k: str(v) for k, v in (params or {}).items()}
        query.setdefault("ts", str(int(time.time() * 1000)))
        full_url = f"{url}?{urlparse.urlencode(query)}" if "?" not in url else url

        headers = self._default_headers()
        req = urlrequest.Request(full_url, headers=headers, method="GET")

        try:
            self._observe_request()
            opener = self._build_opener()
            with opener.open(req, timeout=self.timeout) as resp:
                self._last_request_ts = time.time()
                self._observe_response()
                body = resp.read().decode("utf-8", errors="replace")
        except urlerror.HTTPError as e:
            if e.code in (401, 403):
                self._pending_resign_url = self._extract_service_login_url(e.read())
                raise XiaomiAuthExpiredError(f"HTTP {e.code} 会话失效") from e
            raise XiaomiAPIError(e.code, str(e.reason or e), url=full_url) from e
        except urlerror.URLError as e:
            raise XiaomiAPIError(0, f"网络错误: {e.reason}", url=full_url) from e

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            raise XiaomiAPIError(0, f"响应非 JSON: {body[:200]}", url=full_url)

        # 统一错误判断：小米 API 顶层 code/result/R
        result = str(data.get("result") or "").lower()
        code = int(data.get("code") or -1)
        if (code == 401 or str(data.get("R") or "") == "401"
                or result in ("auth_expired", "need_login", "unauthorized")):
            self._pending_resign_url = str(data.get("D") or "")
            raise XiaomiAuthExpiredError(f"API 鉴权失效 (code={code})")
        if result != "ok" and code != 0:
            if code == 10001:
                # 小米限流/风控（T31.10）：短时间高频扫码+重签触发，业务接口
                # 整体拒绝（album/list 10001 系统错误），静默一段时间自愈——
                # 记录状态供 auth_status/UI 倒计时提示「何时再扫码」
                self.risk_kind = "rate_limited"
                self.risk_until = time.time() + 1800.0
            raise XiaomiAPIError(
                code, str(data.get("description") or data.get("msg") or result),
                url=full_url,
            )
        # 请求成功 = 限流已解除（若有）——即时清掉，避免倒计时误导
        if self.risk_kind:
            self.risk_kind = ""
            self.risk_until = 0.0
        return data

    # 重签失败冷却时长（T31.9）：真机实测失效后高频被动重签会被小米风控
    # 逐步升级（code=0 无 location 要求安全验证 → passToken 整体作废 70016）
    RESIGN_COOLDOWN_SEC = 1800.0

    def session_age_sec(self) -> float:
        """当前会话凭据获取至今的秒数（构建/最近一次重签成功时刻起算）。"""
        return time.time() - self.updated_at

    def risk_state(self) -> dict[str, Any]:
        """风控状态（T31.10，auth_status/UI 倒计时用）。

        {"kind": "rate_limited", "retry_after_ts": <epoch>}（限流中，届时恢复）
        或 {"kind": "", "retry_after_ts": 0}（无限流；会话失效类提示由
        has_session/auth_valid 承载，不在此重复）。
        """
        if time.time() < self.risk_until:
            return {"kind": self.risk_kind, "retry_after_ts": self.risk_until}
        return {"kind": "", "retry_after_ts": 0.0}

    def refresh_session(self) -> bool:
        """静默重签会话（T31.9 心跳预防性续期入口）。

        无 pending D URL 时先匿名探活取一枚新鲜签名 callback（spike 实测：
        serviceLogin 换发必须带签名 callback，不带只能拿到 wb_ 引导地址建立
        不了会话）。成功 True；失败 False 并进入冷却（RESIGN_COOLDOWN_SEC）。
        """
        if not self._pending_resign_url:
            try:
                # 局部导入避免与 qr_login 的循环依赖
                from .qr_login import fetch_service_login_url
                url = fetch_service_login_url(
                    probe_base=self._probe_base,
                    user_agent=self.user_agent, timeout=self.timeout)
                if url:
                    self._pending_resign_url = url
            except Exception as e:
                logger.info("xiaomi probe for resign callback failed: %s", e)
        return self._try_resign()

    def _try_resign(self) -> bool:
        """passToken 静默重签 serviceToken（T31.7，浏览器续期语义）。

        前提：jar 中存在登录域 passToken + userId（扫码登录会话已落盘
        passToken；浏览器导入会话通常没有，直接跳过保持原语义）。成功后新
        cookie 写回 jar 并触发会话观察器落盘（快照含 passToken）。
        失败进入冷却（T31.9）：风控升级与重试频率正相关，冷却期内直接跳过。
        """
        with self._resign_lock:
            if time.time() < self._resign_blocked_until:
                logger.debug(
                    "xiaomi resign in cooldown (%.0fs left)",
                    self._resign_blocked_until - time.time())
                return False
            pass_token = self.get_cookie_value("passToken")
            user_id = self.get_cookie_value("userId")
            self._pending_resign_url, pending = "", self._pending_resign_url
            if not pass_token or not user_id:
                logger.info("xiaomi resign skipped: no passToken/userId in jar")
                return False
            try:
                # 局部导入避免与 qr_login 的循环依赖
                from .qr_login import resign_session_cookies
                cookies = resign_session_cookies(
                    pass_token, user_id, pending,
                    account_domain=self._account_cookie_domain,
                    user_agent=self.user_agent, timeout=self.timeout,
                    standard_base=self._service_login_base,
                )
            except Exception as e:
                self._resign_blocked_until = time.time() + self.RESIGN_COOLDOWN_SEC
                logger.warning("xiaomi resign failed (cooldown %.0f min): %s",
                               self.RESIGN_COOLDOWN_SEC / 60, e)
                return False
            self.set_cookies(cookies)
            self._resign_blocked_until = 0.0
            self.updated_at = time.time()
            if self._session_observer is not None:
                try:
                    self._session_observer(self._snapshot_session_cookies())
                except Exception as e:
                    logger.warning("xiaomi resign observer failed: %s", e)
            logger.info("xiaomi serviceToken resigned via passToken")
            return True

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
            self._observe_request()
            opener = self._build_opener()
            with opener.open(req, timeout=self.timeout) as resp:
                self._last_request_ts = time.time()
                self._observe_response()
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

        调用方自行决定是否调用 download_to_file() 取字节。
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
            self._observe_request()
            opener = self._build_opener()
            with opener.open(req, timeout=self.timeout) as resp:
                self._last_request_ts = time.time()
                self._observe_response()
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

    def download_to_file(
        self,
        download_url: str,
        meta: str,
        path: Path | str,
        *,
        resume: bool = True,
        chunk_size: int = 65536,
        refresh_meta: Callable[[], tuple[str, str]] | None = None,
    ) -> str:
        """执行 ③：POST download_file 流式写盘，支持 .part 断点续传（T28.4）。

        对齐 icloudpd .part 语义：path 已有部分内容时带 Range: bytes=N- 请求；
        206 追加续传；200（服务端忽略 Range 返回全量）覆盖重写；416（Range
        起点越界）两段式处理（T45.2）：部分网关把预签 URL 失效也统一映射为
        416，故先经 refresh_meta 刷新 URL 重试一次 Range 续传，仍 416 才认定
        part 真越界，删 part 全量重下。校验与原子落位由调用方负责
        （引擎 sync 层做 sha1 校验后 rename）。

        返回落位方式："resumed"（206 续传）/ "full"（200 全量覆盖）/
        "downloaded"（首次全量下载）。
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        existing = path.stat().st_size if (resume and path.exists()) else 0
        if existing > 0:
            try:
                return self._download_post(download_url, meta, path, range_start=existing,
                                           chunk_size=chunk_size)
            except _XiaomiRangeNotSatisfiable:
                if refresh_meta is not None:
                    try:
                        dl2, meta2 = refresh_meta()
                        return self._download_post(dl2, meta2, path, range_start=existing,
                                                   chunk_size=chunk_size)
                    except _XiaomiRangeNotSatisfiable:
                        logger.info(
                            "xiaomi download range unsatisfiable after url refresh,"
                            " restart full: %s",
                            path.name,
                        )
                else:
                    logger.info(
                        "xiaomi download range unsatisfiable, restart full: %s", path.name
                    )
                path.unlink(missing_ok=True)
        return self._download_post(download_url, meta, path, range_start=None,
                                   chunk_size=chunk_size)

    def _download_post(
        self,
        download_url: str,
        meta: str,
        path: Path,
        *,
        range_start: int | None,
        chunk_size: int,
    ) -> str:
        """单次 POST 下载请求。range_start 非 None 时带 Range 尝试续传。"""
        self._throttle()
        headers = self._default_headers()
        headers.pop("X-Requested-With", None)
        if range_start is not None:
            headers["Range"] = f"bytes={int(range_start)}-"
        body = urlparse.urlencode({"meta": meta}).encode("utf-8")
        req = urlrequest.Request(download_url, data=body, headers=headers, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        try:
            self._observe_request()
            opener = self._build_opener()
            with opener.open(req, timeout=self.timeout) as resp:
                self._last_request_ts = time.time()
                self._observe_response()
                status = resp.getcode() or 200
                if range_start is not None and status == 206:
                    mode, outcome = "ab", "resumed"
                else:
                    # 200（含服务端忽略 Range 的场景）一律全量覆盖
                    mode, outcome = "wb", ("full" if range_start is not None else "downloaded")
                with open(path, mode) as fh:
                    while True:
                        chunk = resp.read(chunk_size)
                        if not chunk:
                            break
                        fh.write(chunk)
                return outcome
        except urlerror.HTTPError as e:
            if e.code == 416 and range_start is not None:
                raise _XiaomiRangeNotSatisfiable(str(e)) from e
            if e.code in (401, 403):
                raise XiaomiAuthExpiredError(f"HTTP {e.code} 会话失效") from e
            raise XiaomiAPIError(e.code, str(e.reason or e), url=download_url) from e
        except urlerror.URLError as e:
            raise XiaomiAPIError(0, f"网络错误: {e.reason}", url=download_url) from e
