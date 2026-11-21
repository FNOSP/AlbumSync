#!/usr/bin/env python3
"""小米扫码登录状态机（T31.2，协议详见 docs/xiaomi-cloud-api-research.md §6）。

6 步全链路（T31.1 spike 真机验证）：
  1. 匿名 GET album/list → HTTP 200 body {"R":401,"D":<serviceLogin 带签 callback>}
  2. GET /longPolling/loginUrl → &&&START&&&{loginUrl:<可扫内容>, qr:<官方二维码图片URL>,
     lp:<长轮询URL>, timeout:300}（扫码内容必须取 loginUrl，见 _start_locked 注释）
  3. 循环 GET <lp>（服务端挂起 ~60s 无事件断连）→ 确认后返回
     {passToken, userId, ssecurity, location, code:0, ...}
  4. passToken+userId → GET /pass/serviceLogin?sid=i.mi.com&_json=true → 新签 location
  5. GET <location>（302）→ Set-Cookie 原始头种 serviceToken/userId/slh/ph
  6. 用 cookie 调 album/list 验证（strategy 层做 probe）

线程模型：XiaomiAuthStrategy 用锁串行化 start/poll；poll 内部最长挂起
poll_socket_timeout 秒，只占用当前请求线程（ThreadingHTTPServer 每请求一线程，
不阻塞其他账号/API）。网络层方法可注入/覆写便于单测（T31.5）。
"""
from __future__ import annotations

import http.cookiejar
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .xiaomi_client import DEFAULT_USER_AGENT

logger = logging.getLogger(__name__)

PASSPORT_BASE = "https://account.xiaomi.com"
LP_LOGIN_URL = PASSPORT_BASE + "/longPolling/loginUrl"
SERVICE_LOGIN = PASSPORT_BASE + "/pass/serviceLogin"
SID = "i.mi.com"
QS = "%253Fsid%253Di.mi.com"
DEFAULT_TIMEOUT_S = 300  # 服务端票据有效期（loginUrl 响应 timeout 字段兜底）
POLL_SOCKET_TIMEOUT_S = 65  # lp 单次挂起上限（服务端 ~60s 断连）

_JSONP_PREFIX = re.compile(r"^&&&START&&&")
_SET_COOKIE_FIRST = re.compile(r"^\s*([^=;\s]+)\s*=\s*(.*)$")


def strip_jsonp(body: bytes | str) -> str:
    """去掉小米 passport 响应的 &&&START&&& 前缀。"""
    s = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
    return _JSONP_PREFIX.sub("", s).strip()


def parse_set_cookie_pairs(set_cookie_values: list[str]) -> dict[str, str]:
    """从 Set-Cookie 原始头提取 name=value（首个分号前段）。

    STS 302 链中 userId cookie 可能因 secure/domain 属性被 http.cookiejar
    丢弃（T31.1 v3 实验 jar 只收到 3/6），故直接从原始头手工解析。
    空值跳过（如登出时的 i.mi.com_slh=）。
    """
    out: dict[str, str] = {}
    for sc in set_cookie_values or []:
        first = sc.split(";", 1)[0]
        m = _SET_COOKIE_FIRST.match(first)
        if m and m.group(1) and m.group(2):
            out[m.group(1)] = m.group(2)
    return out


def _header(headers: dict[str, str], name: str) -> str:
    """大小写不敏感的 header 取值。"""
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v or ""
    return ""


def _http_get_no_redirect(
    jar: http.cookiejar.CookieJar, url: str, *, user_agent: str,
    timeout: int = 30,
) -> tuple[int, dict[str, str], bytes, list[str]]:
    """独立 jar 的 GET（不跟随重定向），供 passToken 重签使用。"""
    req = urllib.request.Request(
        url, headers={"User-Agent": user_agent})
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), _NoRedirect())
    try:
        r = opener.open(req, timeout=timeout)
        return (r.status, dict(r.headers), r.read(),
                r.headers.get_all("Set-Cookie") or [])
    except urllib.error.HTTPError as e:
        return (e.code, dict(e.headers), e.read(),
                e.headers.get_all("Set-Cookie") or [])


def fetch_service_login_url(
    *, probe_base: str = "https://i.mi.com",
    user_agent: str = DEFAULT_USER_AGENT, timeout: int = 30,
) -> str:
    """匿名探活 i.mi.com，取 401 body 的签名 serviceLogin D URL（T31.9）。

    spike 实测：serviceLogin 换发必须带 i.mi.com 签发的签名 callback，
    否则只能拿到 wb_ 引导地址（无 sign/auth，建立不了会话）。签名 callback
    可随时匿名获取（与凭据无关），预防性续签前先取一枚新鲜的。
    """
    ts = int(time.time() * 1000)
    probe = (f"{probe_base}/gallery/user/album/list"
             f"?ts={ts}&pageNum=0&pageSize=10&isShared=false&numOfThumbnails=1")
    req = urllib.request.Request(probe, headers={"User-Agent": user_agent})
    try:
        body = urllib.request.urlopen(req, timeout=timeout).read()
    except urllib.error.HTTPError as e:
        body = e.read()
    try:
        return str(json.loads(body.decode("utf-8", errors="replace")).get("D") or "")
    except (ValueError, AttributeError):
        return ""


def resign_session_cookies(
    pass_token: str, user_id: str, service_login_url: str = "",
    *, account_domain: str = ".account.xiaomi.com",
    user_agent: str = DEFAULT_USER_AGENT, timeout: int = 30,
    standard_base: str = "",
) -> dict[str, str]:
    """passToken 静默重签（T31.7）：serviceLogin(_json) → STS 302 链收集 cookie。

    浏览器续期语义：serviceToken 被服务端作废时（401 响应回发空值清除
    cookie），凭 account 域 passToken 重走 step4-5 换取新 serviceToken。
    service_login_url 传鉴权失败响应 body 的 D 字段（已含签名 callback 的
    serviceLogin URL）；为空时按标准入口构造（可能因 callback 未签名被拒，
    code 10025）。返回 cookie dict（含 passToken，供整体落盘）。
    """
    if not pass_token or not user_id:
        raise XiaomiQRLoginError("重签缺少 passToken/userId")
    jar = http.cookiejar.CookieJar()

    def _set(domain: str, name: str, value: str) -> None:
        jar.set_cookie(http.cookiejar.Cookie(
            version=0, name=name, value=value, port=None, port_specified=False,
            domain=domain, domain_specified=True, domain_initial_dot=False,
            path="/", path_specified=True, secure=False, expires=None,
            discard=True, comment=None, comment_url=None, rest={}, rfc2109=False))

    _set(account_domain, "passToken", pass_token)
    _set(account_domain, "userId", user_id)

    # 无 D URL 时（预防性续期）标准入口从 standard_base 构造（生产即
    # account.xiaomi.com；测试注入本地 mock，绝不向生产域名发测试凭据）
    base = standard_base or PASSPORT_BASE
    sl_url = service_login_url or f"{base}/pass/serviceLogin?sid={SID}"
    if "_json=" not in sl_url:
        sl_url += ("&" if "?" in sl_url else "?") + "_json=true"

    def _get(u: str) -> tuple[int, dict[str, str], bytes, list[str]]:
        return _http_get_no_redirect(jar, u, user_agent=user_agent, timeout=timeout)

    # 候选链（T31.9）：真机实测 401 body 的 D URL（含 checkSafePhone/_bal）在
    # passToken 有效时也可能返回 code=0 无 location（无法换新 token）；T31.1
    # spike 实测成功的形态是不带这些附加参数的标准入口——故 D URL 失败后回退
    # 标准入口再试一次，响应体记入日志供诊断。
    # 标准入口 host 从 D URL 派生（生产即 account.xiaomi.com；测试注入域时
    # 落在本地 mock，绝不向生产域名发测试凭据）。
    candidates = [sl_url]
    origin = standard_base or PASSPORT_BASE
    if service_login_url:
        parts = urllib.parse.urlsplit(service_login_url)
        if parts.scheme and parts.netloc:
            origin = f"{parts.scheme}://{parts.netloc}"
    standard = f"{origin}/pass/serviceLogin?sid={SID}&_group=DEFAULT&_json=true"
    if standard != candidates[0]:
        candidates.append(standard)

    data: dict[str, object] | None = None
    for i, u in enumerate(candidates):
        st, _, body, _ = _get(u)
        try:
            data = json.loads(strip_jsonp(body))
        except ValueError as e:
            raise XiaomiQRLoginError(
                f"重签 serviceLogin 响应解析失败(HTTP {st}): {e}") from e
        code = data.get("code")
        location = str(data.get("location") or "")
        if code == 70016:
            # 失效形态（T31.9 真机实测：裸 URL 与完整签名 callback 均如此，
            # 且带登录页 location）——换任何入口都无效，立即终止并指明出路
            raise XiaomiQRLoginError(
                "passToken 已失效(70016)，无法自动重签；请重新扫码或导入登录态")
        if code not in (0, None):
            raise XiaomiQRLoginError(
                f"重签 serviceLogin 拒绝: code={code} {data.get('desc')}")
        if location:
            break
        logger.warning(
            "xiaomi resign: serviceLogin 未签发 STS(%s)，body: %s",
            "D URL" if i == 0 else "标准入口",
            body.decode("utf-8", errors="replace")[:300])
        data = None  # 尝试下一候选入口

    if data is None:
        raise XiaomiQRLoginError(
            "serviceLogin 未签发 STS(无 location)，无法自动重签；"
            "请重新扫码或导入登录态")
    location = str(data.get("location"))

    cookies: dict[str, str] = {}
    hop = location
    for _ in range(8):
        st, headers, _, set_cookies = _get(hop)
        cookies.update(parse_set_cookie_pairs(set_cookies))
        nxt = ""
        if st in (301, 302, 303, 307):
            nxt = _header(headers, "Location")
        if not nxt:
            break
        hop = nxt
    cookies.setdefault("passToken", pass_token)
    if not cookies.get("serviceToken"):
        # 诊断（T31.9）：location 可能是登录/验证页而非 STS——记录以确认风控形态
        logger.warning(
            "xiaomi resign: STS 链未收到 serviceToken，location=%s last_hop=%s",
            location[:120], hop[:120])
        raise XiaomiQRLoginError("重签完成但未收到 serviceToken")
    return cookies


class XiaomiQRLoginError(Exception):
    """扫码登录流程错误（网络/协议/票据失效）。"""


class XiaomiQRLogin:
    """一次扫码登录会话：start() 创建票据，poll() 驱动状态机到 confirmed。

    状态：
      - waiting   未确认（含 lp 超时重挂）；前端继续轮询
      - confirmed 已确认且 cookie 换发完成；携带 cookies/user_id
      - expired   票据超过 timeout 秒；需重新 start
      - failed    协议/网络不可恢复错误；携带 error
    """

    def __init__(
        self,
        *,
        timeout_s: int = DEFAULT_TIMEOUT_S,
        poll_socket_timeout_s: int = POLL_SOCKET_TIMEOUT_S,
    ) -> None:
        self.timeout_s = timeout_s
        self.poll_socket_timeout_s = poll_socket_timeout_s
        self.qr_content: str = ""
        self.lp_url: str = ""
        self.expire_at: float = 0.0
        # 确认载荷（含 callback 等上下文），confirmed 后供换发复用
        self._callback: str = ""
        self._jar = http.cookiejar.CookieJar()
        self._lock = threading.Lock()

    # -- 网络层（可覆写/注入） --

    def _http_get(
        self, url: str, *, headers: dict[str, str] | None = None,
        timeout: int = 30,
    ) -> tuple[int, dict[str, str], bytes, list[str]]:
        """GET 请求。返回 (status, headers_dict, body, set_cookie_values)。

        不自动跟随重定向（302 需手工逐跳收集 Set-Cookie）。
        socket 超时抛 socket.timeout / urllib.error.URLError。
        """
        req = urllib.request.Request(
            url, headers={"User-Agent": DEFAULT_USER_AGENT, **(headers or {})})
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._jar), _NoRedirect())
        try:
            r = opener.open(req, timeout=timeout)
            return (r.status, dict(r.headers), r.read(),
                    r.headers.get_all("Set-Cookie") or [])
        except urllib.error.HTTPError as e:
            return (e.code, dict(e.headers), e.read(),
                    e.headers.get_all("Set-Cookie") or [])

    # -- step 1-2：创建票据 --

    def start(self) -> dict[str, object]:
        """匿名探活拿签名 callback → 创建扫码票据。

        返回 {"qr", "lp_url", "expire_at", "timeout"}。
        """
        with self._lock:
            return self._start_locked()

    def _start_locked(self) -> dict[str, object]:
        # step1: 401.D（注意：HTTP 200，业务码在 body）
        probe_url = (
            "https://i.mi.com/gallery/user/album/list"
            f"?ts={int(time.time() * 1000)}&pageNum=0&pageSize=10"
            "&isShared=false&numOfThumbnails=1"
        )
        st, _, body, _ = self._http_get(probe_url)
        try:
            d_url = json.loads(body).get("D", "")
        except (ValueError, AttributeError):
            d_url = ""
        m = re.search(r"callback=([^&]+)", d_url)
        if not d_url or not m:
            raise XiaomiQRLoginError(
                f"匿名探活未返回登录回调（HTTP {st}），i.mi.com 入口可能变更")
        self._callback = urllib.parse.unquote(m.group(1))

        # step2: loginUrl
        u = (
            f"{LP_LOGIN_URL}?sid={SID}"
            f"&callback={urllib.parse.quote(self._callback, safe='')}"
            f"&serviceParam=&qs={QS}&_hasLogo=false&_qrsize=240"
            f"&_locale=zh_CN&_dc={int(time.time() * 1000)}"
        )
        st, _, body, _ = self._http_get(u)
        try:
            data = json.loads(strip_jsonp(body))
        except ValueError as e:
            raise XiaomiQRLoginError(f"loginUrl 响应解析失败: {e}") from e
        if data.get("code") != 0 or not data.get("qr") or not data.get("lp"):
            raise XiaomiQRLoginError(
                f"loginUrl 创建失败: code={data.get('code')} {data.get('desc')}")
        # 扫码内容必须取 loginUrl（与 lp 同 ticket 的可扫通道，真机 PNG 解码实测
        # 官方二维码图片内嵌的正是它）：小米账号扫一扫扫它直接弹确认。
        # qr 字段是「把 loginUrl 编成二维码的图片」的 URL（官方登录页当 <img> 用），
        # 误把 qr 编码进二维码会导致手机扫开后只展示图片里的真二维码（0.3.7 反馈）。
        self.qr_content = data.get("loginUrl") or data["qr"]
        self.lp_url = data["lp"]
        self.timeout_s = int(data.get("timeout") or self.timeout_s)
        self.expire_at = time.time() + self.timeout_s
        return {
            "qr": self.qr_content,
            "lp_url": self.lp_url,
            "expire_at": self.expire_at,
            "timeout": self.timeout_s,
        }

    # -- step 3-6：轮询状态机 --

    def poll(self) -> dict[str, object]:
        """挂 lp 长轮询一次，返回当前状态。

        {"status": "waiting"}
        | {"status": "confirmed", "cookies": {...}, "user_id": ...}
        | {"status": "expired"} | {"status": "failed", "error": ...}
        """
        with self._lock:
            if not self.lp_url:
                return {"status": "failed", "error": "扫码会话未创建（先 start）"}
            if time.time() > self.expire_at:
                return {"status": "expired"}
            try:
                payload = self._poll_once_locked()
            except XiaomiQRLoginError as e:
                return {"status": "failed", "error": str(e)}
            except Exception as e:  # socket.timeout / URLError → 等待中
                _ = e
                return {"status": "waiting"}

            if payload.get("code") != 0:
                # 票据被消费/取消/过期等业务错误
                return {"status": "expired",
                        "error": f"code={payload.get('code')} {payload.get('desc')}"}
            if not payload.get("passToken"):
                return {"status": "waiting"}

            # confirmed → step4-6 换发 cookie
            try:
                cookies, user_id = self._exchange_locked(payload)
            except XiaomiQRLoginError as e:
                return {"status": "failed", "error": str(e)}
            return {
                "status": "confirmed",
                "cookies": cookies,
                "user_id": str(payload.get("userId") or user_id or ""),
            }

    def _poll_once_locked(self) -> dict[str, object]:
        """lp 长轮询单次挂起；socket 超时向上抛由 poll 归类为 waiting。"""
        st, _, body, _ = self._http_get(
            self.lp_url, headers={"Accept": "*/*"},
            timeout=self.poll_socket_timeout_s)
        text = strip_jsonp(body)
        try:
            return json.loads(text)
        except ValueError as e:
            raise XiaomiQRLoginError(f"lp 响应解析失败(HTTP {st}): {e}") from e

    def _set_jar_cookie(self, domain: str, name: str, value: str) -> None:
        self._jar.set_cookie(http.cookiejar.Cookie(
            version=0, name=name, value=value, port=None, port_specified=False,
            domain=domain, domain_specified=True, domain_initial_dot=False,
            path="/", path_specified=True, secure=False, expires=None,
            discard=True, comment=None, comment_url=None, rest={}, rfc2109=False))

    def _exchange_locked(
        self, confirm_payload: dict[str, object],
    ) -> tuple[dict[str, str], str]:
        """step4-6：passToken → serviceLogin(_json) → STS 302 链收集 cookie。"""
        pass_token = str(confirm_payload.get("passToken") or "")
        user_id = str(confirm_payload.get("userId") or "")
        if not pass_token or not user_id:
            raise XiaomiQRLoginError("确认载荷缺少 passToken/userId")

        # 带 passToken + userId 的 jar（serviceLogin 需要）
        self._set_jar_cookie(".account.xiaomi.com", "passToken", pass_token)
        self._set_jar_cookie(".account.xiaomi.com", "userId", user_id)

        # step4: serviceLogin(_json) → 新签 location
        u = (
            f"{SERVICE_LOGIN}?sid={SID}"
            f"&callback={urllib.parse.quote(self._callback, safe='')}"
            "&_group=DEFAULT&_json=true"
        )
        st, _, body, _ = self._http_get(u)
        try:
            data = json.loads(strip_jsonp(body))
        except ValueError as e:
            raise XiaomiQRLoginError(f"serviceLogin 响应解析失败: {e}") from e
        location = str(data.get("location") or "")
        if data.get("code") not in (0, None) or not location:
            raise XiaomiQRLoginError(
                f"serviceLogin 换发失败: code={data.get('code')} {data.get('desc')}")

        # step5: STS 302 链，逐跳收集 Set-Cookie 原始头
        cookies: dict[str, str] = {}
        hop = location
        for _ in range(8):
            st, headers, _, set_cookies = self._http_get(hop)
            cookies.update(parse_set_cookie_pairs(set_cookies))
            nxt = ""
            if st in (301, 302, 303, 307):
                nxt = _header(headers, "Location")
            if not nxt:
                break
            hop = nxt
        # passToken 一并返回落盘（T31.7）：serviceToken 被服务端作废后，
        # 客户端凭它走 serviceLogin 静默重签（浏览器续期语义）
        cookies.setdefault("passToken", pass_token)
        return cookies, user_id

    def cancel(self) -> None:
        """作废本地票据（不做网络取消；票据到期服务端自然失效）。"""
        with self._lock:
            self.lp_url = ""
            self.expire_at = 0.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        return None
