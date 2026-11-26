#!/usr/bin/env python3
"""请求者身份解析与绑定（T30 多用户隔离，路线 A：fnOS 网关身份头直信）。

链路（docs/fnos-gateway-identity-spike.md）：
  浏览器 → :5666 网关(nginx) → trim_http_cgi（校验 fnOS 登录态，注入
  X-Trim-Userid / X-Trim-Username / X-Trim-Isadmin）→ app.sock → 本服务。

信任模型：
- 经网关（携带身份头）：身份头即权威身份，owner 过滤按 user_id 生效
- socket 直连 / 裸 socket（无身份头，0.3.36 起服务无 TCP 端口）：本机 admin 信任
  （与 fnOS 应用生态一致，socket 仅 NAS 本机可达）
- daemon / 调度器等后台路径：SYSTEM_REQUESTOR（等价 admin，全可见）

防伪造：身份头由网关 CGI 注入；CGI 是否剥离外部同名头经 /api/debug/headers
动态确认（部署后 T30.6 验证）。
"""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_VALUE_MAX = 128  # 与 validate_account 的 owner 限长一致


@dataclass(frozen=True)
class Requestor:
    """单个 HTTP 请求（或后台路径）的身份。"""

    user_id: str        # fnOS 用户 id（X-Trim-Userid）；"" = 本机/系统
    username: str       # 展示名（X-Trim-Username）
    is_admin: bool      # X-Trim-Isadmin 归一化
    via_gateway: bool   # 是否携带网关身份头（False = 直连/系统路径）

    @property
    def sees_all(self) -> bool:
        """admin/系统身份可见全部账号。"""
        return self.is_admin or not self.via_gateway


# daemon / 调度器等非 HTTP 路径的系统身份（等价 admin，全可见）
SYSTEM_REQUESTOR = Requestor("", "system", True, False)

_current: ContextVar[Requestor] = ContextVar(
    "albumsync_requestor", default=SYSTEM_REQUESTOR
)


def current_requestor() -> Requestor:
    """当前线程绑定的请求者身份（未绑定时 = 系统身份）。"""
    return _current.get()


def bind_requestor(r: Requestor) -> object:
    """绑定当前线程的请求者身份（返回 token 供 reset）。"""
    return _current.set(r)


def parse_requestor(headers) -> Requestor:
    """从 HTTP 请求头解析身份；无身份头 = 直连 = 本机 admin 信任。

    headers 为 email.message.Message（BaseHTTPRequestHandler.headers），
    .get 键名不区分大小写。
    """
    uid = str(headers.get("X-Trim-Userid") or "").strip()
    if not uid:
        return SYSTEM_REQUESTOR
    username = str(headers.get("X-Trim-Username") or "").strip()
    raw_admin = str(headers.get("X-Trim-Isadmin") or "").strip().lower()
    return Requestor(
        uid[:_VALUE_MAX],
        username[:_VALUE_MAX],
        raw_admin in _TRUTHY,
        True,
    )
