#!/usr/bin/env python3
"""Provider 抽象层（T25）：多平台相册云接入的接口协议与能力声明。

三个核心抽象（docs/multi-account-multi-platform-architecture.md §5）：
- PhotoProvider        相册云平台能力面（sync.py/daemon.py 引擎实际调用的 10 个方法）
- AuthStrategy         登录/会话策略（两段式 2FA、cURL 导入、有效性检查）
- ProviderCapabilities 平台能力声明（引擎与 UI 据此降级，如不支持云删除则强制关 auto_delete）

平台实现：
- providers/huawei/  华为云空间（包装 hwcloudpd.client.HuaweiGalleryClient、
  hwcloudpd.auth.AuthManager、hwcloudpd.cas_auth.HuaweiCasAuthenticator，
  vendor 引擎零改动）
- 平台注册表 PLATFORMS 见 providers/__init__.py

约束：本包不反向依赖 app_runtime/scheduler（保持单向：runtime → providers → hwcloudpd）。
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol, runtime_checkable

from hwcloudpd.auth import AuthManager
from hwcloudpd.client import DownloadResult
from hwcloudpd.models import AlbumInfo, AuthExpiredError, MediaItem, MediaStub


# ---------------------------------------------------------------------------
# T25.1 PhotoProvider：引擎调用面
# ---------------------------------------------------------------------------

@runtime_checkable
class PhotoProvider(Protocol):
    """相册云平台统一接口面 = sync.py/daemon.py 实际调用的全部 client 方法。

    实现类不要求继承本协议（结构化类型）；isinstance 检查可用
    （runtime_checkable 仅验证方法存在性）。华为实现见 providers/huawei。
    """

    def heartbeat_check(self) -> bool:
        """会话有效性探测（daemon 保活用）。"""

    def get_gallery_stats(self) -> dict[str, int]:
        """相册库统计（总数等）。"""

    def list_albums(self, *, include_stats: bool = False) -> list[AlbumInfo]:
        """相册列表（含系统/虚拟相册）。"""

    def iter_simple_files(
        self,
        album_id: str | None,
        *,
        album_name: str = "",
        album_version: str = "",
        owner_id: str | None = None,
        query_type: int | None = None,
        page_size: int = 100,
        request_delay_ms: int = 0,
    ) -> Iterator[list[MediaStub]]:
        """按相册分页拉取文件 stub（yield 页列表）。"""

    def get_burst_files(
        self,
        album_id: str,
        unique_id: str,
        *,
        album_name: str = "",
        album_version: str = "",
        owner_id: str | None = None,
    ) -> list[MediaStub]:
        """展开连拍组（burst stack）为成员列表。"""

    def enrich_metadata(self, stubs: list[MediaStub]) -> list[MediaItem]:
        """stub → 完整元数据（文件名/尺寸/下载句柄等）。"""

    def pre_process(self) -> None:
        """同步前的平台侧准备（如 galleryStatsInfo 预热）。"""

    def get_download_url(self, item: MediaItem, size_variant: str = "original") -> str:
        """取下载直链（original/medium/thumb）。"""

    def download_to_part(self, url: str, part_path: Path) -> DownloadResult:
        """流式下载到 .part 文件。"""

    def delete_cloud_files(self, items: list[MediaItem]) -> int:
        """云删除（auto_delete/keep_cloud_recent_days 用）。"""


# ---------------------------------------------------------------------------
# T25.2 AuthStrategy：登录/会话策略
# ---------------------------------------------------------------------------

@runtime_checkable
class AuthStrategy(Protocol):
    """平台登录/会话策略。

    两段式 Web 登录：web_login() 触发登录与验证码下发，抛
    TwoFactorRequiredError 表示需要二次验证 → UI 收集验证码 →
    submit_challenge(code) 完成登录。
    """

    def ensure_session(self) -> Any:
        """返回有效会话（无效时抛 AuthExpiredError）。"""

    def get_session_if_present(self) -> Any | None:
        """返回当前已持有的会话（不触发网络校验），无则 None。"""

    def web_login(self, *, prompt_fn: Any = None, output_fn: Any = None,
                  interactive: bool = False) -> Any:
        """账号密码登录。2FA 时抛 TwoFactorRequiredError；interactive 表示请求来自网页。"""

    def submit_challenge(self, code: str, *, prompt_fn: Any = None,
                         output_fn: Any = None) -> Any:
        """提交二次验证码，恢复 pending 挑战流程，成功返回会话。"""

    def pending_challenge(self) -> dict[str, Any] | None:
        """待验证挑战信息（flow/channels/created_at），无则 None。"""

    def has_credentials(self) -> bool:
        """是否已配置可用于登录的凭据。"""

    def import_session(self, curl_text: str) -> Any:
        """从 cURL 文本导入登录态（保底通道）。"""

    def is_valid(self) -> bool:
        """当前是否持有会话（不触发网络校验）。"""

    def invalidate(self) -> None:
        """清除本地会话（保留可重导入的 curl.txt）。"""

    def build_authenticator(self, two_fa_code: str | None = None) -> Any:
        """daemon 自动重登认证器（app_runtime._start_daemon 无条件调用）。

        不支持密码自动重登的平台返回 NoAutoRelogin（基类默认）。
        """

    def auth_probe(self) -> dict[str, Any]:
        """认证探针（auth_status 用）：pending_2fa / has_cas_tgt / credentials_configured。

        平台无对应语义时按基类默认返回 false/None。
        """

    def session_info(self, session: Any) -> dict[str, Any]:
        """会话字段归一化（auth_status 用）。

        返回 {"user_id", "login_sec_level", "session_updated_at"}；
        平台特有字段提取逻辑由各策略覆写。
        """


# ---------------------------------------------------------------------------
# BaseAuthStrategy：平台策略公共基类（消灭通用层的鸭子探测）
# ---------------------------------------------------------------------------

class NoAutoRelogin:
    """daemon 自动重登桩：不支持密码自动重登的平台共用（如小米）。

    app_runtime._start_daemon 检查 can_attempt_login，False 时向 daemon
    传 authenticator=None，daemon 仅依赖已导入的会话文件。
    """

    can_attempt_login = False

    def attempt_login(self) -> None:  # pragma: no cover - daemon 永不调用
        raise AuthExpiredError("该平台不支持自动重登，请在「认证与安全」重新导入登录态")


class BaseAuthStrategy:
    """平台登录策略公共基类。

    目的：把平台扩展面从「运行时 hasattr/getattr 鸭子探测」收编为显式
    继承接口，通用层（app_runtime/daemon/backup）可无防御地直接调用；
    平台差异全部下沉到 providers/<platform>/ 策略类覆写。

    子类按需覆写：
    - 平台元数据：platform_label / credentials_hint / login_success_hint /
      auth_recovery_hint / qr_login_hint
    - auth_probe()：平台认证探针（华为 CAS 语义；默认无对应语义 → false）
    - session_info()：平台会话字段提取（默认通用 getattr，适配
      user_id/account_id + updated_at 会话模型）
    - build_authenticator()：默认 NoAutoRelogin（不支持自动重登）
    - start_qr_login()/qr_login_status()：默认不支持扫码
    """

    # 平台显示名（daemon 通知标题用，如「华为云空间」）
    platform_label: str = "云相册"
    # 凭据缺失时 web_login 的引导文案
    credentials_hint: str = "请先在「认证与安全」导入登录态"
    # 登录成功文案
    login_success_hint: str = "登录成功"
    # 会话失效恢复指引（daemon auth_expired 通知用；空 = 通用文案）
    auth_recovery_hint: str = ""
    # 扫码登录指引文案（支持扫码的平台覆写）
    qr_login_hint: str = ""

    def get_session_if_present(self) -> Any | None:
        return None

    def auth_probe(self) -> dict[str, Any]:
        return {
            "pending_2fa": None,
            "has_cas_tgt": False,
            "credentials_configured": self.has_credentials(),
        }

    def session_info(self, session: Any) -> dict[str, Any]:
        """通用会话字段提取：兼容 user_id/account_id 属性 + updated_at。"""
        user_id = str(
            getattr(session, "user_id", "") or getattr(session, "account_id", "") or ""
        )
        return {
            "user_id": user_id,
            "login_sec_level": None,
            "session_updated_at": getattr(session, "updated_at", None),
        }

    def risk_state(self) -> dict[str, Any] | None:
        """平台风控状态（auth_status/UI 用），无风控语义 → None。

        有则返回 {"kind": "rate_limited", "retry_after_ts": <epoch>}——
        UI 据此渲染「限流中 + 倒计时，届时再扫码登录」提醒（T31.10）。
        """
        return None

    def build_authenticator(self, two_fa_code: str | None = None) -> Any:
        return NoAutoRelogin()

    def start_qr_login(self) -> dict[str, Any]:
        return {"status": "error", "message": "该平台不支持扫码登录"}

    def qr_login_status(self) -> dict[str, Any]:
        return {"status": "failed", "error": "该平台不支持扫码登录"}


# ---------------------------------------------------------------------------
# ProviderCapabilities：能力声明
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProviderCapabilities:
    """平台能力声明。引擎在构造 SyncConfig 后按此降级（app_runtime._apply_capabilities）。

    所有字段默认 True（华为全量能力）；新平台按需置 False，
    对应的用户配置项会在运行时被强制钳制并记录日志。
    """

    platform: str = ""
    display_name: str = ""

    supports_web_login_2fa: bool = True     # 账密登录 + 两段式验证码
    supports_curl_import: bool = True       # cURL 会话导入
    supports_qr_login: bool = True          # 扫码登录（小米 T31；不支持的平台 UI 隐藏扫码入口）
    supports_delete: bool = True            # 云删除（钳制 auto_delete/keep_cloud_recent_days）
    supports_burst_expansion: bool = True   # 连拍展开（钳制 skip_bursts 语义）
    supports_metadata_enrich: bool = True   # 元数据补全
    supports_favorites_filter: bool = True  # 仅收藏过滤（钳制 only_favorites）
    supports_live_photo_mov: bool = True    # 实况图 MOV 伴随下载（钳制 live_photo_mov_filename_policy）
    supports_gallery_stats: bool = True     # 相册库统计

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "display_name": self.display_name,
            "supports_web_login_2fa": self.supports_web_login_2fa,
            "supports_curl_import": self.supports_curl_import,
            "supports_qr_login": self.supports_qr_login,
            "supports_delete": self.supports_delete,
            "supports_burst_expansion": self.supports_burst_expansion,
            "supports_metadata_enrich": self.supports_metadata_enrich,
            "supports_favorites_filter": self.supports_favorites_filter,
            "supports_live_photo_mov": self.supports_live_photo_mov,
            "supports_gallery_stats": self.supports_gallery_stats,
        }


# 工厂类型别名（平台注册表用）
ProviderFactory = Callable[[AuthManager], PhotoProvider]
AuthStrategyFactory = Callable[[AuthManager, dict[str, Any]], Any]
