#!/usr/bin/env python3
"""华为云空间 Provider（T25.3）：现有引擎实现的 Provider/AuthStrategy 包装层。

设计：**包装而非重写**。sync.py/daemon.py 的调用面（10 个方法）原样委托给
vendored HuaweiGalleryClient；登录策略委托 AuthManager（凭据存储）+
HuaweiCasAuthenticator（CAS 账密两段式登录）。vendor 引擎零改动。

华为特定语义集中在本模块（从通用层下沉，auth.py L206/L209 对应）：
- cURL 导入提示：需复制 cloud.huawei.com 域下已登录请求（/album/getSimpleFile
  或 /heartbeatCheck）
- CSRF 规则：CSRFToken 请求头或 shareToken cookie 二者取其一，均缺失则导入失败
  （解析细节在 vendor auth.py 解析器内，本策略持有语义常量并对外暴露）
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Callable, Iterator

from hwcloudpd.auth import AuthManager
from hwcloudpd.cas_auth import HuaweiCasAuthenticator
from hwcloudpd.client import DownloadResult, HuaweiGalleryClient
from hwcloudpd.models import (
    AlbumInfo,
    AuthExpiredError,
    MediaItem,
    MediaStub,
)
from providers.base import BaseAuthStrategy, ProviderCapabilities

logger = logging.getLogger("albumsync.providers.huawei")


class HuaweiProvider:
    """PhotoProvider 实现：薄委托 HuaweiGalleryClient。

    account_id 仅用于日志标识；引擎调用面与 HuaweiGalleryClient 完全一致。
    """

    def __init__(self, auth_manager: AuthManager, account_id: str = "") -> None:
        self.auth_manager = auth_manager
        self.account_id = account_id or "huawei"
        self._client = HuaweiGalleryClient(auth_manager)
        self._maybe_attach_observer()

    def _maybe_attach_observer(self) -> None:
        """T28.7：ALBUMSYNC_HTTP_OBSERVER=1 时挂响应观察器（默认关闭）。

        每个 API 响应打一行 debug 日志（path/status/Set-Cookie 数量），用于
        接入新厂商时的交互录制与凭据轮替排查。见 docs/multi-account-multi-
        platform-architecture.md「5.2.2 响应观察器」。
        """
        if os.environ.get("ALBUMSYNC_HTTP_OBSERVER", "").strip() not in ("1", "true", "yes"):
            return
        account = self.account_id

        def observe(info: dict[str, Any]) -> None:
            cookies = info.get("set_cookies") or {}
            logger.debug(
                "[observer:%s] %s %s set_cookies=%s",
                account, info.get("status"), info.get("path"), sorted(cookies),
            )

        self._client.response_observer = observe
        logger.info("huawei response observer attached (ALBUMSYNC_HTTP_OBSERVER), account=%s", account)

    # -- 引擎调用面（10 方法，原样委托） --

    def heartbeat_check(self) -> bool:
        return self._client.heartbeat_check()

    def get_gallery_stats(self) -> dict[str, int]:
        return self._client.get_gallery_stats()

    def list_albums(self, *, include_stats: bool = False) -> list[AlbumInfo]:
        return self._client.list_albums(include_stats=include_stats)

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
        return self._client.iter_simple_files(
            album_id,
            album_name=album_name,
            album_version=album_version,
            owner_id=owner_id,
            query_type=query_type,
            page_size=page_size,
            request_delay_ms=request_delay_ms,
        )

    def get_burst_files(
        self,
        album_id: str,
        unique_id: str,
        *,
        album_name: str = "",
        album_version: str = "",
        owner_id: str | None = None,
    ) -> list[MediaStub]:
        return self._client.get_burst_files(
            album_id,
            unique_id,
            album_name=album_name,
            album_version=album_version,
            owner_id=owner_id,
        )

    def enrich_metadata(self, stubs: list[MediaStub]) -> list[MediaItem]:
        return self._client.enrich_metadata(stubs)

    def pre_process(self) -> None:
        self._client.pre_process()

    def get_download_url(self, item: MediaItem, size_variant: str = "original") -> str:
        return self._client.get_download_url(item, size_variant)

    def download_to_part(self, url: str, part_path: Path) -> DownloadResult:
        return self._client.download_to_part(url, part_path)

    def delete_cloud_files(self, items: list[MediaItem]) -> int:
        return self._client.delete_cloud_files(items)


class HuaweiAuthStrategy(BaseAuthStrategy):
    """AuthStrategy 实现：CAS 账密两段式登录 + cURL 会话导入。"""

    PLATFORM = "huawei"
    # 华为特定语义常量（见模块 docstring；vendor 解析器内为实现侧）
    CLOUD_DOMAIN_HINT = "cloud.huawei.com"
    CURL_HINT = (
        "请复制 cloud.huawei.com 域下已登录请求（如 /album/getSimpleFile 或 "
        "/heartbeatCheck）为 cURL (bash) 格式"
    )
    # -- 平台元数据（BaseAuthStrategy 约定，通用层直接读取） --
    platform_label = "华为云空间"
    credentials_hint = "请先在「同步设置」中填写华为账号与密码"
    login_success_hint = "登录成功（信任设备生效后，会话过期将静默自动重登）"
    auth_recovery_hint = (
        "若已配置 HUAWEI_USERNAME/HUAWEI_PASSWORD 请执行 "
        "`docker exec -it hwcloudpd hwcloudpd --auth-only` 输入二次验证码；"
        "或从浏览器 Copy as cURL 覆盖写入 config/curl.txt，容器将自动热恢复。"
    )

    def __init__(
        self,
        auth_manager: AuthManager,
        account: dict[str, Any] | None = None,
        *,
        client: HuaweiGalleryClient | None = None,
    ) -> None:
        account = account or {}
        self.auth_manager = auth_manager
        self.account_id = str(account.get("id") or "")
        self._username = (str(account.get("username") or "").strip() or None)
        self._password = (str(account.get("password") or "") or None)
        self._client = client  # 可选：登录成功后 heartbeat 校验用

    # -- 认证器构造 --

    def build_authenticator(self, two_fa_code: str | None = None) -> HuaweiCasAuthenticator:
        return HuaweiCasAuthenticator(
            self.auth_manager,
            username=self._username,
            password=self._password,
            two_fa_code=two_fa_code,
            login_timeout_sec=30,
        )

    # -- AuthStrategy 协议 --

    def ensure_session(self) -> Any:
        return self.auth_manager.ensure_session()

    def get_session_if_present(self) -> Any:
        return self.auth_manager.get_session_if_present()

    def has_credentials(self) -> bool:
        return self.build_authenticator().has_credentials

    def web_login(self, *, prompt_fn: Any = None, output_fn: Any = None,
                  interactive: bool = False) -> Any:
        """账号密码登录（网页触发）。触发 2FA 时抛 TwoFactorRequiredError。

        凭据缺失抛 AuthExpiredError（与 vendor 异常族一致，调用方统一捕获）。
        """
        authenticator = self.build_authenticator()
        if not authenticator.has_credentials:
            raise AuthExpiredError("请先在「同步设置」中填写华为账号与密码")
        return authenticator.login(
            interactive=False,
            prompt_fn=prompt_fn or (lambda _p: ""),
            output_fn=output_fn or (lambda _s: None),
        )

    def submit_challenge(self, code: str, *, prompt_fn: Any = None,
                         output_fn: Any = None) -> Any:
        """提交 6 位验证码，恢复 pending 2FA 流程。"""
        code = str(code or "").strip()
        authenticator = self.build_authenticator(two_fa_code=code)
        return authenticator.login(
            interactive=False,
            prompt_fn=prompt_fn or (lambda _p: ""),
            output_fn=output_fn or (lambda _s: None),
        )

    def pending_challenge(self) -> dict[str, Any] | None:
        try:
            return self.build_authenticator()._load_pending_2fa()
        except Exception as exc:
            logger.warning("load pending 2fa failed: %s", exc)
            return None

    def auth_probe(self) -> dict[str, Any]:
        """华为认证探针：auth_status 用（CAS TGT/凭据/待验证状态）。"""
        try:
            authenticator = self.build_authenticator()
            pending = authenticator._load_pending_2fa()
            has_tgt = authenticator._has_cas_tgt()
            credentials = authenticator.has_credentials
        except Exception as exc:
            logger.warning("authenticator probe failed: %s", exc)
            pending, has_tgt, credentials = None, False, False
        return {
            "pending_2fa": pending,
            "has_cas_tgt": has_tgt,
            "credentials_configured": credentials,
        }

    def session_info(self, session: Any) -> dict[str, Any]:
        """华为会话字段提取：user_id + loginSecLevel（CAS 语义）。"""
        user_id = str(getattr(session, "user_id", "") or "")
        login_sec_level = None
        cookies = getattr(session, "cookies", None)
        if isinstance(cookies, dict):
            login_sec_level = cookies.get("loginSecLevel")
        if not user_id:
            # CAS cookiejar 内兜底找 userId cookie
            jar = getattr(session, "cookiejar", None)
            if jar is not None and hasattr(jar, "__iter__"):
                for c in jar:
                    if getattr(c, "name", "") == "userId":
                        user_id = str(c.value or "")
                        break
        return {
            "user_id": user_id,
            "login_sec_level": login_sec_level,
            "session_updated_at": getattr(session, "updated_at", None),
        }

    def import_session(self, curl_text: str) -> Any:
        return self.auth_manager.import_curl_text(curl_text)

    def is_valid(self) -> bool:
        try:
            return self.auth_manager.get_session_if_present() is not None
        except Exception:
            return False

    def invalidate(self) -> None:
        """清除本地会话（auth.json）；curl.txt 保留可重导入。"""
        auth_file = self.auth_manager.auth_file
        try:
            Path(auth_file).unlink(missing_ok=True)
            logger.info("account %s auth session invalidated", self.account_id)
        except Exception as exc:
            logger.warning("invalidate auth session failed: %s", exc)


# 能力声明：华为全量能力
HUAWEI_CAPABILITIES = ProviderCapabilities(
    platform="huawei",
    display_name="华为云空间",
)


def make_huawei_provider(auth_manager: AuthManager, account: dict[str, Any] | None = None) -> HuaweiProvider:
    account = account or {}
    return HuaweiProvider(auth_manager, account_id=str(account.get("id") or ""))


def make_huawei_auth_strategy(auth_manager: AuthManager, account: dict[str, Any] | None = None) -> HuaweiAuthStrategy:
    return HuaweiAuthStrategy(auth_manager, account)
