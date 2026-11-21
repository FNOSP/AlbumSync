#!/usr/bin/env python3
"""iCloud 云相册 Provider：可信会话、2FA/2SA 与个人图库只读同步。"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Iterator

from hwcloudpd.client import DownloadResult
from hwcloudpd.models import (
    AlbumInfo,
    AuthExpiredError,
    MediaItem,
    MediaStub,
    TwoFactorRequiredError,
)
from providers.base import BaseAuthStrategy, ProviderCapabilities
from providers.icloud.icloud_client import PENDING_TTL_SEC, ICloudClient

logger = logging.getLogger("albumsync.providers.icloud")


class ICloudSessionStore:
    """账号级 iCloud session/cookie 文件存储，所有写入均为 0600 原子替换。"""

    def __init__(self, auth_file: str | Path, cookie_file: str | Path) -> None:
        self.auth_file = Path(auth_file)
        self.cookie_file = Path(cookie_file)
        self.pending_file = self.auth_file.with_name(
            f"{self.auth_file.stem.replace('_session', '')}_pending.json"
        )

    def save(self, session_data: dict[str, Any]) -> None:
        self.auth_file.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(session_data, ensure_ascii=False, indent=2)
        try:
            if self.auth_file.read_text(encoding="utf-8") == payload:
                return  # 内容未变不落盘，避免 mtime 变化触发其他实例重建/重复认证。
        except OSError:
            pass
        tmp = self.auth_file.with_suffix(self.auth_file.suffix + ".tmp")
        tmp.write_text(payload, encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.auth_file)

    def save_cookies(self, cookies: Any) -> None:
        self.cookie_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.cookie_file.with_suffix(self.cookie_file.suffix + ".tmp")
        cookies.save(str(tmp), ignore_discard=True, ignore_expires=True)
        os.chmod(tmp, 0o600)
        try:
            if self.cookie_file.read_bytes() == tmp.read_bytes():
                tmp.unlink(missing_ok=True)
                return
        except OSError:
            pass
        tmp.replace(self.cookie_file)

    def load(self) -> dict[str, Any] | None:
        if not self.auth_file.is_file():
            return None
        try:
            data = json.loads(self.auth_file.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("icloud session load failed: %s", exc)
            return None

    def has_session(self, *, apple_id: str = "", domain: str = "") -> bool:
        data = self.load()
        if not data or not str(data.get("session_token") or "").strip():
            return False
        stored_id = str(data.get("apple_id") or "").strip().lower()
        stored_domain = str(data.get("domain") or "").strip().lower()
        if apple_id and stored_id and stored_id != apple_id.strip().lower():
            return False
        if domain and stored_domain and stored_domain != domain.strip().lower():
            return False
        return True

    def save_pending(self, data: dict[str, Any]) -> None:
        """落盘二次验证暂停标记，让 daemon 等并发实例知道有交互式验证在进行。"""
        self.pending_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.pending_file.with_suffix(self.pending_file.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.pending_file)

    def load_pending(self, ttl: float = PENDING_TTL_SEC) -> dict[str, Any] | None:
        if not self.pending_file.is_file():
            return None
        try:
            data = json.loads(self.pending_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("icloud pending challenge load failed: %s", exc)
            return None
        if not isinstance(data, dict):
            return None
        try:
            created_at = float(data.get("created_at") or 0.0)
        except (TypeError, ValueError):
            created_at = 0.0
        if created_at <= 0 or time.time() - created_at > ttl:
            self.clear_pending()
            return None
        return data

    def clear_pending(self) -> None:
        for path in (self.pending_file, self.pending_file.with_suffix(self.pending_file.suffix + ".tmp")):
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:
                logger.warning("icloud pending challenge clear failed: %s", exc)

    def clear(self) -> None:
        self.clear_pending()
        for path in (
            self.auth_file,
            self.cookie_file,
            self.auth_file.with_suffix(self.auth_file.suffix + ".tmp"),
            self.cookie_file.with_suffix(self.cookie_file.suffix + ".tmp"),
        ):
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:
                logger.warning("icloud session clear failed: %s", exc)


class ICloudAuthenticator:
    """daemon 非交互重登入口；需要验证码时明确抛出 TwoFactorRequiredError。"""

    def __init__(self, strategy: ICloudAuthStrategy, two_fa_code: str | None = None) -> None:
        self.strategy = strategy
        self.two_fa_code = two_fa_code

    @property
    def has_credentials(self) -> bool:
        return self.strategy.has_credentials()

    @property
    def can_attempt_login(self) -> bool:
        # 网页端二次验证进行中时禁止 daemon 另行登录，否则会刷新 Apple 挑战使验证码失效。
        if self.strategy.store.load_pending():
            return False
        client = self.strategy._client
        if client is not None and getattr(client, "auth_backoff_active", lambda: False)():
            return False
        return self.has_credentials or self.strategy.store.has_session(
            apple_id=self.strategy._username or "",
            domain=self.strategy.domain,
        )

    def login(self, *, interactive: bool = False, prompt_fn: Any = None, output_fn: Any = None) -> ICloudClient:
        del prompt_fn, output_fn
        if self.two_fa_code:
            return self.strategy.submit_challenge(self.two_fa_code)
        return self.strategy.web_login(interactive=interactive)


class ICloudAuthStrategy(BaseAuthStrategy):
    PLATFORM = "icloud"
    platform_label = "iCloud 云相册"
    credentials_hint = "请先在「同步设置」中填写 Apple ID、密码和账号区域"
    login_success_hint = "登录成功（受信任会话将在过期后自动尝试恢复）"
    auth_recovery_hint = "请在「认证与安全」完成 Apple 双重/两步验证；受信任会话恢复后将自动继续同步"

    def __init__(
        self,
        auth_manager: Any,
        account: dict[str, Any] | None = None,
        *,
        session_file: str | None = None,
        cookie_file: str | None = None,
    ) -> None:
        account = account or {}
        self.account_id = str(account.get("id") or "")
        self._username = str(account.get("username") or "").strip() or None
        self._password = str(account.get("password") or "") or None
        self.domain = str(account.get("domain") or "com").strip().lower()
        if self.domain not in ("com", "cn"):
            raise ValueError("iCloud 账号区域仅支持 com（国际区）或 cn（中国区）")
        try:
            config_dir = Path(getattr(auth_manager, "auth_file", Path.cwd())).parent
        except Exception:
            config_dir = Path.cwd()
        suffix = self.account_id or "default"
        session_file = session_file or str(config_dir / f"icloud_{suffix}_session.json")
        cookie_file = cookie_file or str(config_dir / f"icloud_{suffix}_cookies.lwp")
        self.store = ICloudSessionStore(session_file, cookie_file)
        self._client: ICloudClient | None = None
        self._client_file_signature: tuple[tuple[int, int], ...] = ()

    @staticmethod
    def _file_signature(path: Path) -> tuple[int, int]:
        try:
            stat = path.stat()
            return stat.st_mtime_ns, stat.st_size
        except OSError:
            return 0, 0

    def _files_signature(self) -> tuple[tuple[int, int], ...]:
        return (
            self._file_signature(self.store.auth_file),
            self._file_signature(self.store.cookie_file),
        )

    def _on_session_update(self) -> None:
        self._client_file_signature = self._files_signature()

    def _client_or_raise(self) -> ICloudClient:
        signature = self._files_signature()
        if self._client is not None and self._client.pending_challenge() is not None:
            # 二次验证等待期间保留当前 client（提交验证码必须沿用同一 Apple 挑战）。
            return self._client
        if self._client is not None and signature != self._client_file_signature:
            logger.info("icloud session files changed on disk, rebuilding client")
            self._client.invalidate()
            self._client = None
        if self._client is None:
            self._client = ICloudClient(
                apple_id=self._username or "",
                password=self._password,
                domain=self.domain,
                session_path=self.store.auth_file,
                cookiejar_path=self.store.cookie_file,
                store=self.store,
                on_session_update=self._on_session_update,
            )
            self._client_file_signature = signature
        return self._client

    def ensure_session(self, *, probe: bool = False) -> ICloudClient:
        client = self._client_or_raise()
        if not self.store.has_session(apple_id=self._username or "", domain=self.domain):
            if not self.has_credentials():
                raise AuthExpiredError(self.credentials_hint)
        client.ensure_service()
        if probe:
            client.heartbeat()
        return client

    def get_session_if_present(self) -> ICloudClient | None:
        if not self.store.has_session(apple_id=self._username or "", domain=self.domain):
            return None
        return self._client_or_raise()

    def has_credentials(self) -> bool:
        return bool(self._username and self._password)

    def web_login(self, *, prompt_fn: Any = None, output_fn: Any = None, interactive: bool = False) -> ICloudClient:
        del prompt_fn, output_fn
        if not self.has_credentials() and not self.store.has_session(
            apple_id=self._username or "", domain=self.domain
        ):
            raise AuthExpiredError(self.credentials_hint)
        return self._client_or_raise().login(interactive=interactive)

    def submit_challenge(self, code: str, *, prompt_fn: Any = None, output_fn: Any = None) -> ICloudClient:
        del prompt_fn, output_fn
        code = str(code or "").strip()
        if not code.isdigit() or len(code) != 6:
            raise TwoFactorRequiredError("iCloud 验证码须为 6 位数字")
        if self._client is None:
            raise AuthExpiredError("二次验证流程已失效，请重新登录")
        return self._client.submit_challenge(code)

    def pending_challenge(self) -> dict[str, Any] | None:
        return self._client.pending_challenge() if self._client is not None else None

    def auth_probe(self) -> dict[str, Any]:
        return {
            "pending_2fa": self.pending_challenge(),
            "has_cas_tgt": False,
            "credentials_configured": self.has_credentials(),
        }

    def session_info(self, session: Any) -> dict[str, Any]:
        return {
            "user_id": str(getattr(session, "apple_id", "") or self._username or ""),
            "login_sec_level": None,
            "session_updated_at": getattr(session, "updated_at", None),
        }

    def import_session(self, curl_text: str) -> Any:
        del curl_text
        raise AuthExpiredError("iCloud 不支持 cURL 导入，请使用 Apple ID 和密码登录")

    def is_valid(self) -> bool:
        return self.store.has_session(apple_id=self._username or "", domain=self.domain)

    def invalidate(self) -> None:
        if self._client is not None:
            self._client.invalidate()
        self._client = None
        self.store.clear()
        self._client_file_signature = self._files_signature()
        logger.info("icloud session invalidated, account_id=%s", self.account_id)

    def build_authenticator(self, two_fa_code: str | None = None) -> ICloudAuthenticator:
        return ICloudAuthenticator(self, two_fa_code)


class ICloudProvider:
    """PhotoProvider 实现：上游 PhotoAsset 到通用媒体模型的薄转换。"""

    def __init__(self, auth_manager: Any, account: dict[str, Any] | None = None) -> None:
        self.auth_strategy = ICloudAuthStrategy(auth_manager, account)
        self.account_id = self.auth_strategy.account_id or "icloud"

    def _client(self) -> ICloudClient:
        return self.auth_strategy.ensure_session()

    def heartbeat_check(self) -> bool:
        client = self.auth_strategy.get_session_if_present()
        if client is None:
            raise AuthExpiredError("iCloud 会话不存在或已失效")
        return client.heartbeat()

    def get_gallery_stats(self) -> dict[str, int]:
        return {"total": 0, "albums": len(self.list_albums())}

    def list_albums(self, *, include_stats: bool = False) -> list[AlbumInfo]:
        del include_stats  # 不为了计数遍历图库或调用逐相册 count。
        result = []
        for entry in self._client().list_albums():
            result.append(AlbumInfo(
                album_id=str(entry["id"]),
                name=str(entry["name"]),
                album_version="",
                owner_id=None,
                img_num=0,
                video_num=0,
                hide=1 if entry["name"] == "Hidden" else 0,
                is_virtual=bool(entry.get("is_virtual")),
                is_recycle=bool(entry.get("is_recycle")),
            ))
        return result

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
        del query_type
        client = self._client()
        page: list[MediaStub] = []
        size = max(1, int(page_size or 100))
        for asset in client.iter_assets(album_id, page_size=size):
            page.append(self._asset_to_stub(
                asset,
                album_id=album_id,
                album_name=album_name,
                album_version=album_version,
                owner_id=owner_id,
                client=client,
            ))
            if len(page) >= size:
                yield page
                page = []
                if request_delay_ms > 0:
                    time.sleep(request_delay_ms / 1000.0)
        if page:
            yield page

    def get_burst_files(
        self,
        album_id: str,
        unique_id: str,
        *,
        album_name: str = "",
        album_version: str = "",
        owner_id: str | None = None,
    ) -> list[MediaStub]:
        del album_id, unique_id, album_name, album_version, owner_id
        return []

    def enrich_metadata(self, stubs: list[MediaStub]) -> list[MediaItem]:
        return [
            MediaItem(
                unique_id=stub.unique_id,
                album_id=stub.album_id,
                album_name=stub.album_name,
                file_type=stub.file_type,
                create_time_ms=stub.create_time_ms,
                is_cover=stub.is_cover,
                is_fav=stub.is_fav,
                uid=stub.uid,
                file_name=stub.file_name,
                file_size=int(getattr(stub, "_size", 0) or 0),
                checksum="",
                album_version=stub.album_version,
                owner_id=stub.owner_id,
                expand=dict(getattr(stub, "_expand", {}) or {}),
            )
            for stub in stubs
        ]

    def pre_process(self) -> None:
        return None

    def get_download_url(self, item: MediaItem, size_variant: str = "original") -> str:
        expand = item.expand or {}
        return self._client().get_download_url(
            item.unique_id,
            album_id=str(expand.get("icloud_source_album_id") or "") or None,
            size_variant=size_variant,
            versions=expand.get("icloud_versions"),
        )

    def download_to_part(self, url: str, part_path: Path) -> DownloadResult:
        return self._client().download_to_file(url, part_path, resume=True)

    def delete_cloud_files(self, items: list[MediaItem]) -> int:
        logger.info("icloud 为只读平台，跳过 %d 个云删除请求", len(items))
        return 0

    @staticmethod
    def _asset_to_stub(
        asset: Any,
        *,
        album_id: str | None,
        album_name: str,
        album_version: str,
        owner_id: str | None,
        client: ICloudClient,
    ) -> MediaStub:
        asset_id = str(asset.id)
        filename = str(asset.filename)
        item_type = getattr(asset, "item_type", None)
        item_type_value = str(getattr(item_type, "value", item_type) or "").lower()
        extension = Path(filename).suffix.lower()
        if item_type_value == "movie":
            file_type = "4"
        elif extension in (".heic", ".heif"):
            file_type = "9"
        else:
            file_type = "1"
        try:
            create_time_ms = int(asset.asset_date.timestamp() * 1000)
        except (AttributeError, TypeError, ValueError, OSError):
            create_time_ms = 0
        versions = client._serialize_versions(asset)
        try:
            file_size = int(asset.size or 0)
        except (AttributeError, KeyError, TypeError, ValueError):
            file_size = int((versions.get("original") or {}).get("size") or 0)
        fields = getattr(asset, "_asset_record", {}).get("fields", {})
        is_fav = 1 if (fields.get("isFavorite") or {}).get("value") else 0
        stub = MediaStub(
            unique_id=asset_id,
            album_id=str(album_id or "0"),
            album_name=album_name or "全部照片",
            file_type=file_type,
            create_time_ms=create_time_ms,
            is_cover=0,
            is_fav=is_fav,
            uid="",
            file_name=filename,
            album_version=album_version,
            owner_id=owner_id,
            recycle_time="",
        )
        stub._size = file_size
        stub._expand = {
            "icloud_source_album_id": album_id or "",
            "icloud_versions": versions,
        }
        return stub


ICLOUD_CAPABILITIES = ProviderCapabilities(
    platform="icloud",
    display_name="iCloud 云相册",
    supports_web_login_2fa=True,
    supports_curl_import=False,
    supports_qr_login=False,
    supports_delete=False,
    supports_burst_expansion=False,
    supports_metadata_enrich=True,
    supports_favorites_filter=False,
    supports_live_photo_mov=False,
    supports_gallery_stats=True,
)


def make_icloud_provider(auth_manager: Any, account: dict[str, Any] | None = None) -> ICloudProvider:
    return ICloudProvider(auth_manager, account)


def make_icloud_auth_strategy(auth_manager: Any, account: dict[str, Any] | None = None) -> ICloudAuthStrategy:
    return ICloudAuthStrategy(auth_manager, account)


__all__ = [
    "ICloudProvider",
    "ICloudAuthStrategy",
    "ICloudAuthenticator",
    "ICloudSessionStore",
    "ICloudClient",
    "ICLOUD_CAPABILITIES",
    "make_icloud_provider",
    "make_icloud_auth_strategy",
]
