#!/usr/bin/env python3
"""iCloud 协议适配：认证、个人图库访问和只读 CDN 断点续传。"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
import time
from email.message import Message
from pathlib import Path
from typing import Any, Callable, Iterator
from uuid import uuid4

# 第三方实现只随本平台包发布，不污染其他 provider 的依赖来源。
_VENDOR_DIR = Path(__file__).resolve().parent / "vendor"
if str(_VENDOR_DIR) not in sys.path:
    sys.path.insert(0, str(_VENDOR_DIR))

import requests  # noqa: E402
from pyicloud_ipd import PyiCloudService  # noqa: E402
from pyicloud_ipd.exceptions import (  # noqa: E402
    PyiCloud2SARequiredException,
    PyiCloudAPIResponseException,
    PyiCloudConnectionErrorException,
    PyiCloudConnectionException,
    PyiCloudException,
    PyiCloudFailedLoginException,
    PyiCloudFailedMFAException,
    PyiCloudServiceUnavailableException,
)
from pyicloud_ipd.version_size import AssetVersionSize  # noqa: E402

from hwcloudpd.client import DownloadResult  # noqa: E402
from hwcloudpd.models import (  # noqa: E402
    AuthExpiredError,
    HwCloudError,
    InvalidCredentialsError,
    TwoFactorRequiredError,
)

logger = logging.getLogger("albumsync.providers.icloud.client")

_SIZE_KEYS = {
    "original": AssetVersionSize.ORIGINAL,
    "medium": AssetVersionSize.MEDIUM,
    "thumb": AssetVersionSize.THUMB,
}
_CONTENT_RANGE_RE = re.compile(r"^bytes\s+(\d+)-(\d+)/(\d+|\*)$", re.IGNORECASE)
_AUTH_ERROR_CODES = {"401", "421", "450", "AUTHENTICATION_FAILED"}
# 二次验证等待窗口：期间其他实例（尤其 daemon）不得重复发起 Apple 登录，
# 否则会反复刷新挑战/推送，用户看到的验证码可能立即失效。
PENDING_TTL_SEC = 600.0
_SRP_FIELDS = {"salt", "b", "c", "iteration", "protocol"}
# 认证失败后的自动重试退避：避免 daemon 高频重登持续喂给 Apple 风控。
_AUTH_RETRY_BACKOFF_SEC = 120.0


class AlbumSyncPyiCloudService(PyiCloudService):
    """把上游会话文件固定到 AlbumSync 的账号目录。"""

    def __init__(self, *args: Any, session_path: str, cookiejar_path: str, **kwargs: Any) -> None:
        self._albumsync_session_path = session_path
        self._albumsync_cookiejar_path = cookiejar_path
        super().__init__(*args, **kwargs)

    @property
    def session_path(self) -> str:
        return self._albumsync_session_path

    @property
    def cookiejar_path(self) -> str:
        return self._albumsync_cookiejar_path


class _CdnAuthorizationError(Exception):
    pass


class _RangeNotSatisfiable(Exception):
    pass


class _RestartFullDownload(Exception):
    pass


class ICloudClient:
    """懒构造 PyiCloudService，向 Provider 暴露安全的领域操作。"""

    def __init__(
        self,
        *,
        apple_id: str,
        password: str | None,
        domain: str,
        session_path: str | Path,
        cookiejar_path: str | Path,
        store: Any,
        on_session_update: Callable[[], None] | None = None,
        service_factory: Callable[..., Any] | None = None,
        download_session_factory: Callable[[], requests.Session] = requests.Session,
        http_timeout: float = 30.0,
    ) -> None:
        self.apple_id = apple_id
        self.user_id = apple_id
        self.domain = domain
        self._password = password
        self.session_path = Path(session_path)
        self.cookiejar_path = Path(cookiejar_path)
        self.store = store
        self._on_session_update = on_session_update
        self._service_factory = service_factory or AlbumSyncPyiCloudService
        self._download_session_factory = download_session_factory
        self.http_timeout = http_timeout
        self._service: Any | None = None
        self._pending: dict[str, Any] | None = None
        self._assets: dict[str, Any] = {}
        self._auth_retry_after = 0.0

    @property
    def updated_at(self) -> float | None:
        try:
            return self.session_path.stat().st_mtime
        except OSError:
            return None

    def _notify_session_update(self) -> None:
        if self._on_session_update is not None:
            self._on_session_update()

    def _translate(self, exc: Exception) -> Exception:
        if isinstance(exc, (AuthExpiredError, InvalidCredentialsError, HwCloudError)):
            return exc
        if isinstance(exc, PyiCloudFailedMFAException):
            return TwoFactorRequiredError("iCloud 二次验证码校验失败，请重试")
        if isinstance(exc, PyiCloud2SARequiredException):
            return TwoFactorRequiredError("iCloud 需要两步验证")
        if isinstance(exc, PyiCloudFailedLoginException):
            if self._password:
                return InvalidCredentialsError("Apple ID 或密码错误，或 Apple 拒绝了登录请求")
            return AuthExpiredError("iCloud 会话已失效，且未配置可用于重新登录的密码")
        if isinstance(exc, PyiCloudAPIResponseException):
            code = str(exc.code or "")
            if code in _AUTH_ERROR_CODES:
                return AuthExpiredError(f"iCloud 登录态已失效（{code or '认证错误'}）")
            return HwCloudError(f"iCloud 请求失败（{code or '未知错误'}）")
        if isinstance(exc, (
            PyiCloudConnectionErrorException,
            PyiCloudConnectionException,
            PyiCloudServiceUnavailableException,
            requests.RequestException,
        )):
            return HwCloudError(f"iCloud 网络请求失败: {exc}")
        if isinstance(exc, PyiCloudException):
            return HwCloudError(f"iCloud 操作失败: {exc}")
        if isinstance(exc, KeyError) and str(exc).strip("'") in _SRP_FIELDS:
            # Apple 拒绝 signin/init（风控、验证码或密码错误）时返回体缺少 SRP 字段。
            return HwCloudError(
                "Apple 登录响应异常（可能触发风控或需要人工验证），请稍后重试或更换网络"
            )
        return exc

    def _build_service(self) -> Any:
        data = self.store.load() or {}
        data.update({
            "platform": "icloud",
            "apple_id": self.apple_id,
            "domain": self.domain,
        })
        data.setdefault("client_id", f"auth-{uuid4()}")
        self.store.save(data)
        try:
            service = self._service_factory(
                self.domain,
                self.apple_id,
                lambda: self._password,
                cookie_directory=str(self.session_path.parent),
                client_id=str(data["client_id"]),
                with_family=False,
                http_timeout=self.http_timeout,
                session_path=str(self.session_path),
                cookiejar_path=str(self.cookiejar_path),
            )
        except Exception as exc:
            self._auth_retry_after = time.time() + _AUTH_RETRY_BACKOFF_SEC
            raise self._translate(exc) from exc
        self._persist_service(service)
        return service

    def _persist_service(self, service: Any) -> None:
        data = dict(getattr(service, "session_data", {}) or {})
        data.update({
            "platform": "icloud",
            "apple_id": self.apple_id,
            "domain": self.domain,
        })
        service.session_data = data
        self.store.save(data)
        session = getattr(service, "session", None)
        cookies = getattr(session, "cookies", None)
        if cookies is not None:
            self.store.save_cookies(cookies)
        self._notify_session_update()

    @staticmethod
    def _challenge_channels(flow: str, devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if flow == "2fa":
            return [{"id": "trusted_device", "name": "受信任 Apple 设备", "type": "push"}]
        channels = []
        for index, device in enumerate(devices):
            channels.append({
                "id": str(device.get("id") or index),
                "name": str(device.get("deviceName") or device.get("phoneNumber") or f"受信任设备 {index + 1}"),
                "type": "sms",
            })
        return channels

    @staticmethod
    def _phone_device_id(device: Any, index: int) -> Any:
        device_id = getattr(device, "id", None)
        if device_id is None and isinstance(device, dict):
            device_id = device.get("id")
        return device_id if device_id is not None else index

    def _phone_channel(self, device: Any, index: int) -> dict[str, Any]:
        number = str(getattr(device, "obfuscated_number", "") or "")
        if not number and isinstance(device, dict):
            number = str(device.get("phoneNumber") or "")
        return {
            "id": str(self._phone_device_id(device, index)),
            "name": f"短信验证码 {number}".strip(),
            "type": "sms",
        }

    def _trigger_push(self, service: Any) -> bool:
        """Apple 2026+ 流程需显式触发推送，否则受信任设备不会收到验证码。"""
        trigger = getattr(service, "trigger_push_notification", None)
        if trigger is None:
            return False
        try:
            ok = bool(trigger())
        except Exception as exc:
            logger.warning("icloud 2FA push trigger failed: %s", exc)
            return False
        if ok:
            logger.info("icloud 2FA push notification triggered, account=%s", self.apple_id)
        else:
            logger.warning("icloud 2FA push notification not accepted, account=%s", self.apple_id)
        return ok

    def _trusted_phones(self, service: Any) -> list[Any]:
        getter = getattr(service, "get_trusted_phone_numbers", None)
        if getter is None:
            return []
        try:
            return list(getter() or [])
        except Exception as exc:
            logger.warning("icloud trusted phone lookup failed: %s", exc)
            return []

    def _set_pending_challenge(self, service: Any, *, trigger_push: bool = False) -> None:
        if bool(getattr(service, "requires_2fa", False)):
            channels: list[dict[str, Any]] = [
                {"id": "trusted_device", "name": "受信任 Apple 设备", "type": "push"}
            ]
            push_ok = False
            sms_device: Any | None = None
            sms_device_id: Any | None = None
            if trigger_push:
                # 只有网页触发的登录才推送，避免 daemon 后台重登额外打扰用户。
                phones = self._trusted_phones(service)
                push_ok = self._trigger_push(service)
                if phones and not push_ok:
                    # 推送未触发成功时退回短信通道，避免用户面对「验证码已发送」却无码可填。
                    sms_device = phones[0]
                    sms_device_id = self._phone_device_id(sms_device, 0)
                    send_sms = getattr(service, "send_2fa_code_sms", None)
                    try:
                        sent = bool(send_sms(sms_device_id)) if send_sms is not None else False
                    except Exception as exc:
                        logger.warning("icloud 2FA SMS sending failed: %s", exc)
                        sent = False
                    if sent:
                        channels.append(self._phone_channel(sms_device, 0))
                        logger.info("icloud 2FA SMS code sent, account=%s", self.apple_id)
                    else:
                        sms_device = None
                        sms_device_id = None
            self._pending = {
                "flow": "2fa",
                "channels": channels,
                "created_at": time.time(),
                "service": service,
                "sms_device": sms_device,
                "sms_device_id": sms_device_id,
            }
            self.store.save_pending({
                "flow": "2fa",
                "channels": channels,
                "created_at": self._pending["created_at"],
            })
            if not trigger_push:
                raise TwoFactorRequiredError(
                    "iCloud 需要二次验证，请在网页点击「登录」触发验证码推送后再输入"
                )
            if push_ok:
                raise TwoFactorRequiredError("验证码已推送至受信任 Apple 设备，请输入 6 位验证码")
            if sms_device is not None:
                raise TwoFactorRequiredError("推送未送达，验证码已改为短信发送，请输入 6 位验证码")
            raise TwoFactorRequiredError(
                "请在受信任 Apple 设备上查看 6 位验证码；若长时间未收到，请重新登录以再次触发推送"
            )
        if bool(getattr(service, "requires_2sa", False)):
            try:
                devices = [dict(d) for d in (getattr(service, "trusted_devices", []) or [])]
                if not devices:
                    raise TwoFactorRequiredError("iCloud 需要两步验证，但未找到可接收验证码的受信任设备")
                device = devices[0]
                if not service.send_verification_code(device):
                    raise HwCloudError("iCloud 两步验证码发送失败，请稍后重试")
            except Exception as exc:
                translated = self._translate(exc)
                raise translated from exc
            self._pending = {
                "flow": "2sa",
                "channels": self._challenge_channels("2sa", devices),
                "created_at": time.time(),
                "service": service,
                "device": device,
            }
            self.store.save_pending({
                "flow": "2sa",
                "channels": self._pending["channels"],
                "created_at": self._pending["created_at"],
            })
            raise TwoFactorRequiredError("验证码已发送至受信任设备，请输入 6 位验证码")

    @staticmethod
    def _marker_created_at(marker: dict[str, Any] | None) -> float:
        try:
            return float((marker or {}).get("created_at") or 0.0)
        except (TypeError, ValueError):
            return 0.0

    def _pending_file_mtime(self) -> float:
        try:
            return self.session_path.stat().st_mtime
        except OSError:
            return 0.0

    def _discard_stale_pending(self) -> None:
        """多实例并存（web 与 daemon 各持一个 client）时，内存 pending 可能已过时。

        - 磁盘标记比本实例 pending 更新：别的实例开启了新验证流程，本实例让位；
        - 标记消失且会话文件在 pending 之后被写过：别的实例已完成验证并落盘
          可信会话，本实例丢弃内存挑战并改用磁盘会话重建。
        """
        if self._pending is None:
            return
        created = float(self._pending.get("created_at") or 0.0)
        marker = self.store.load_pending()
        marker_created = self._marker_created_at(marker)
        if marker is not None and marker_created > created:
            logger.info(
                "icloud stale in-memory pending superseded by newer flow, account=%s", self.apple_id
            )
            self._pending = None
        elif marker is None and created > 0 and self._pending_file_mtime() > created:
            logger.info(
                "icloud pending completed by another instance, reloading trusted session, account=%s",
                self.apple_id,
            )
            self._pending = None
            self._service = None

    def _ready_service(self, *, ignore_pending: bool = False, force: bool = False,
                       trigger_push: bool = False) -> Any:
        if not force and self._service is None and time.time() < self._auth_retry_after:
            raise HwCloudError("iCloud 认证连续失败，已暂停自动重试；请稍后在网页重新登录")
        self._discard_stale_pending()
        if not ignore_pending and self._pending is None and self.store.load_pending():
            raise TwoFactorRequiredError(
                "iCloud 二次验证尚未完成，请在「认证与安全」输入 6 位验证码（如已失效请重新登录）"
            )
        if self._pending is not None:
            raise TwoFactorRequiredError("iCloud 二次验证尚未完成，请先提交验证码")
        if self._service is None:
            self._service = self._build_service()
        self._set_pending_challenge(self._service, trigger_push=trigger_push)
        return self._service

    def login(self, *, interactive: bool = False) -> ICloudClient:
        """恢复可信会话；会话无效时由上游使用已配置密码重新登录。"""
        self._pending = None  # 重新登录视为开启新的验证流程。
        self.store.clear_pending()
        self._ready_service(ignore_pending=True, force=True, trigger_push=interactive)
        self._auth_retry_after = 0.0
        self._persist_service(self._service)
        logger.info("icloud login succeeded, account=%s domain=%s", self.apple_id, self.domain)
        return self

    def ensure_service(self) -> Any:
        return self._ready_service()

    def auth_backoff_active(self) -> bool:
        return self._service is None and time.time() < self._auth_retry_after

    def pending_challenge(self) -> dict[str, Any] | None:
        self._discard_stale_pending()
        if self._pending is None:
            return None
        return {
            "flow": self._pending["flow"],
            "channels": list(self._pending.get("channels") or []),
            "created_at": self._pending.get("created_at"),
        }

    def submit_challenge(self, code: str) -> ICloudClient:
        if self._pending is None:
            raise AuthExpiredError("没有进行中的 iCloud 二次验证，请重新登录")
        service = self._pending["service"]
        flow = self._pending["flow"]
        logger.info(
            "icloud challenge submit begin, account=%s flow=%s", self.apple_id, flow
        )
        try:
            if flow == "2fa":
                ok = bool(service.validate_2fa_code(code))
                sms_device_id = self._pending.get("sms_device_id")
                if not ok and sms_device_id is not None:
                    # 短信通道发出的验证码只能由 /sms/securitycode 校验。
                    validate_sms = getattr(service, "validate_2fa_code_sms", None)
                    if validate_sms is not None:
                        ok = bool(validate_sms(sms_device_id, code))
            else:
                ok = bool(service.validate_verification_code(self._pending["device"], code))
                # 2SA 的部分账号不支持 /2sv/trust；上游已在此场景完成令牌认证。
                service.trust_session()
            if not ok:
                logger.warning(
                    "icloud challenge code rejected, account=%s flow=%s", self.apple_id, flow
                )
                raise TwoFactorRequiredError("验证码错误或已过期，请重新输入")
            if bool(getattr(service, "requires_2fa", False)) or bool(getattr(service, "requires_2sa", False)):
                logger.warning(
                    "icloud challenge still required after submit, account=%s flow=%s "
                    "requires_2fa=%s requires_2sa=%s trust=%s",
                    self.apple_id, flow,
                    bool(getattr(service, "requires_2fa", False)),
                    bool(getattr(service, "requires_2sa", False)),
                    bool(getattr(service, "is_trusted_session", False)),
                )
                raise TwoFactorRequiredError("二次验证尚未完成，请重新输入验证码")
        except Exception as exc:
            translated = self._translate(exc)
            if not isinstance(translated, TwoFactorRequiredError):
                # 验证码错误可重试；其他异常（网络/会话失效）应结束本轮验证。
                logger.warning(
                    "icloud challenge submit failed, account=%s flow=%s: %s",
                    self.apple_id, flow, translated,
                )
            # 保留 pending service，验证码错误可直接重试。
            raise translated from exc
        self._pending = None
        self.store.clear_pending()
        self._service = service
        self._persist_service(service)
        logger.info("icloud challenge completed, account=%s flow=%s", self.apple_id, flow)
        return self

    def heartbeat(self) -> bool:
        try:
            self.list_albums()
            return True
        except Exception as exc:
            raise self._translate(exc) from exc

    @staticmethod
    def _album_id(name: str, album: Any) -> str:
        obj_type = str(getattr(album, "obj_type", "") or "")
        if obj_type.startswith("CPLContainerRelationNotDeletedByAssetDate:"):
            return obj_type.rsplit(":", 1)[-1]
        return f"smart:{name}"

    def list_albums(self) -> list[dict[str, Any]]:
        try:
            service = self._ready_service()
            raw_albums = service.photos.albums
            result = []
            for name, album in raw_albums.items():
                result.append({
                    "id": self._album_id(name, album),
                    "name": name,
                    "album": album,
                    "is_virtual": name in getattr(service.photos, "SMART_FOLDERS", {}),
                    "is_recycle": name == "Recently Deleted",
                })
            self._notify_session_update()
            return result
        except Exception as exc:
            raise self._translate(exc) from exc

    def _find_album(self, album_id: str) -> Any:
        for entry in self.list_albums():
            if entry["id"] == album_id:
                return entry["album"]
        raise HwCloudError(f"iCloud 相册不存在或已移除: {album_id}")

    def iter_assets(self, album_id: str | None, *, page_size: int = 100) -> Iterator[Any]:
        try:
            service = self._ready_service()
            album = service.photos.all if album_id is None else self._find_album(album_id)
            album.page_size = max(1, int(page_size or 100))
            for asset in album.photos:
                self._assets[str(asset.id)] = asset
                yield asset
            self._notify_session_update()
        except Exception as exc:
            raise self._translate(exc) from exc

    def _refresh_asset(self, asset_id: str, album_id: str | None) -> Any:
        self._assets.pop(asset_id, None)
        for asset in self.iter_assets(album_id, page_size=100):
            if str(asset.id) == asset_id:
                return asset
        raise HwCloudError("无法刷新 iCloud 下载地址：资产已不存在或不在原相册中")

    @staticmethod
    def _serialize_versions(asset: Any) -> dict[str, dict[str, Any]]:
        versions = {}
        for key, version in (asset.versions or {}).items():
            # Live Photo 伴随 MOV 使用同名尺寸键，首版仅下载静帧，必须隔离。
            if not isinstance(key, AssetVersionSize):
                continue
            name = str(getattr(key, "value", key)).lower()
            if name == "small":
                name = "thumb"
            versions[name] = {
                "url": str(getattr(version, "url", "") or ""),
                "size": int(getattr(version, "size", 0) or 0),
                "type": str(getattr(version, "type", "") or ""),
                "checksum": str(getattr(version, "checksum", "") or ""),
            }
        return versions

    def get_download_url(
        self,
        asset_id: str,
        *,
        album_id: str | None,
        size_variant: str = "original",
        versions: dict[str, dict[str, Any]] | None = None,
        refresh: bool = False,
    ) -> str:
        if size_variant not in _SIZE_KEYS:
            raise HwCloudError(f"不支持的 iCloud 下载尺寸: {size_variant}")
        try:
            asset = None if refresh else self._assets.get(asset_id)
            if refresh or (asset is None and versions is None):
                asset = self._refresh_asset(asset_id, album_id)
            if asset is not None:
                versions = self._serialize_versions(asset)
            version = (versions or {}).get(size_variant)
            url = str((version or {}).get("url") or "")
            if not url:
                raise HwCloudError(f"iCloud 资产缺少 {size_variant} 下载版本，未降级为其他尺寸")
            return json.dumps({
                "url": url,
                "asset_id": asset_id,
                "album_id": album_id or "",
                "size_variant": size_variant,
            }, ensure_ascii=False)
        except Exception as exc:
            raise self._translate(exc) from exc

    @staticmethod
    def _content_disposition_filename(response: Any) -> str | None:
        value = response.headers.get("Content-Disposition")
        if not value:
            return None
        message = Message()
        message["Content-Disposition"] = value
        filename = message.get_filename()
        return str(filename) if filename else None

    def _stream_once(self, url: str, part_path: Path, *, resume: bool) -> DownloadResult:
        resume_from = part_path.stat().st_size if resume and part_path.is_file() else 0
        headers = {"Accept": "*/*", "User-Agent": "AlbumSync/1.0"}
        if resume_from:
            headers["Range"] = f"bytes={resume_from}-"
        session = self._download_session_factory()
        # 独立 CDN Session：绝不复制 PyiCloudService 的登录 Cookie。
        session.cookies.clear()
        response = None
        try:
            response = session.get(url, headers=headers, stream=True, timeout=self.http_timeout)
            if response.status_code in (401, 403):
                raise _CdnAuthorizationError()
            if response.status_code == 416 and resume_from:
                raise _RangeNotSatisfiable()
            if response.status_code == 206:
                match = _CONTENT_RANGE_RE.fullmatch(
                    str(response.headers.get("Content-Range") or "").strip()
                )
                if not match or int(match.group(1)) != resume_from:
                    if resume_from:
                        raise _RestartFullDownload()
                    raise HwCloudError("iCloud CDN 返回了无效的 Content-Range")
            elif response.status_code != 200:
                response.raise_for_status()

            append = response.status_code == 206 and resume_from > 0
            sha256 = hashlib.sha256()
            md5 = hashlib.md5()
            total = 0
            if append:
                with part_path.open("rb") as existing:
                    while chunk := existing.read(1024 * 1024):
                        sha256.update(chunk)
                        md5.update(chunk)
                        total += len(chunk)
            mode = "ab" if append else "wb"
            with part_path.open(mode) as output:
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    output.write(chunk)
                    sha256.update(chunk)
                    md5.update(chunk)
                    total += len(chunk)
            return DownloadResult(
                bytes_written=total,
                sha256_hex=sha256.hexdigest(),
                md5_hex=md5.hexdigest(),
                content_disposition_filename=self._content_disposition_filename(response),
            )
        except (_CdnAuthorizationError, _RangeNotSatisfiable, _RestartFullDownload):
            raise
        except requests.RequestException as exc:
            raise HwCloudError(f"iCloud CDN 下载失败: {exc}") from exc
        finally:
            if response is not None:
                response.close()
            session.close()

    def download_to_file(self, descriptor: str, part_path: str | Path, *, resume: bool = True) -> DownloadResult:
        part_path = Path(part_path)
        part_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            parsed = json.loads(descriptor)
            details = parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, TypeError):
            details = {}
        url = str(details.get("url") or descriptor)
        asset_id = str(details.get("asset_id") or "")
        album_id = str(details.get("album_id") or "") or None
        size_variant = str(details.get("size_variant") or "original")

        refreshed = False
        while True:
            resume_allowed = resume
            retried_416 = False
            restarted_bad_range = False
            try:
                while True:
                    try:
                        return self._stream_once(url, part_path, resume=resume_allowed)
                    except _RangeNotSatisfiable:
                        if retried_416:
                            raise HwCloudError("iCloud CDN 全量重试仍返回 416")
                        retried_416 = True
                        part_path.unlink(missing_ok=True)
                        resume_allowed = False
                    except _RestartFullDownload:
                        if restarted_bad_range:
                            raise HwCloudError("iCloud CDN 多次返回无效 Content-Range")
                        restarted_bad_range = True
                        resume_allowed = False
            except _CdnAuthorizationError as exc:
                if refreshed or not asset_id:
                    raise HwCloudError("iCloud CDN 签名地址已失效，刷新后仍无法下载") from exc
                refreshed = True
                new_descriptor = self.get_download_url(
                    asset_id,
                    album_id=album_id,
                    size_variant=size_variant,
                    refresh=True,
                )
                url = str(json.loads(new_descriptor)["url"])

    def invalidate(self) -> None:
        self._service = None
        self._pending = None
        self._assets.clear()


__all__ = [
    "AlbumSyncPyiCloudService",
    "ICloudClient",
]
