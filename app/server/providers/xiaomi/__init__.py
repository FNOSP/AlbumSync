#!/usr/bin/env python3
"""小米云相册 Provider（T27）：import_session 路线 + XiaomiClient（urllib 纯标准库）。

登录策略：**仅 import_session（cookie 导入）**。密码直登在冷启动/登出后场景
大概率触发短信验证码（T26.1 两次登录对比实测），自动化不可靠；故 capabilities
supports_web_login_2fa = False，supports_curl_import = True。

Provider 10 方法：
  ✓ heartbeat_check / get_gallery_stats / list_albums / iter_simple_files
    enrich_metadata / pre_process / get_download_url / download_to_part
  ✗ get_burst_files / delete_cloud_files → 返回空/零，capabilities 声明 false

相册名称：API 不含，前端按 albumId 本地映射；XiaomiClient.resolve_album_name()
内置常用系统相册字典 + 自定义兜底 "相册{albumId}"。

引擎约束：小米接口（i.mi.com/gallery/user/*）不在 vendor hwcloudpd 引擎中，
本 Provider 独立实现，不委托 HuaweiGalleryClient。
"""
from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Iterator

from hwcloudpd.models import (
    AlbumInfo,
    AuthExpiredError,
    MediaItem,
    MediaStub,
)
from providers.base import ProviderCapabilities

from providers.xiaomi.xiaomi_client import (
    XiaomiAPIError,
    XiaomiAuthExpiredError,
    XiaomiClient,
    _mimetype_to_file_type,
    parse_cookie_string,
    validate_session_cookies,
)

logger = logging.getLogger("albumsync.providers.xiaomi")


# ---------------------------------------------------------------------------
# XiaomiSessionStore：文件式 cookie 存储（替代 HuaweiAuthManager）
# ---------------------------------------------------------------------------

class XiaomiSessionStore:
    """小米会话存储：一个 JSON 文件存 cookie dict + 元信息。

    华为 AuthManager 是华为专用（含 CSRFToken、CAS TGT），小米会话模型
    仅需 cookie dict，故自建轻量 store。auth_file 路径由构造器传入
    （调用方决定存哪里，对齐华为的 auth.json 位置）。
    """

    def __init__(self, auth_file: str | Path) -> None:
        self.auth_file = Path(auth_file)

    def save(self, cookies: dict[str, str]) -> None:
        auth_file = Path(self.auth_file)  # 防御 str 覆盖构造器 Path 转换
        auth_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "platform": "xiaomi",
            "cookies": cookies,
            "user_id": str(cookies.get("userId") or ""),
            "updated_at": time.time(),
        }
        tmp = auth_file.with_suffix(auth_file.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(auth_file)

    def load(self) -> dict[str, Any] | None:
        auth_file = Path(self.auth_file)
        if not auth_file.is_file():
            return None
        try:
            return json.loads(auth_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("xiaomi session load failed: %s", e)
            return None

    def load_cookies(self) -> dict[str, str]:
        data = self.load()
        if not data:
            return {}
        return {str(k): str(v) for k, v in (data.get("cookies") or {}).items()}

    def clear(self) -> None:
        try:
            self.auth_file.unlink(missing_ok=True)
        except Exception as e:
            logger.warning("xiaomi session clear failed: %s", e)

    def has_session(self) -> bool:
        cookies = self.load_cookies()
        ok, _ = validate_session_cookies(cookies)
        return ok


# ---------------------------------------------------------------------------
# XiaomiAuthStrategy
# ---------------------------------------------------------------------------

class XiaomiAuthStrategy:
    """AuthStrategy 实现：import_session 导入 + heartbeat 探活。

    supports_web_login_2fa = False（密码直登不可靠），
    supports_curl_import = True（cookie 导入为唯一登录通道）。
    """

    PLATFORM = "xiaomi"

    def __init__(
        self,
        auth_manager: Any,  # 保持与工厂签名兼容，小米不真正使用
        account: dict[str, Any] | None = None,
        *,
        auth_file: str | None = None,
    ) -> None:
        account = account or {}
        self.account_id = str(account.get("id") or "")
        self._username = (str(account.get("username") or "").strip() or None)
        # auth_file 默认：config_dir/xiaomi_{account_id}_auth.json
        # 调用方（account manager）会在 account["auth_file"] 里传实际路径
        auth_file = auth_file or str(account.get("auth_file") or "")
        if not auth_file:
            # 尝试从 auth_manager 推导（华为路径），否则用 cwd/xiaomi_auth.json
            try:
                am = auth_manager
                cfg_dir = Path(getattr(am, "auth_file", Path.cwd())).parent
                auth_file = str(cfg_dir / f"xiaomi_{self.account_id or 'default'}_auth.json")
            except Exception:
                auth_file = str(Path.cwd() / f"xiaomi_{self.account_id or 'default'}_auth.json")
        self.store = XiaomiSessionStore(auth_file)
        self._client: XiaomiClient | None = None

    # -- 懒构造 client --

    def _client_or_raise(self) -> XiaomiClient:
        if self._client is None:
            cookies = self.store.load_cookies()
            ok, err = validate_session_cookies(cookies)
            if not ok:
                raise AuthExpiredError(f"小米会话未导入或无效: {err}")
            self._client = XiaomiClient(cookies)
        return self._client

    # -- 从 cURL 提取 cookie --

    @staticmethod
    def _extract_cookies_from_curl(curl_text: str) -> dict[str, str]:
        """从 cURL bash 文本中提取 -H 'Cookie: ...' 或 --cookie '...' 的 cookie。"""
        cookies: dict[str, str] = {}
        # -H 'cookie: ...' 或 -H "cookie: ..."
        for m in re.finditer(
            r'-H\s+[\'"](cookie|Cookie)\s*:\s*([^\'"]+)[\'"]', curl_text,
        ):
            cookies.update(parse_cookie_string(m.group(2)))
        # --cookie '...' 或 -b '...'
        for m in re.finditer(
            r'(--cookie|-b)\s+[\'"]([^\'"]+)[\'"]', curl_text,
        ):
            cookies.update(parse_cookie_string(m.group(2)))
        return cookies

    # -- AuthStrategy 协议 --

    def ensure_session(self) -> XiaomiClient:
        client = self._client_or_raise()
        # 探活确认会话有效
        if not client.probe_session():
            self._client = None  # 强制下次重构造
            raise AuthExpiredError("小米会话已失效，请重新导入")
        return client

    def get_session_if_present(self) -> XiaomiClient | None:
        if not self.store.has_session():
            return None
        try:
            client = self._client_or_raise()
        except AuthExpiredError:
            return None
        return client

    def has_credentials(self) -> bool:
        """小米「凭据」= 已导入的 cookie；账号密码不使用。"""
        return self.store.has_session()

    def web_login(self, *, prompt_fn: Any = None, output_fn: Any = None) -> Any:
        """小米不做密码直登（风控必触发验证码）。"""
        raise AuthExpiredError(
            "小米云相册不支持密码直登，请从已登录浏览器复制 cookie 导入"
        )

    def submit_challenge(self, code: str, *, prompt_fn: Any = None,
                         output_fn: Any = None) -> Any:
        raise AuthExpiredError("小米不支持两段式验证码登录")

    def pending_challenge(self) -> dict[str, Any] | None:
        return None

    def import_session(self, curl_text: str) -> XiaomiClient:
        """从 cURL 文本或 cookie 字符串导入会话。

        curl_text 可以是：
        - cURL bash 命令（含 -H 'Cookie: ...'）
        - 纯 cookie 字符串 "userId=xxx; serviceToken=yyy; ..."
        """
        cookies: dict[str, str] = {}
        # 先尝试 cURL 提取
        extracted = self._extract_cookies_from_curl(curl_text)
        if extracted:
            cookies = extracted
        else:
            # 退回：直接当 cookie 字符串解析
            cookies = parse_cookie_string(curl_text)

        ok, err = validate_session_cookies(cookies)
        if not ok:
            raise AuthExpiredError(f"导入失败：{err}")

        self.store.save(cookies)
        self._client = XiaomiClient(cookies)

        # 探活确认真的能用
        if not self._client.probe_session():
            self.store.clear()
            self._client = None
            raise AuthExpiredError(
                "会话探活失败（serviceToken 可能已过期），请重新导出 cookie"
            )
        logger.info("xiaomi session imported, userId=%s", cookies.get("userId", ""))
        return self._client

    def is_valid(self) -> bool:
        return self.store.has_session()

    def invalidate(self) -> None:
        self.store.clear()
        self._client = None
        logger.info("xiaomi session invalidated, account_id=%s", self.account_id)

    # -- 华为平台特有方法的空实现（auth_status / _start_daemon 会无条件调用） --

    def cas_probe(self) -> dict[str, Any]:
        """AuthRuntime.auth_status 无条件调用；小米平台无 CAS 语义 → 全 false。"""
        return {
            "pending_2fa": None,
            "has_cas_tgt": False,
            "credentials_configured": self.store.has_session(),
        }

    def build_authenticator(self, two_fa_code: str | None = None) -> Any:
        """daemon 启动时无条件调用（app_runtime._start_daemon）。

        小米不支持密码自动重登 → 返回 can_attempt_login=False 的桩，
        daemon 收到 authenticator=None，仅依赖已导入的 cookie 会话。
        """
        return _XiaomiNoRelogin()


class _XiaomiNoRelogin:
    """小米 daemon 认证器桩：永远不允许自动重登。"""

    can_attempt_login = False

    def attempt_login(self) -> None:  # pragma: no cover - daemon 永不调用
        raise AuthExpiredError("小米云不支持自动重登，请在「认证与安全」重新导入 cookie")


# ---------------------------------------------------------------------------
# XiaomiProvider：PhotoProvider 协议
# ---------------------------------------------------------------------------

class XiaomiProvider:
    """PhotoProvider 实现：薄包装 XiaomiClient + 数据转换。

    小米 API 字段名与华为不同（小米：fileName/id/sha1/size；华为：uniqueId/size），
    本层负责 Xiaomi 原始 dict → MediaStub/MediaItem 的转换。
    """

    def __init__(
        self,
        auth_manager: Any,
        account: dict[str, Any] | None = None,
    ) -> None:
        self.auth_strategy = XiaomiAuthStrategy(auth_manager, account)
        self.account_id = self.auth_strategy.account_id or "xiaomi"

    def _client(self) -> XiaomiClient:
        return self.auth_strategy.ensure_session()

    # -- PhotoProvider 10 方法 --

    def heartbeat_check(self) -> bool:
        try:
            client = self.auth_strategy.get_session_if_present()
            if client is None:
                return False
            return client.probe_session()
        except Exception:
            return False

    def get_gallery_stats(self) -> dict[str, int]:
        """聚合相册 mediaCount → 总数。"""
        try:
            client = self._client()
            albums = client.get_album_list()
            total = sum(int(a.get("mediaCount") or 0) for a in albums)
            return {
                "total": total,
                "albums": len(albums),
            }
        except (XiaomiAuthExpiredError, AuthExpiredError):
            raise
        except Exception as e:
            logger.warning("xiaomi gallery stats failed: %s", e)
            return {"total": 0, "albums": 0}

    def list_albums(self, *, include_stats: bool = False) -> list[AlbumInfo]:
        client = self._client()
        raw_albums = client.get_album_list()
        result: list[AlbumInfo] = []
        for a in raw_albums:
            aid = str(a.get("albumId") or "")
            mc = int(a.get("mediaCount") or 0)
            result.append(AlbumInfo(
                album_id=aid,
                name=client.resolve_album_name(aid),
                album_version="",
                owner_id=str(a.get("userId") or ""),
                img_num=mc,
                video_num=0,  # 小米不区分视频数量
                hide=0,
                is_virtual=False,
                is_recycle=False,
            ))
        # 按 mediaCount 倒序
        result.sort(key=lambda x: x.img_num, reverse=True)
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
        """timeline → galleries 按天分页 → yield list[MediaStub]。

        遍历策略：timeline(dayCount) 拿全部日期 → 每天 galleries 翻页
        （小米默认 pageSize=30，引擎 page_size=100 也可接受）。
        若 timeline 为空则直接用 startDate=19700101 宽日期区间翻页。
        """
        client = self._client()

        # 日期集合
        day_count = client.get_timeline(album_id) if album_id else {}
        dates = sorted(day_count.keys()) if day_count else []

        if not dates:
            # 兜底：单次拉
            dates = ["19700101"]

        for date_str in dates:
            page_num = 0
            while True:
                resp = client.get_photo_page(
                    date_str, date_str,
                    page_num=page_num,
                    page_size=page_size,
                    album_id=album_id,
                )
                data = resp.get("data") or {}
                items = list(data.get("galleries") or data.get("photos") or [])
                stubs = [self._photo_to_stub(p, album_id, album_name, client) for p in items]
                if stubs:
                    yield stubs
                if data.get("isLastPage"):
                    break
                page_num += 1

    def get_burst_files(
        self,
        album_id: str,
        unique_id: str,
        *,
        album_name: str = "",
        album_version: str = "",
        owner_id: str | None = None,
    ) -> list[MediaStub]:
        """小米未调研连拍接口 → 返回空列表（capabilities 已声明 false）。"""
        return []

    def enrich_metadata(self, stubs: list[MediaStub]) -> list[MediaItem]:
        """小米 galleries 响应已含完整字段（size/exifInfo/sha1），
        此处仅 stub → MediaItem 转换。
        """
        return [
            MediaItem(
                unique_id=s.unique_id,
                album_id=s.album_id,
                album_name=s.album_name,
                file_type=s.file_type,
                create_time_ms=s.create_time_ms,
                is_cover=s.is_cover,
                is_fav=s.is_fav,
                uid=s.uid,
                file_name=s.file_name,
                file_size=getattr(s, "_size", 0),
                checksum=getattr(s, "_sha1", ""),
                album_version=s.album_version,
                owner_id=s.owner_id,
                expand=getattr(s, "_expand", {}),
            )
            for s in stubs
        ]

    def pre_process(self) -> None:
        """小米无 galleryStatsInfo 预热 → 空实现。"""

    def get_download_url(self, item: MediaItem, size_variant: str = "original") -> str:
        """执行小米三跳链路，返回 download_file URL + meta 的 JSON 串（引擎侧
        download_to_part 再解析用）。

        小米的「下载 URL」不是一个可直接 GET 的直链，需要 POST form meta。
        所以这里返回一个 JSON 串 {"url": "...download_file?...", "meta": "..."}，
        download_to_part 里解析后 POST 取字节。
        """
        client = self._client()
        photo_id = item.unique_id
        if not photo_id:
            raise XiaomiAPIError(0, "MediaItem.unique_id 为空，无法下载")
        download_url, meta = client.get_download_meta(photo_id)
        return json.dumps({"url": download_url, "meta": meta})

    def download_to_part(self, url: str, part_path: Path) -> Any:
        """解析 get_download_url 返回的 JSON 串 → POST form meta → 流式写 part 文件。"""
        try:
            meta_obj = json.loads(url)
        except json.JSONDecodeError:
            # 兼容：如果传进来的是纯 URL（非 JSON 串），退化为原始逻辑
            logger.warning("xiaomi download_to_part url 不是 JSON 串: %s", url[:100])
            raise XiaomiAPIError(0, "download_to_part 参数格式错误：需要 JSON 串 {url, meta}")

        download_url = str(meta_obj.get("url") or "")
        meta = str(meta_obj.get("meta") or "")
        if not download_url or not meta:
            raise XiaomiAPIError(0, f"download_url JSON 缺 url/meta: {meta_obj}")

        client = self._client()
        sink = _FileSink(part_path)
        client.download_with_meta(download_url, meta, sink=sink.write)
        sink.close()

        # 返回 DownloadResult-like 对象（引擎检查 attributes）
        return type("XiaomiDownloadResult", (), {
            "success": True,
            "size": sink.bytes_written,
            "part_path": part_path,
            "error": None,
        })()

    def delete_cloud_files(self, items: list[MediaItem]) -> int:
        """小米未调研删除接口 → 返回 0（capabilities 已声明 false，引擎不会真正调）。"""
        logger.info("xiaomi delete_cloud_files 不支持，跳过 %d 个文件", len(items))
        return 0

    # ------------------------------------------------------------------
    # 数据转换辅助
    # ------------------------------------------------------------------

    @staticmethod
    def _photo_to_stub(
        photo: dict[str, Any],
        album_id: str | None,
        album_name: str,
        client: XiaomiClient,
    ) -> MediaStub:
        pid = str(photo.get("id") or "")
        file_name = str(photo.get("fileName") or photo.get("title") or f"{pid}.jpg")
        mime = str(photo.get("mimeType") or "")
        photo_type = str(photo.get("type") or "")
        file_type = _mimetype_to_file_type(mime, photo_type)
        create_ts = int(
            photo.get("dateTaken")
            or photo.get("sortTime")
            or photo.get("createTime")
            or photo.get("dateModified")
            or 0
        )

        # 从 description 里抽 isFavorite
        is_fav = 0
        try:
            desc = photo.get("description") or ""
            if isinstance(desc, str) and desc:
                d = json.loads(desc)
                if d.get("isFavorite"):
                    is_fav = 1
        except (json.JSONDecodeError, TypeError):
            pass

        stub = MediaStub(
            unique_id=pid,
            album_id=str(album_id or "0"),
            album_name=album_name or client.resolve_album_name(str(album_id or "0")),
            file_type=file_type,
            create_time_ms=create_ts,
            is_cover=0,
            is_fav=is_fav,
            uid=str(photo.get("userId") or ""),
            file_name=file_name,
            album_version="",
            owner_id=str(photo.get("userId") or None),
            recycle_time="",
        )
        # 附加字段（enrich_metadata 用）
        stub._size = int(photo.get("size") or 0)
        stub._sha1 = str(photo.get("sha1") or "")
        stub._expand = {
            "mimeType": mime,
            "type": photo_type,
            "thumbnail_big": ((photo.get("bigThumbnailInfo") or {}).get("data") or ""),
            "thumbnail": ((photo.get("thumbnailInfo") or {}).get("data") or ""),
        }
        return stub


class _FileSink:
    """download_to_part 的流式写入器，避免大文件一次性载入内存。"""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(path, "wb")
        self.bytes_written = 0

    def write(self, chunk: bytes) -> None:
        self._fh.write(chunk)
        self.bytes_written += len(chunk)

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 能力声明 + 工厂（PLATFORMS 注册用）
# ---------------------------------------------------------------------------

# 小米能力矩阵（T26 调研结论）：
#   ✓ supports_curl_import  唯一登录通道
#   ✓ supports_metadata_enrich / supports_gallery_stats
#   ✗ supports_web_login_2fa  密码直登不可靠
#   ✗ supports_delete  未调研删除接口
#   ✗ supports_burst_expansion  未调研连拍
#   ✗ supports_live_photo_mov  未调研实况
#   ✗ supports_favorites_filter  description.isFavorite 有，但引擎是否支持需确认
XIAOMI_CAPABILITIES = ProviderCapabilities(
    platform="xiaomi",
    display_name="小米云相册",
    supports_web_login_2fa=False,
    supports_curl_import=True,
    supports_delete=False,
    supports_burst_expansion=False,
    supports_metadata_enrich=True,
    supports_favorites_filter=False,
    supports_live_photo_mov=False,
    supports_gallery_stats=True,
)


def make_xiaomi_provider(auth_manager: Any, account: dict[str, Any] | None = None) -> XiaomiProvider:
    return XiaomiProvider(auth_manager, account)


def make_xiaomi_auth_strategy(auth_manager: Any, account: dict[str, Any] | None = None) -> XiaomiAuthStrategy:
    return XiaomiAuthStrategy(auth_manager, account)


__all__ = [
    "XiaomiProvider",
    "XiaomiAuthStrategy",
    "XiaomiSessionStore",
    "XiaomiClient",
    "XiaomiAPIError",
    "XiaomiAuthExpiredError",
    "XIAOMI_CAPABILITIES",
    "make_xiaomi_provider",
    "make_xiaomi_auth_strategy",
]
