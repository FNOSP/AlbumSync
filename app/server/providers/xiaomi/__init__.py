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

import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Callable, Iterator

from hwcloudpd.models import (
    AlbumInfo,
    AuthExpiredError,
    MediaItem,
    MediaStub,
)
from providers.base import BaseAuthStrategy, ProviderCapabilities

from providers.xiaomi.xiaomi_client import (
    XiaomiAPIError,
    XiaomiAuthExpiredError,
    XiaomiClient,
    _mimetype_to_file_type,
    parse_cookie_string,
    validate_session_cookies,
)
from providers.xiaomi.longterm import LongtermRenewer, LongtermSessionError, TOKEN_DEAD
from providers.xiaomi.qr_login import XiaomiQRLogin

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

    def save(self, cookies: dict[str, str], longterm: dict[str, Any] | None = None) -> None:
        auth_file = Path(self.auth_file)  # 防御 str 覆盖构造器 Path 转换
        auth_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "platform": "xiaomi",
            "cookies": cookies,
            "user_id": str(cookies.get("userId") or ""),
            "updated_at": time.time(),
        }
        # 保留既有 longterm（serviceToken 轮替落盘不覆盖长效票据）
        if longterm is None:
            prev = self.load()
            longterm = prev.get("longterm") if prev else None
        if longterm:
            payload["longterm"] = longterm
        tmp = auth_file.with_suffix(auth_file.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)  # T28.1：凭据文件权限收紧（对齐华为 auth.json）
        tmp.replace(auth_file)

    def save_longterm(self, longterm: dict[str, Any]) -> None:
        """单独更新长效票据块（T36.5），保留当前 cookies。"""
        data = self.load() or {}
        data["longterm"] = longterm
        cookies = {str(k): str(v) for k, v in (data.get("cookies") or {}).items()}
        self.save(cookies, longterm=longterm)

    def load_longterm(self) -> dict[str, Any] | None:
        data = self.load()
        if not data:
            return None
        lt = data.get("longterm")
        return lt if isinstance(lt, dict) and lt.get("pass_token") else None


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

class XiaomiAuthStrategy(BaseAuthStrategy):
    """AuthStrategy 实现：import_session 导入 + heartbeat 探活。

    supports_web_login_2fa = False（密码直登不可靠），
    supports_curl_import = True（cookie 导入为唯一登录通道）。
    """

    PLATFORM = "xiaomi"
    # -- 平台元数据（BaseAuthStrategy 约定，通用层直接读取） --
    platform_label = "小米云相册"
    credentials_hint = "请先在「认证与安全」导入登录态（扫码登录或 cookie/cURL 导入）"
    login_success_hint = "登录成功"
    qr_login_hint = "请用小米手机「设置 → 小米账号 → 扫一扫」扫码并在手机上确认（5 分钟内有效）"

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
        # 进行中的扫码登录会话（T31.2；None = 无）
        self._qr: XiaomiQRLogin | None = None
        # client 构建时的 auth_file mtime；文件被外部更新（import API /
        # 扫码登录 / 手动替换）后据此重建 client。多 strategy 实例共享同一
        # auth_file（AccountRuntime.strategy 与 XiaomiProvider.auth_strategy
        # 各持一份），单靠内存缓存会让 daemon 永远拿旧 token（真机 401 案发根因）。
        self._client_file_mtime: float = 0.0
        # 长效票重签失败冷却截止（T36.5）
        self._longterm_cooldown_until: float = 0.0

    # -- 懒构造 client --

    def _auth_file_mtime(self) -> float:
        try:
            return self.store.auth_file.stat().st_mtime
        except OSError:
            return 0.0

    def _on_session_rotated(self, cookies: dict[str, str]) -> None:
        """XiaomiClient 响应观察器回调（T28.1）。

        服务端在任意响应中轮替 serviceToken 等会话 cookie 时，把当前完整
        会话原子落盘——对齐 icloudpd「每请求捕获即持久化」语义；否则进程
        重启后内存新 token 丢失，只能报「请重新导入」。
        """
        try:
            self.store.save(cookies)
            # 同步记录新 mtime，避免下一次 _client_or_raise 误判外部更新
            # （jar 里已是新 cookie，无需重建）。
            self._client_file_mtime = self._auth_file_mtime()
            logger.debug(
                "xiaomi rotated session persisted, account=%s userId=%s",
                self.account_id, cookies.get("userId", ""),
            )
        except OSError as e:
            logger.warning("xiaomi rotated session persist failed: %s", e)

    def _new_client(self, cookies: dict[str, str]) -> XiaomiClient:
        """构造带轮替观察器的 client（所有 client 出口统一走这里）。"""
        return XiaomiClient(cookies, session_observer=self._on_session_rotated)

    def _client_or_raise(self) -> XiaomiClient:
        file_mtime = self._auth_file_mtime()
        if self._client is not None and file_mtime != self._client_file_mtime:
            # auth_file 被外部更新 → 丢弃内存 client，从文件重建
            logger.info("xiaomi auth_file changed on disk, rebuilding client")
            self._client = None
        if self._client is None:
            cookies = self.store.load_cookies()
            ok, err = validate_session_cookies(cookies)
            if not ok:
                raise AuthExpiredError(f"小米会话未导入或无效: {err}")
            self._client = self._new_client(cookies)
            self._client_file_mtime = file_mtime
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

    def ensure_session(self, *, probe: bool = False) -> XiaomiClient:
        """获取可用会话。probe=True 时先探活（导入/显式验证场景）。

        T28.5a（对齐 icloudpd）：下载循环每张照片调用本方法，逐张探活
        （每次 = 一轮完整 get_album_list API 调用）纯属浪费且放大限流风险。
        改为信任内存 client；会话失效由请求异常驱动（XiaomiAuthExpiredError
        中断本轮，daemon 下一轮 keepalive 重新探活），单次下载失败时由
        XiaomiProvider._auth_retry 重探活一次再重试。
        """
        client = self._client_or_raise()
        if probe and not client.probe_session():
            # 长效模式下先静默重签再探活一次（T36.5：serviceToken 短命，
            # 401/探活失败大多为 token 过期而非票据死亡）
            if self.try_longterm_renew():
                client = self._client_or_raise()
                if client.probe_session():
                    return client
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

    def session_info(self, session: Any) -> dict[str, Any]:
        """通用字段 + 风控状态透传（T31.10，UI 限流倒计时用）。"""
        info = super().session_info(session)
        try:
            info["risk"] = session.risk_state()
        except Exception:
            info["risk"] = None
        return info

    def risk_state(self) -> dict[str, Any] | None:
        """风控状态：读当前缓存 client（限流在会话失效期间也存在）。"""
        try:
            client = self.get_session_if_present()
        except Exception:
            return None
        if client is None:
            return None
        try:
            risk = client.risk_state()
            return risk or None
        except Exception:
            return None

    def auth_probe(self) -> dict[str, Any]:
        """默认探针 + 长效会话状态透传（T36.5，UI「免扫码模式」显示）。"""
        probe = super().auth_probe()
        probe["longterm"] = self.longterm_state()
        return probe

    def web_login(self, *, prompt_fn: Any = None, output_fn: Any = None,
                  interactive: bool = False) -> Any:
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
        self._client = self._new_client(cookies)

        # 探活确认真的能用
        if not self._client.probe_session():
            self.store.clear()
            self._client = None
            raise AuthExpiredError(
                "会话探活失败（serviceToken 可能已过期），请重新导出 cookie"
            )
        logger.info("xiaomi session imported, userId=%s", cookies.get("userId", ""))
        return self._client

    # -- 扫码登录（T31.2，协议 docs §6） --

    def start_qr_login(self) -> dict[str, Any]:
        """创建扫码票据。返回 {"qr_content", "expire_at"}；异常向上抛由 API 层转 502。"""
        qr = XiaomiQRLogin()
        r = qr.start()
        self._qr = qr
        logger.info("xiaomi qr login started, account=%s expire_at=%s",
                    self.account_id, r["expire_at"])
        return {"qr_content": str(r["qr"]), "expire_at": float(r["expire_at"])}

    def qr_login_status(self) -> dict[str, Any]:
        """驱动扫码状态机一步（lp 长轮询最长挂起 ~65s）。

        confirmed 时自动完成：validate → store.save → _new_client → probe
        （复用 T28.1 观察器接线；探活失败则清 store 报 failed）。
        """
        if self._qr is None:
            return {"status": "expired", "error": "没有进行中的扫码登录"}
        r = self._qr.poll()
        status = r.get("status")

        if status == "confirmed":
            cookies = {str(k): str(v) for k, v in (r.get("cookies") or {}).items()}
            ok, err = validate_session_cookies(cookies)
            if not ok:
                self._qr = None
                return {"status": "failed", "error": f"扫码 cookie 不完整: {err}"}
            self.store.save(cookies)
            self._client = self._new_client(cookies)
            if not self._client.probe_session():
                self.store.clear()
                self._client = None
                self._qr = None
                return {"status": "failed",
                        "error": "扫码会话探活失败，请重试扫码"}
            user_id = str(r.get("user_id") or cookies.get("userId") or "")
            self._qr = None
            logger.info("xiaomi qr login confirmed, account=%s userId=%s",
                        self.account_id, user_id)
            return {"status": "confirmed", "user_id": user_id}

        if status in ("expired", "failed"):
            self._qr = None  # 终态：清会话，下次 start 重建
        return r

    def is_valid(self) -> bool:
        return self.store.has_session()

    # -- 长效会话（T36.5，机制 docs/xiaomi-cloud-api-research.md §7） --

    # 长效 serviceToken 主动续期阈值：serviceToken 短命（实测 ~15-30 分钟，
    # 重签后旧值 15 分钟并存窗口作废），心跳间隔 60s 粒度下 25 分钟阈值保证
    # 同步窗口永不踩 401。
    LONGTERM_REFRESH_MAX_AGE_SEC = 1500
    # 重签失败冷却（风控软拦/服务端波动期避免高频重试加深风控）
    LONGTERM_RETRY_COOLDOWN_SEC = 1800

    def _longterm_renewer(self, lt: dict[str, Any]) -> LongtermRenewer:
        return LongtermRenewer(
            pass_token=str(lt.get("pass_token") or ""),
            user_id=str(lt.get("user_id") or self.store.load_cookies().get("userId") or ""),
            c_user_id=str(lt.get("c_user_id") or ""),
            device_id=str(lt.get("device_id") or ""),
            account_service_token=str(lt.get("account_service_token") or ""),
            passport_slh=str(lt.get("passport_slh") or ""),
            passport_ph=str(lt.get("passport_ph") or ""),
        )

    def import_longterm(self, payload: dict[str, Any]) -> XiaomiClient:
        """导入 account 域长效票据并立即换发验证（T36.5）。

        payload 必填 passToken/userId；可选 cUserId/deviceId/accountServiceToken/
        passportSlh/passportPh。换发成功 = 长效票确认，签发的 serviceToken
        会话落盘并重建 client；失败抛 AuthExpiredError（含票型判定提示）。
        """
        payload = payload or {}
        pass_token = str(payload.get("passToken") or payload.get("pass_token") or "").strip()
        user_id = str(payload.get("userId") or payload.get("user_id") or "").strip()
        if not pass_token or not user_id:
            raise AuthExpiredError("导入失败：passToken 与 userId 均必填")
        renewer = self._longterm_renewer({
            "pass_token": pass_token,
            "user_id": user_id,
            "c_user_id": str(payload.get("cUserId") or payload.get("c_user_id") or ""),
            "device_id": str(payload.get("deviceId") or payload.get("device_id") or ""),
            "account_service_token": str(
                payload.get("accountServiceToken") or payload.get("account_service_token") or ""),
            "passport_slh": str(payload.get("passportSlh") or ""),
            "passport_ph": str(payload.get("passportPh") or ""),
        })
        try:
            cookies = renewer.renew()
        except LongtermSessionError as exc:
            if exc.code == TOKEN_DEAD:
                raise AuthExpiredError(
                    f"passToken 已失效（{exc}）。请从已登录 i.mi.com 的浏览器重新复制："
                    "F12 → Application → Cookies → account.xiaomi.com → passToken")
            raise AuthExpiredError(f"长效票据验证失败（{exc}），请稍后重试")
        self.store.save(cookies)
        self.store.save_longterm({
            "pass_token": pass_token,
            "user_id": user_id,
            "c_user_id": renewer.c_user_id,
            "device_id": renewer.device_id,
            "account_service_token": renewer.account_service_token,
            "passport_slh": renewer.passport_slh,
            "passport_ph": renewer.passport_ph,
            "source": "browser",
            "created_at": time.time(),
            "last_renew_at": time.time(),
            "rounds": 1,
        })
        self._client = self._new_client(cookies)
        self._client_file_mtime = self._auth_file_mtime()
        logger.info("xiaomi longterm session imported, account=%s userId=%s",
                    self.account_id, user_id)
        return self._client

    def try_longterm_renew(self) -> bool:
        """长效票静默重签：成功落盘新 serviceToken 并重建 client。

        无长效票 / 冷却期 / 换发失败均返回 False（调用方继续原失败路径）；
        TOKEN_DEAD 时清除长效票据块（票已死，保留会误导后续重试）。
        """
        lt = self.store.load_longterm()
        if not lt:
            return False
        now = time.time()
        if now < self._longterm_cooldown_until:
            return False
        try:
            cookies = self._longterm_renewer(lt).renew()
        except LongtermSessionError as exc:
            self._longterm_cooldown_until = now + self.LONGTERM_RETRY_COOLDOWN_SEC
            if exc.code == TOKEN_DEAD:
                lt["dead"] = True
                lt["dead_reason"] = str(exc)
                lt["dead_at"] = now
                self.store.save_longterm(lt)
                logger.warning(
                    "xiaomi longterm passToken dead, longterm disabled: %s", exc)
            else:
                logger.warning("xiaomi longterm renew transient failure: %s", exc)
            return False
        self.store.save(cookies)  # longterm 块由 save 自动保留
        lt = self.store.load_longterm() or lt
        lt["last_renew_at"] = now
        lt["rounds"] = int(lt.get("rounds") or 0) + 1
        self.store.save_longterm(lt)
        self._client = self._new_client(cookies)
        self._client_file_mtime = self._auth_file_mtime()
        self._longterm_cooldown_until = 0.0
        logger.info("xiaomi longterm renewed, account=%s rounds=%s",
                    self.account_id, lt.get("rounds"))
        return True

    def longterm_state(self) -> dict[str, Any] | None:
        """auth_status 透传：长效会话启用状态（UI 显示「免扫码模式」）。"""
        lt = self.store.load_longterm()
        if not lt:
            return None
        dead = bool(lt.get("dead"))
        return {
            "enabled": not dead,
            "source": str(lt.get("source") or ""),
            "rounds": int(lt.get("rounds") or 0),
            "last_renew_at": lt.get("last_renew_at"),
            "dead": dead,
            "dead_reason": str(lt.get("dead_reason") or "") if dead else "",
        }

    def _maybe_proactive_renew(self, client: XiaomiClient) -> None:
        """长效模式下 serviceToken 超龄时主动静默重签（心跳内调用，失败不影响结果）。"""
        if self.store.load_longterm() is None:
            return
        try:
            age = client.session_age_sec()
        except Exception:
            return
        if age < self.LONGTERM_REFRESH_MAX_AGE_SEC:
            return
        if self.try_longterm_renew():
            logger.info("xiaomi longterm proactive renew ok, account=%s age_was=%.0fs",
                        self.account_id, age)

    def is_valid(self) -> bool:
        return self.store.has_session()

    def invalidate(self) -> None:
        self.store.clear()
        self._client = None
        logger.info("xiaomi session invalidated, account_id=%s", self.account_id)

    # auth_probe / build_authenticator / start_qr_login / qr_login_status：
    # auth_probe 与 build_authenticator 继承 BaseAuthStrategy 默认实现
    # （小米无 CAS 语义、不支持自动重登 → NoAutoRelogin）；
    # 扫码链路在上方 T31.2 节覆写。


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

    def _auth_retry(self, fn: Callable[[], Any]) -> Any:
        """T28.5a：请求遇 AuthExpiredError 时重探活一次，成功则重试本次请求。

        覆盖「下载中途 serviceToken 轮替导致 401」场景：探活通过说明会话
        仍可用（T28.1 观察器已把轮替 cookie 捕获进 jar/磁盘），直接重试；
        探活也失败则上抛，由引擎中断本轮、daemon 标记失效。
        """
        try:
            return fn()
        except AuthExpiredError:
            # T36.5：长效模式下先静默重签再重探活一次
            self.auth_strategy.try_longterm_renew()
            self.auth_strategy.ensure_session(probe=True)  # 探活失败 → 上抛
            logger.info("xiaomi re-probe ok after auth error, retrying request once")
            return fn()

    # -- PhotoProvider 10 方法 --

    # 预防性续期阈值（T31.9 终版结论，秒）：passToken 换发特权为一次性——
    # 扫码确认交换（serviceLogin→STS）时即已消耗，此后任何重签（2 分钟龄/
    # 12 分钟龄、带不带新鲜签名 callback）都被风控拒绝（wb_ 引导地址/authStart
    # 安全验证，2026-11-20 NAS 真机四轮实验实锤），且扫码会话本身 ~15-35 分钟
    # 被服务端作废。预防性续签已无收益，设为 30 天等效停用；机制保留，冷却与
    # 401 被动重签仍生效（小米政策若放宽可自动恢复会话，30 分钟一次不骚扰）。
    SESSION_REFRESH_MAX_AGE_SEC = 2592000

    def heartbeat_check(self) -> bool:
        """对齐华为语义（T28.2b）：True 或抛 AuthExpiredError。

        daemon keepalive_step 只认「True=有效 / AuthExpiredError=失效」两分支；
        此前吞掉所有异常返回 False 会被 daemon 静默当作有效。网络类
        XiaomiAPIError 原样上抛，由 daemon 的 transient 分支处理（不计失效）。
        T31.9：探活成功且会话超龄时预防性静默续签（失败不影响本次结果，
        冷却机制防止高频重试触发风控升级）。
        """
        client = self.auth_strategy.get_session_if_present()
        if client is None:
            raise AuthExpiredError("小米会话未导入或无效")
        client.get_album_list()  # XiaomiAuthExpiredError（AuthExpiredError 子类）自然上抛
        if client.session_age_sec() > self.SESSION_REFRESH_MAX_AGE_SEC:
            if client.refresh_session():
                logger.info(
                    "xiaomi session proactively refreshed, account=%s age_was=%.0fs",
                    self.account_id, client.session_age_sec(),
                )
        # T36.5：长效模式下 serviceToken 超龄（25 分钟）时用 passToken 静默重签
        self.auth_strategy._maybe_proactive_renew(client)
        return True

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
        except AuthExpiredError:  # 含 XiaomiAuthExpiredError 子类
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
        photo_id = item.unique_id
        if not photo_id:
            raise XiaomiAPIError(0, "MediaItem.unique_id 为空，无法下载")

        def do() -> str:
            client = self._client()
            download_url, meta = client.get_download_meta(photo_id)
            return json.dumps({"url": download_url, "meta": meta})

        return self._auth_retry(do)

    def download_to_part(self, url: str, part_path: Path) -> Any:
        """解析 get_download_url 返回的 JSON 串 → POST 流式写 part（断点续传 T28.4）。

        part_path 已有部分内容时带 Range 续传（206 追加）；服务端不支持 Range
        时全量覆盖；416 删 part 重下。sha1 校验与最终落位由引擎 sync 层负责。
        """
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

        def do() -> Any:
            client = self._client()
            outcome = client.download_to_file(download_url, meta, part_path, resume=True)
            logger.debug("xiaomi download %s: %s", part_path.name, outcome)
            # 对齐引擎 DownloadResult 契约（hwcloudpd.client.DownloadResult，
            # T31.11）：bytes_written 参与大小一致性校验、sha256_hex 记入
            # 下载账本；md5 仅在云端校验和为 32 位时比对（小米是 sha1，不提供）
            size = Path(part_path).stat().st_size
            return type("XiaomiDownloadResult", (), {
                "success": True,
                "size": size,
                "bytes_written": size,
                "sha256_hex": self._sha256_of(part_path),
                "md5_hex": "",
                "part_path": part_path,
                "error": None,
            })()

        return self._auth_retry(do)

    @staticmethod
    def _sha256_of(path: Path) -> str:
        """流式计算文件 sha256（引擎账本 local_sha256 用）。"""
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

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


# ---------------------------------------------------------------------------
# 能力声明 + 工厂（PLATFORMS 注册用）
# ---------------------------------------------------------------------------

# 小米能力矩阵（T26 调研结论 + T31 扫码）：
#   ✓ supports_curl_import  cookie 导入通道（保留）
#   ✓ supports_qr_login     扫码登录（T31，推荐默认通道）
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
    supports_qr_login=True,
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
