#!/usr/bin/env python3
"""AlbumSync 运行时：在服务进程内组装 hwcloudpd 引擎组件。

路径布局（TRIM_PKGVAR，fnOS 数据目录）：
  config.json        Web 界面持久化配置（本模块读写，chmod 600）
  auth.json          华为云会话凭据（AuthManager）
  curl.txt           浏览器会话导入文件（AuthManager，热重载）
  cas_cookies.lwp / cas_state.json / cas_pending_2fa.json  CAS 认证状态
  state.db           同步记录数据库（WAL，线程安全）
  health.json        daemon 健康快照（SyncDaemon.write_health）
  logs/sync.log      引擎日志（RotatingFileHandler）
  photos/            默认照片存储目录（可在配置中改为共享目录绝对路径）

Web 化二次验证：HuaweiCasAuthenticator.login(interactive=False,
prompt_fn/output_fn 注入) 配合 patches/0001、0002（非交互自动发码），
实现「网页登录 → 返回验证通道 → 提交 6 位验证码」的两段式 API。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import threading
import time
from collections import deque
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from hwcloudpd.auth import AuthManager
from hwcloudpd.cas_auth import HuaweiCasAuthenticator
from hwcloudpd.client import HuaweiGalleryClient
from hwcloudpd.config import parse_date_bound
from hwcloudpd.cron import CronSchedule
from hwcloudpd.daemon import SyncDaemon
from hwcloudpd.models import (
    AuthExpiredError,
    CaptchaRequiredError,
    InvalidCredentialsError,
    SyncConfig,
    TwoFactorRequiredError,
)
from hwcloudpd.notifier import Notifier
from hwcloudpd.store import StateStore
from hwcloudpd.sync import SyncEngine

logger = logging.getLogger("albumsync.runtime")

APP_NAME = "AlbumSync"
APP_VERSION = os.environ.get("TRIM_APPVER") or "0.1.0"

# Web 配置 → SyncConfig 的默认值（与引擎默认一致）
DEFAULT_CONFIG: dict[str, Any] = {
    "username": "",
    "password": "",
    "photos_dir": "",  # 空则回退 <pkgvar>/photos
    "custom_photos_dirs": [],  # 手动登记的可选目录清单（探测可写才入库）
    "folder_structure": "{:%Y/%m/%d}",
    "timezone": "Asia/Shanghai",
    "albums": [],
    "exclude_albums": [],
    "photo_size": "original",  # original | medium | thumb
    "file_match_policy": "name-size-dedup-with-suffix",  # 或 name-id7
    "live_photo_mov_filename_policy": "none",  # none | suffix | original
    "set_exif_datetime": False,
    "xmp_sidecar": False,
    "skip_videos": False,
    "skip_photos": False,
    "skip_live_photos": False,
    "skip_bursts": False,
    "only_favorites": False,
    "created_after": None,  # "YYYY-MM-DD" 或 None
    "created_before": None,
    "min_size": None,  # 字节
    "max_size": None,
    "recent": None,
    "until_found": None,
    "auto_delete": False,
    "delete_after_download": False,
    "keep_cloud_recent_days": None,
    "download_concurrency": 2,
    "page_size": 100,
    "request_delay_ms": 120,
    "cron": "0 3 * * *",
    "watch_interval": None,  # 秒；与 cron 二选一，均空时 daemon 兜底 2h
    "keepalive_interval": 60,
    "run_on_startup": True,
    "full_scan_interval_hours": 168.0,
    "webhook_url": None,
    "telegram_chat_id": None,
    "notification_script": None,
    "log_level": "INFO",
}

_BOOL_KEYS = (
    "set_exif_datetime", "xmp_sidecar", "skip_videos", "skip_photos",
    "skip_live_photos", "skip_bursts", "only_favorites", "auto_delete",
    "delete_after_download", "run_on_startup",
)
_STR_KEYS = (
    "username", "password", "photos_dir", "folder_structure", "timezone",
    "photo_size", "file_match_policy", "live_photo_mov_filename_policy",
    "webhook_url", "telegram_chat_id", "notification_script", "log_level",
)
_OPT_INT_KEYS = (
    "min_size", "max_size", "recent", "until_found",
    "keep_cloud_recent_days", "watch_interval",
)
_PASSWORD_MASK = "******"
_PASSWORD_CLEAR = "__clear__"


def _opt_number(value: Any, key: str, *, minimum: float, maximum: float,
                integer: bool = True) -> tuple[bool, str]:
    """校验可空数值字段。返回 (ok, 错误信息)。"""
    if value is None or value == "":
        return True, ""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False, f"{key} 必须为数字"
    if not (minimum <= value <= maximum):
        return False, f"{key} 超出范围 [{minimum}, {maximum}]"
    if integer and int(value) != value:
        return False, f"{key} 必须为整数"
    return True, ""


def validate_config(data: dict[str, Any]) -> str | None:
    """校验 Web 配置。返回错误描述或 None（合法）。"""
    for key in _STR_KEYS:
        if key in data and data[key] is not None and not isinstance(data[key], str):
            return f"{key} 必须为字符串"
    for key in _BOOL_KEYS:
        if key in data and not isinstance(data[key], bool):
            return f"{key} 必须为布尔值"

    if data.get("photo_size") not in (None, "original", "medium", "thumb"):
        return "photo_size 仅支持 original / medium / thumb"
    if data.get("file_match_policy") not in (None, "name-size-dedup-with-suffix", "name-id7"):
        return "file_match_policy 仅支持 name-size-dedup-with-suffix / name-id7"
    if data.get("live_photo_mov_filename_policy") not in (None, "none", "suffix", "original"):
        return "live_photo_mov_filename_policy 仅支持 none / suffix / original"
    if data.get("log_level") not in (None, "DEBUG", "INFO", "WARNING", "ERROR"):
        return "log_level 仅支持 DEBUG / INFO / WARNING / ERROR"
    if data.get("folder_structure") is not None and not str(data["folder_structure"]).strip():
        return "folder_structure 不能为空"

    tz = data.get("timezone")
    if tz:
        try:
            from zoneinfo import ZoneInfo
            ZoneInfo(str(tz))
        except Exception:
            return f"timezone 无效: {tz}"

    cron = data.get("cron")
    if cron not in (None, ""):
        try:
            CronSchedule.parse(str(cron))
        except Exception as exc:
            return f"cron 表达式无效: {exc}"

    for key, minimum, maximum in (
        ("download_concurrency", 1, 8),
        ("page_size", 10, 500),
        ("request_delay_ms", 0, 10000),
        ("keepalive_interval", 15, 3600),
    ):
        ok, err = _opt_number(data.get(key), key, minimum=minimum, maximum=maximum)
        if not ok:
            return err

    for key in _OPT_INT_KEYS:
        ok, err = _opt_number(data.get(key), key, minimum=0, maximum=10**12)
        if not ok:
            return err
    ok, err = _opt_number(data.get("full_scan_interval_hours"), "full_scan_interval_hours",
                          minimum=0.1, maximum=24 * 365, integer=False)
    if not ok:
        return err

    for key in ("created_after", "created_before"):
        value = data.get(key)
        if value in (None, ""):
            continue
        if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            return f"{key} 需为 YYYY-MM-DD 格式或留空"
        try:
            parse_date_bound(value, str(tz or DEFAULT_CONFIG["timezone"]))
        except Exception as exc:
            return f"{key} 无效: {exc}"

    webhook = data.get("webhook_url")
    if webhook:
        if not re.fullmatch(r"https?://[^\s]+", str(webhook)):
            return "webhook_url 需为 http(s):// 开头的 URL"

    for key in ("albums", "exclude_albums"):
        value = data.get(key)
        if value is None:
            continue
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            return f"{key} 必须为字符串数组"

    photos_dir = data.get("photos_dir")
    if photos_dir is not None and str(photos_dir).strip():
        pd = str(photos_dir).strip()
        if not os.path.isabs(pd):
            return "photos_dir 必须为绝对路径（如 /vol1/1000/photos 或共享目录路径）"
        # 可写性预检：沿目录树向上找最近存在的祖先做写权限探测。
        # fnOS 通过内核级 trim_acl 授权（应用设置→访问权限），未授权目录
        # 此处即拦截，避免等到运行时才报 PermissionError。
        probe = Path(pd)
        while not probe.exists():
            parent = probe.parent
            if parent == probe:
                probe = None
                break
            probe = parent
        if probe is not None and not os.access(probe, os.W_OK):
            return (
                f"photos_dir 不可写: {pd}"
                "（可能未在 fnOS「系统设置→应用→相册同步→应用设置→访问权限」"
                "中授权该目录；授权后立即生效，无需重启应用）"
            )

    # 手动登记的可选目录清单：清洗（去空/去重）+ 绝对路径校验（就地写回，
    # save_config 保存的是同一 dict，清洗结果随全量保存持久化）
    custom_dirs = data.get("custom_photos_dirs")
    if custom_dirs is not None:
        if not isinstance(custom_dirs, list) or not all(isinstance(v, str) for v in custom_dirs):
            return "custom_photos_dirs 必须为字符串数组"
        cleaned: list[str] = []
        for v in custom_dirs:
            vs = str(v).strip()
            if not vs:
                continue
            if not os.path.isabs(vs):
                return f"custom_photos_dirs 含非绝对路径: {vs}"
            if vs not in cleaned:
                cleaned.append(vs)
        data["custom_photos_dirs"] = cleaned

    return None


def report_to_dict(report: Any) -> dict[str, Any]:
    """SyncReport → 结构化 dict。"""
    return {
        "scanned": report.scanned,
        "downloaded": report.downloaded,
        "skipped_existing": report.skipped_existing,
        "skipped_filtered": report.skipped_filtered,
        "deleted_local": report.deleted_local,
        "deleted_cloud": report.deleted_cloud,
        "failed": report.failed,
        "duration_sec": round(report.duration_sec, 2),
        "summary_text": report.summary_text(),
    }


class AppConfig:
    """config.json 读写 + SyncConfig 映射。"""

    def __init__(self, path: Path, pkgvar: Path) -> None:
        self.path = path
        self.pkgvar = pkgvar

    def load(self) -> dict[str, Any]:
        data = dict(DEFAULT_CONFIG)
        try:
            stored = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(stored, dict):
                for key in DEFAULT_CONFIG:
                    if key in stored:
                        data[key] = stored[key]
        except FileNotFoundError:
            pass
        except Exception as exc:
            logger.warning("读取 config.json 失败，使用默认值: %s", exc)
        if not str(data.get("photos_dir") or "").strip():
            data["photos_dir"] = str(self.pkgvar / "photos")
        return data

    def save(self, data: dict[str, Any]) -> None:
        payload = {key: data.get(key, DEFAULT_CONFIG[key]) for key in DEFAULT_CONFIG}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f".config.{os.getpid()}.tmp")
        tmp.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)  # 含账号密码，限制访问
        except OSError:
            pass

    def to_sync_config(self, data: dict[str, Any] | None = None, *,
                       dry_run: bool = False) -> SyncConfig:
        data = data or self.load()
        tz = str(data.get("timezone") or DEFAULT_CONFIG["timezone"])
        created_after = data.get("created_after") or None
        created_before = data.get("created_before") or None
        return SyncConfig(
            directory=Path(str(data["photos_dir"])),
            config_dir=self.pkgvar,
            username=(str(data.get("username") or "").strip() or None),
            password=(str(data.get("password") or "") or None),
            folder_structure=str(data.get("folder_structure") or DEFAULT_CONFIG["folder_structure"]),
            timezone=tz,
            albums=[str(a) for a in (data.get("albums") or [])],
            exclude_albums=[str(a) for a in (data.get("exclude_albums") or [])],
            photo_size=str(data.get("photo_size") or "original"),
            file_match_policy=str(data.get("file_match_policy") or "name-size-dedup-with-suffix"),
            live_photo_mov_filename_policy=str(data.get("live_photo_mov_filename_policy") or "none"),
            set_exif_datetime=bool(data.get("set_exif_datetime")),
            xmp_sidecar=bool(data.get("xmp_sidecar")),
            skip_videos=bool(data.get("skip_videos")),
            skip_photos=bool(data.get("skip_photos")),
            skip_live_photos=bool(data.get("skip_live_photos")),
            skip_bursts=bool(data.get("skip_bursts")),
            only_favorites=bool(data.get("only_favorites")),
            created_after_ms=parse_date_bound(created_after, tz) if created_after else None,
            created_before_ms=parse_date_bound(created_before, tz, end_of_day=True) if created_before else None,
            min_size=data.get("min_size"),
            max_size=data.get("max_size"),
            recent=data.get("recent"),
            until_found=data.get("until_found"),
            auto_delete=bool(data.get("auto_delete")),
            delete_after_download=bool(data.get("delete_after_download")),
            keep_cloud_recent_days=data.get("keep_cloud_recent_days"),
            dry_run=dry_run,
            download_concurrency=int(data.get("download_concurrency") or 2),
            page_size=int(data.get("page_size") or 100),
            request_delay_ms=int(data.get("request_delay_ms") or 120),
            cron=(str(data["cron"]).strip() or None) if data.get("cron") else None,
            watch_interval=data.get("watch_interval"),
            keepalive_interval=int(data.get("keepalive_interval") or 60),
            run_on_startup=bool(data.get("run_on_startup")),
            full_scan_interval_hours=data.get("full_scan_interval_hours"),
            webhook_url=(str(data["webhook_url"]).strip() or None) if data.get("webhook_url") else None,
            telegram_chat_id=(str(data["telegram_chat_id"]).strip() or None) if data.get("telegram_chat_id") else None,
            notification_script=(str(data["notification_script"]).strip() or None) if data.get("notification_script") else None,
            log_level=str(data.get("log_level") or "INFO"),
        )


class AppRuntime:
    """组装引擎组件并向 REST 层暴露操作。

    生命周期：server.py 启动时创建（后台线程运行 SyncDaemon），
    配置保存后 restart_daemon() 热重建，进程退出时 stop()。
    """

    def __init__(self, pkgvar: Path) -> None:
        self.pkgvar = Path(pkgvar).resolve()
        (self.pkgvar / "logs").mkdir(parents=True, exist_ok=True)
        (self.pkgvar / "photos").mkdir(parents=True, exist_ok=True)
        self.app_config = AppConfig(self.pkgvar / "config.json", self.pkgvar)
        self.started_at = time.time()

        cfg = self.app_config.load()
        self._setup_logging(str(cfg.get("log_level") or "INFO"))

        self.auth_manager = AuthManager(self.pkgvar)
        self.client = HuaweiGalleryClient(self.auth_manager)
        self.notifier = Notifier(
            webhook_url=cfg.get("webhook_url") or None,
            telegram_chat_id=cfg.get("telegram_chat_id") or None,
            notification_script=cfg.get("notification_script") or None,
        )
        self.store = StateStore(self.pkgvar / "state.db")

        self._daemon: SyncDaemon | None = None
        self._daemon_thread: threading.Thread | None = None
        self._runtime_lock = threading.RLock()  # 串行化 daemon 重建
        self._login_lock = threading.Lock()
        self._dry_lock = threading.Lock()
        self._dry_state: dict[str, Any] = {
            "running": False, "report": None, "error": None,
            "started_at": None, "finished_at": None,
        }
        self._start_daemon(cfg)
        logger.info("AppRuntime initialized: pkgvar=%s version=%s", self.pkgvar, APP_VERSION)

    # ---------- 日志 ----------

    def _log_paths(self) -> tuple[Path, Path]:
        return self.pkgvar / "logs" / "sync.log", self.pkgvar / "logs" / "info.log"

    def _setup_logging(self, level_name: str) -> None:
        sync_log, info_log = self._log_paths()
        root = logging.getLogger()
        root.setLevel(getattr(logging, level_name.upper(), logging.INFO))
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler = RotatingFileHandler(
            sync_log, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(fmt)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(fmt)
        # 幂等：关闭并替换旧 handler（配置保存后重建时避免重复输出与句柄泄漏）
        for old in list(root.handlers):
            root.removeHandler(old)
            try:
                old.close()
            except Exception:
                pass
        root.addHandler(file_handler)
        root.addHandler(stream_handler)
        self._apply_info_log_alias(info_log)

    @staticmethod
    def _apply_info_log_alias(info_log: Path) -> None:
        """shell 层 info.log 由 cmd/main 负责；此处仅确保目录存在。"""
        info_log.parent.mkdir(parents=True, exist_ok=True)

    # ---------- daemon ----------

    def _build_authenticator(self, cfg: dict[str, Any],
                             two_fa_code: str | None = None) -> HuaweiCasAuthenticator:
        return HuaweiCasAuthenticator(
            self.auth_manager,
            username=(str(cfg.get("username") or "").strip() or None),
            password=(str(cfg.get("password") or "") or None),
            two_fa_code=two_fa_code,
            login_timeout_sec=30,
        )

    def _start_daemon(self, cfg: dict[str, Any]) -> None:
        sync_cfg = self.app_config.to_sync_config(cfg)
        authenticator = self._build_authenticator(cfg)
        daemon = SyncDaemon(
            sync_cfg, self.auth_manager, self.client, self.store, self.notifier,
            authenticator=authenticator if authenticator.can_attempt_login else None,
        )
        daemon.write_health()
        thread = threading.Thread(
            target=self._run_daemon, args=(daemon,), name="sync-daemon", daemon=True
        )
        self._daemon, self._daemon_thread = daemon, thread
        thread.start()
        logger.info("SyncDaemon started (cron=%s watch_interval=%s)", sync_cfg.cron, sync_cfg.watch_interval)

    def _run_daemon(self, daemon: SyncDaemon) -> None:
        try:
            asyncio.run(daemon.run_forever())
        except Exception:
            logger.exception("sync daemon crashed")

    def restart_daemon(self) -> None:
        """配置保存后热重建：停旧 daemon → 重建（新 SyncConfig/Notifier）。"""
        with self._runtime_lock:
            old_daemon, old_thread = self._daemon, self._daemon_thread
            if old_daemon is not None:
                old_daemon.request_stop()
            if old_thread is not None and old_thread.is_alive():
                # 5s 上限：daemon 的 sleep/等待均可中断，空闲时秒退；若正在执行同步
                # 周期则不等它跑完（state.db 为 WAL 事务原子提交，下载中断不影响一致性，
                # 下次扫描按大小/校验策略自愈）。20s 会超出 fnOS 停止等待窗口导致
                # 卸载/停止被平台判失败（0.1.6 实测：心跳 sync 中停止耗时 21s）。
                old_thread.join(timeout=5)
            cfg = self.app_config.load()
            self._setup_logging(str(cfg.get("log_level") or "INFO"))
            self.notifier = Notifier(
                webhook_url=cfg.get("webhook_url") or None,
                telegram_chat_id=cfg.get("telegram_chat_id") or None,
                notification_script=cfg.get("notification_script") or None,
            )
            self._start_daemon(cfg)

    def stop(self) -> None:
        with self._runtime_lock:
            if self._daemon is not None:
                self._daemon.request_stop()
            if self._daemon_thread is not None and self._daemon_thread.is_alive():
                # 同 restart_daemon：5s 上限，避免超出 fnOS 停止等待窗口（0.1.6 实测教训）
                self._daemon_thread.join(timeout=5)
            try:
                self.store.close()
            except Exception:
                pass
            logger.info("AppRuntime stopped")

    # ---------- 状态 ----------

    def _read_health(self) -> dict[str, Any]:
        try:
            data = json.loads((self.pkgvar / "health.json").read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def status_snapshot(self) -> dict[str, Any]:
        health = self._read_health()
        daemon, thread = self._daemon, self._daemon_thread
        last_report = getattr(daemon, "_last_report", None) if daemon else None
        try:
            store_counts = self.store.count_by_status()
        except Exception as exc:
            logger.warning("count_by_status failed: %s", exc)
            store_counts = {}
        return {
            "app": APP_NAME,
            "version": APP_VERSION,
            "ok": bool(health.get("ok")),
            "auth_valid": bool(health.get("auth_valid")),
            "last_heartbeat_at": health.get("last_heartbeat_at"),
            "last_sync_at": health.get("last_sync_at"),
            "last_full_scan_at": health.get("last_full_scan_at"),
            "last_error": health.get("last_error") or "",
            "last_report_text": health.get("last_report"),
            "last_report": report_to_dict(last_report) if last_report else None,
            "daemon_running": bool(thread and thread.is_alive()),
            "uptime_sec": round(time.time() - self.started_at, 1),
            "store_counts": store_counts,
            "updated_at": health.get("updated_at"),
            "auth": self.auth_status(),
        }

    def auth_status(self) -> dict[str, Any]:
        session = None
        try:
            session = self.auth_manager.get_session_if_present()
        except Exception as exc:
            logger.warning("get_session_if_present failed: %s", exc)
        try:
            authenticator = self._build_authenticator(self.app_config.load())
            pending = authenticator._load_pending_2fa()
            has_tgt = authenticator._has_cas_tgt()
            credentials = authenticator.has_credentials
        except Exception as exc:
            logger.warning("authenticator probe failed: %s", exc)
            pending, has_tgt, credentials = None, False, False
        return {
            "has_session": session is not None,
            "user_id": getattr(session, "user_id", "") or "" if session else "",
            "login_sec_level": (session.cookies.get("loginSecLevel") if session else None),
            "session_updated_at": getattr(session, "updated_at", None) if session else None,
            "has_cas_tgt": has_tgt,
            "credentials_configured": credentials,
            "pending_2fa": (
                {
                    "flow": pending.get("flow"),
                    "channels": pending.get("channels") or [],
                    "created_at": pending.get("created_at"),
                }
                if pending else None
            ),
        }

    # ---------- 同步操作 ----------

    def trigger_sync(self) -> dict[str, Any]:
        daemon, thread = self._daemon, self._daemon_thread
        if not (daemon and thread and thread.is_alive()):
            return {"status": "error", "message": "同步守护进程未运行，请重启应用"}
        daemon._immediate_sync_event.set()
        return {"status": "ok", "message": "已触发立即同步（登录态有效后自动执行）"}

    def start_dry_run(self) -> dict[str, Any]:
        if self._dry_state.get("running"):
            return {"status": "busy", "message": "已有预览任务在进行中"}
        if not self._dry_lock.acquire(blocking=False):
            return {"status": "busy", "message": "已有预览任务在进行中"}

        def work() -> None:
            try:
                cfg = self.app_config.to_sync_config(self.app_config.load(), dry_run=True)
                engine = SyncEngine(cfg, self.client, self.store)
                report = engine.run_once()
                self._dry_state["report"] = report_to_dict(report)
                self._dry_state["error"] = None
                logger.info("Dry-run completed: %s", report.summary_text())
            except AuthExpiredError as exc:
                self._dry_state["error"] = f"登录态失效，请先完成认证: {exc}"
            except Exception as exc:
                logger.exception("dry-run failed")
                self._dry_state["error"] = f"预览失败: {exc}"
            finally:
                self._dry_state["running"] = False
                self._dry_state["finished_at"] = time.time()
                self._dry_lock.release()

        self._dry_state.update(
            {"running": True, "report": None, "error": None, "started_at": time.time()}
        )
        threading.Thread(target=work, name="dry-run", daemon=True).start()
        return {"status": "ok", "message": "dry-run 预览已开始"}

    def dry_run_status(self) -> dict[str, Any]:
        return dict(self._dry_state)

    def tail_logs(self, lines: int = 200) -> list[str]:
        lines = max(1, min(int(lines), 1000))
        sync_log, _ = self._log_paths()
        try:
            with open(sync_log, "r", encoding="utf-8", errors="replace") as fh:
                return list(deque(fh, maxlen=lines))
        except FileNotFoundError:
            return []

    # ---------- 认证 ----------

    def web_login(self) -> dict[str, Any]:
        """账号密码登录（非交互）。触发 2FA 时返回验证通道列表。"""
        if not self._login_lock.acquire(blocking=False):
            return {"status": "busy", "message": "已有登录/验证流程进行中，请稍候"}
        try:
            cfg = self.app_config.load()
            authenticator = self._build_authenticator(cfg)
            if not authenticator.has_credentials:
                return {"status": "error", "message": "请先在「同步设置」中填写华为账号与密码"}
            lines: list[str] = []
            try:
                session = authenticator.login(
                    interactive=False, prompt_fn=lambda _p: "", output_fn=lines.append
                )
            except TwoFactorRequiredError as exc:
                pending = authenticator._load_pending_2fa()
                return {
                    "status": "2fa_required",
                    "message": str(exc) or "需要二次验证，验证码已发送",
                    "channels": (pending or {}).get("channels") or [],
                    "output": lines,
                }
            except (InvalidCredentialsError, CaptchaRequiredError, AuthExpiredError) as exc:
                return {"status": "error", "message": str(exc), "output": lines}
            except Exception as exc:
                return {"status": "error", "message": f"登录失败: {exc}", "output": lines}
            return self._post_login_success(session, lines)
        finally:
            self._login_lock.release()

    def submit_2fa(self, code: str) -> dict[str, Any]:
        """提交 6 位二次验证码，恢复 pending 2FA 流程。"""
        code = str(code or "").strip()
        if not re.fullmatch(r"\d{6}", code):
            return {"status": "error", "message": "验证码须为 6 位数字"}
        if not self._login_lock.acquire(blocking=False):
            return {"status": "busy", "message": "已有登录/验证流程进行中，请稍候"}
        try:
            cfg = self.app_config.load()
            authenticator = self._build_authenticator(cfg, two_fa_code=code)
            lines: list[str] = []
            try:
                session = authenticator.login(
                    interactive=False, prompt_fn=lambda _p: "", output_fn=lines.append
                )
            except TwoFactorRequiredError as exc:
                return {
                    "status": "2fa_required",
                    "message": f"验证码校验未通过: {exc}",
                    "channels": (authenticator._load_pending_2fa() or {}).get("channels") or [],
                    "output": lines,
                }
            except (InvalidCredentialsError, CaptchaRequiredError, AuthExpiredError) as exc:
                return {"status": "error", "message": str(exc), "output": lines}
            except Exception as exc:
                return {"status": "error", "message": f"二次验证失败: {exc}", "output": lines}
            return self._post_login_success(session, lines)
        finally:
            self._login_lock.release()

    def _post_login_success(self, session: Any, lines: list[str]) -> dict[str, Any]:
        try:
            self.client.heartbeat_check()
        except Exception as exc:
            return {"status": "error", "message": f"登录成功但会话校验失败: {exc}", "output": lines}
        return {
            "status": "ok",
            "message": "登录成功（信任设备生效后，会话过期将静默自动重登）",
            "user_id": getattr(session, "user_id", "") or "",
            "output": lines,
        }

    def import_curl(self, curl_text: str) -> dict[str, Any]:
        text = str(curl_text or "").strip()
        if not text:
            return {"status": "error", "message": "cURL 内容为空"}
        try:
            session = self.auth_manager.import_curl_text(text)
        except Exception as exc:
            return {"status": "error", "message": f"导入失败: {exc}"}
        return {
            "status": "ok",
            "message": "cURL 会话导入成功（daemon 将在 15 秒内热重载并校验）",
            "user_id": getattr(session, "user_id", "") or "",
        }

    # ---------- 相册 ----------

    def list_albums(self) -> list[dict[str, Any]]:
        albums = self.client.list_albums(include_stats=True)
        return [
            {
                "album_id": a.album_id,
                "name": a.name,
                "img_num": a.img_num,
                "video_num": a.video_num,
                "hide": bool(a.hide),
                "is_virtual": bool(a.is_virtual),
                "is_recycle": bool(a.is_recycle),
            }
            for a in albums
        ]

    # ---------- 配置 ----------

    def get_config(self) -> dict[str, Any]:
        data = self.app_config.load()
        if data.get("password"):
            data["password"] = _PASSWORD_MASK
        return data

    def save_config(self, incoming: dict[str, Any]) -> dict[str, Any]:
        current = self.app_config.load()
        data = {key: current[key] for key in DEFAULT_CONFIG}
        for key in DEFAULT_CONFIG:
            if key not in incoming:
                continue
            if key == "password":
                value = incoming["password"]
                if value == _PASSWORD_CLEAR:
                    data["password"] = ""
                elif value in (_PASSWORD_MASK, "", None):
                    pass  # 保留已存密码
                else:
                    data["password"] = str(value)
                continue
            data[key] = incoming[key]

        error = validate_config(data)
        if error:
            return {"status": "error", "message": error}
        self.app_config.save(data)
        self.restart_daemon()
        logger.info("config saved; daemon restarted")
        result = self.get_config()
        return {"status": "ok", "message": "配置已保存并热生效", "config": result}

    def probe_photos_dirs(self) -> list[dict[str, Any]]:
        """探测 fnOS 共享区中当前运行用户可访问的目录，供照片存储目录下拉选择。

        fnOS 未提供「读取本应用被授权目录清单」的 API（授权存于内核
        trim_acl），因此采用枚举 + os.access 实时探测：fnOS 的授权在
        内核层按路径生效，用户在「应用设置→访问权限」添加目录后无需
        重启，本探测即可识别（实测一致）。
        """
        candidates: list[str] = []

        # 0) 用户手动登记的目录（config.json 持久化；每次调用实时重新探测，
        #    fnOS 授权被撤销后再次展开弹窗即显示未授权并禁选）
        custom_set: set[str] = set()
        customs = self.app_config.load().get("custom_photos_dirs") or []
        for p in customs:
            if isinstance(p, str) and p.strip():
                ps = p.strip()
                if ps not in custom_set:
                    custom_set.add(ps)
                    candidates.append(ps)

        # 1) 官方 data-share 目录（config/resource 声明，环境变量由 fnOS 注入）
        env_paths = os.environ.get("TRIM_DATA_SHARE_PATHS", "")
        for part in re.split(r"[;:]", env_paths):
            part = part.strip()
            if part and os.path.isdir(part):
                candidates.append(part)

        # 2) 枚举 /vol1 共享区两级（跳过 @appdata/@appshare 等系统目录与隐藏项）
        vol_root = Path("/vol1")
        if vol_root.is_dir():
            try:
                for entry in vol_root.iterdir():
                    if entry.name.startswith(("@", ".")):
                        continue
                    try:
                        if not entry.is_dir():
                            continue
                    except OSError:
                        continue
                    candidates.append(str(entry))
                    try:
                        for sub in entry.iterdir():
                            if sub.name.startswith((".", "@")):
                                continue
                            try:
                                if sub.is_dir():
                                    candidates.append(str(sub))
                            except OSError:
                                continue
                    except OSError:
                        pass
            except OSError:
                pass

        # 去重保序 + 实时权限探测（os.access 每次都是真实系统调用，无缓存）
        seen: set[str] = set()
        result: list[dict[str, Any]] = []
        for path in candidates:
            if path in seen:
                continue
            seen.add(path)
            result.append({
                "path": path,
                "readable": os.access(path, os.R_OK),
                "writable": os.access(path, os.W_OK),
                "custom": path in custom_set,
            })
        # 可写目录排前，其余按路径排序
        result.sort(key=lambda item: (not item["writable"], item["path"]))
        return result

    def probe_single_dir(self, path: str) -> dict[str, Any]:
        """探测单个目录的当前访问权限（供前端对用户手输路径实时校验）。

        用户共享目录对应用通常只有 x 无 r（无法枚举父目录内容），
        但对已知路径 os.access 探测完全可行，与 fnOS 授权状态实时一致。
        """
        p = os.path.normpath(str(path or "").strip())  # 尾斜杠等归一，避免同目录重复登记
        if not p or not os.path.isabs(p):
            return {"path": p, "exists": False, "readable": False,
                    "writable": False, "registered": False, "error": "需为绝对路径"}
        registered = p in (self.app_config.load().get("custom_photos_dirs") or [])
        return {
            "path": p,
            "exists": os.path.isdir(p),
            "readable": os.access(p, os.R_OK),
            "writable": os.access(p, os.W_OK),
            "registered": registered,
        }

    def add_custom_photos_dir(self, path: str) -> dict[str, Any]:
        """登记手输路径到「可选目录」清单：探测可写才入库（去重）。

        仅写 config.json 的 custom_photos_dirs 单字段、不重启 daemon。
        注意读取原始 stored dict（而非 AppConfig.load() 的回退结果）再保存，
        避免把 photos_dir 的 pkgvar 回退值固化进 config.json。
        """
        probe = self.probe_single_dir(path)
        p = probe["path"]
        if not probe["exists"]:
            return {"status": "error", "message": f"目录不存在: {p}"}
        if not probe["writable"]:
            return {
                "status": "error",
                "message": (
                    f"目录不可写: {p}（未在 fnOS「系统设置→应用→相册同步→"
                    "应用设置→访问权限」中授权，或仅只读；授权后立即生效）"
                ),
            }
        try:
            stored = json.loads(self.app_config.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            stored = {}
        if not isinstance(stored, dict):
            stored = {}
        customs = stored.get("custom_photos_dirs")
        if not isinstance(customs, list):
            customs = []
        customs = [str(v) for v in customs if isinstance(v, str) and v.strip()]
        if p in customs:
            return {"status": "ok", "message": "该目录已在可选目录清单中",
                    "custom_photos_dirs": customs}
        customs.append(p)
        stored["custom_photos_dirs"] = customs
        self.app_config.save(stored)
        logger.info("custom photos dir added: %s", p)
        return {"status": "ok", "message": "已添加到可选目录",
                "custom_photos_dirs": customs}
