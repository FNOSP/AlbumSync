#!/usr/bin/env python3
"""AlbumSync 运行时：在服务进程内组装 hwcloudpd 引擎组件（多账号版）。

pkgvar 路径布局（TRIM_PKGVAR，fnOS 数据目录）：
  config.json              v2 配置：{version, settings, accounts[]}（chmod 600）
  config.json.bak-v1       v1→v2 一次性迁移的原始备份
  accounts/<id>/           每账号独立目录（AuthManager/CAS/state.db/health.json 全部隔离）
    auth.json / curl.txt / cas_* / state.db / health.json
    logs/sync.log          该账号引擎日志（RotatingFileHandler，按账号上下文过滤）
  photos/<id>/             photos_dir 为空时的默认照片存储目录
  logs/service.log         服务级日志（跨账号，含调度器）

设计要点（docs/multi-account-multi-platform-architecture.md）：
- AccountRuntime = 单账号作用域运行时（锁、daemon、日志均收窄到账号内）
- 引擎目录隔离零改动：AuthManager(config_dir=账号目录)、SyncConfig.config_dir=账号目录
- 跨账号同步串行：_SerialSyncGate 包装 engine.run_once（全局闸门 + 热重载取消）
- v1→v2 迁移器 fail-fast 回滚（见 migrate_config_v1_to_v2）

Web 化二次验证：HuaweiCasAuthenticator.login(interactive=False,
prompt_fn/output_fn 注入) 配合 patches/0001、0002（非交互自动发码），
实现「网页登录 → 返回验证通道 → 提交 6 位验证码」的两段式 API。
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import secrets
import shutil
import threading
import time
from collections import deque
from contextvars import ContextVar
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Iterator

from hwcloudpd.auth import AuthManager
from hwcloudpd.config import parse_date_bound
from hwcloudpd.cron import CronSchedule
from hwcloudpd.daemon import SyncDaemon
from hwcloudpd.models import (
    AuthExpiredError,
    CaptchaRequiredError,
    InvalidCredentialsError,
    SyncConfig,
    SyncReport,
    TwoFactorRequiredError,
)
from hwcloudpd.notifier import Notifier
from hwcloudpd.store import StateStore
from hwcloudpd.sync import SyncEngine
from providers import get_platform_spec
from providers.base import ProviderCapabilities

logger = logging.getLogger("albumsync.runtime")

APP_NAME = "AlbumSync"
APP_VERSION = os.environ.get("TRIM_APPVER") or "0.1.0"

CONFIG_VERSION = 2

# ---------- 全局设置（与账号无关） ----------
DEFAULT_SETTINGS: dict[str, Any] = {
    "timezone": "Asia/Shanghai",
    "custom_photos_dirs": [],  # 手动登记的可选目录清单（探测可写才入库）
    "log_level": "INFO",
}

# ---------- 账号字段（每账号一份） ----------
DEFAULT_ACCOUNT: dict[str, Any] = {
    "id": "",                       # acc-<platform>-<6hex>，创建后不变
    "owner": "",                    # fnOS 用户 id（网关 X-Trim-Userid）；空 = admin/存量账号（T30.2）
    "platform": "huawei",           # huawei | xiaomi | ...（T25 起多平台）
    "enabled": True,
    "name": "",                     # 展示名
    "username": "",
    "password": "",
    "photos_dir": "",               # 空 = pkgvar/photos/<id>/
    "folder_structure": "{:%Y/%m/%d}",
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
}

_ACCOUNT_BOOL_KEYS = (
    "enabled", "set_exif_datetime", "xmp_sidecar", "skip_videos", "skip_photos",
    "skip_live_photos", "skip_bursts", "only_favorites", "auto_delete",
    "delete_after_download", "run_on_startup",
)
_ACCOUNT_STR_KEYS = (
    "id", "owner", "platform", "name", "username", "password", "photos_dir",
    "folder_structure", "photo_size", "file_match_policy",
    "live_photo_mov_filename_policy", "webhook_url", "telegram_chat_id",
    "notification_script",
)
_OPT_INT_KEYS = (
    "min_size", "max_size", "recent", "until_found",
    "keep_cloud_recent_days", "watch_interval",
)
_PASSWORD_MASK = "******"
_PASSWORD_CLEAR = "__clear__"

# v1 平铺状态文件 → v2 账号目录下沉清单
V1_ACCOUNT_STATE_FILES = (
    "auth.json", "curl.txt", "curl.txt.imported", "cas_cookies.lwp",
    "cas_state.json", "cas_pending_2fa.json", "cas_auth.lock",
    "state.db", "state.db-wal", "state.db-shm", "health.json",
)


class ConfigMigrationError(RuntimeError):
    """v1→v2 配置迁移失败（已回滚到迁移前状态）。"""


def generate_account_id(platform: str, existing: set[str]) -> str:
    """生成稳定账号 id：acc-<platform>-<6hex>，冲突重试。"""
    platform = re.sub(r"[^a-z0-9]", "", str(platform or "hw").lower()) or "hw"
    while True:
        cand = f"acc-{platform}-{secrets.token_hex(3)}"
        if cand not in existing:
            return cand


def sanitize_account_name(name: str) -> str:
    """账号名安全化：剔除文件系统非法字符，压缩空白，限长 48。

    用途：photos_dir 子目录派生（<目录>/<安全化账号名>，0.2.1 缺陷④）。
    """
    cleaned = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "", str(name or ""))
    cleaned = re.sub(r"\s+", " ", cleaned).strip().strip(".").strip()
    return cleaned[:48]


def derive_photos_dir(base_dir: str, name: str, account_id: str,
                      existing_accounts: list[dict[str, Any]]) -> tuple[str, str]:
    """派生账号专属存储子目录：<base>/<安全化账号名>；重名追加账号 id 短后缀。

    返回 (绝对路径, 错误信息)；错误非空表示派生失败（持续重名等）。
    """
    raw_base = str(base_dir or "").strip()
    if not raw_base:
        return "", ""
    if not os.path.isabs(raw_base):
        return "", "photos_dir 必须为绝对路径（如 /vol1/1000/photos 或共享目录路径）"
    base = Path(raw_base).expanduser()

    def _norm(p: Path) -> str:
        return os.path.normpath(os.path.abspath(str(p)))

    taken = {
        _norm(Path(str(a.get("photos_dir"))))
        for a in existing_accounts if str(a.get("photos_dir") or "").strip()
    }
    leaf = sanitize_account_name(name) or account_id[-6:]
    cand = base / leaf
    if _norm(cand) in taken:
        cand = base / f"{leaf}-{account_id[-6:]}"
        if _norm(cand) in taken:
            return "", f"存储子目录冲突：{cand} 已被其他账号占用，请更换账号名或存储目录"
    return _norm(cand), ""


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


def validate_settings(data: dict[str, Any]) -> str | None:
    """校验全局设置。返回错误描述或 None（合法）。custom_photos_dirs 就地清洗。"""
    if data.get("log_level") not in (None, "DEBUG", "INFO", "WARNING", "ERROR"):
        return "log_level 仅支持 DEBUG / INFO / WARNING / ERROR"

    tz = data.get("timezone")
    if tz:
        try:
            from zoneinfo import ZoneInfo
            ZoneInfo(str(tz))
        except Exception:
            return f"timezone 无效: {tz}"

    # 手动登记的可选目录清单：清洗（去空/去重/归一）+ 绝对路径校验（就地写回，
    # save 保存的是同一 dict，清洗结果随全量保存持久化）
    custom_dirs = data.get("custom_photos_dirs")
    if custom_dirs is not None:
        if not isinstance(custom_dirs, list) or not all(isinstance(v, str) for v in custom_dirs):
            return "custom_photos_dirs 必须为字符串数组"
        cleaned: list[str] = []
        for v in custom_dirs:
            vs_raw = str(v).strip()
            if not vs_raw:
                continue
            vs = os.path.normpath(vs_raw)
            if not os.path.isabs(vs):
                return f"custom_photos_dirs 含非绝对路径: {vs_raw}"
            if vs not in cleaned:
                cleaned.append(vs)
        data["custom_photos_dirs"] = cleaned

    return None


def validate_account(data: dict[str, Any], tz: str | None = None) -> str | None:
    """校验单账号配置。返回错误描述或 None（合法）。tz 用于日期字段解释。"""
    for key in _ACCOUNT_STR_KEYS:
        if key in data and data[key] is not None and not isinstance(data[key], str):
            return f"{key} 必须为字符串"
    for key in _ACCOUNT_BOOL_KEYS:
        if key in data and not isinstance(data[key], bool):
            return f"{key} 必须为布尔值"

    if data.get("photo_size") not in (None, "original", "medium", "thumb"):
        return "photo_size 仅支持 original / medium / thumb"
    if data.get("file_match_policy") not in (None, "name-size-dedup-with-suffix", "name-id7"):
        return "file_match_policy 仅支持 name-size-dedup-with-suffix / name-id7"
    if data.get("live_photo_mov_filename_policy") not in (None, "none", "suffix", "original"):
        return "live_photo_mov_filename_policy 仅支持 none / suffix / original"
    if data.get("folder_structure") is not None and not str(data["folder_structure"]).strip():
        return "folder_structure 不能为空"
    # T30.2：owner 为 fnOS 用户 id，服务端按请求者身份注入；限长防滥用
    if len(str(data.get("owner") or "")) > 128:
        return "owner 过长（最大 128 字符）"
    # T25.5：平台必须在 PLATFORMS 注册表内（防呆，小米等未注册平台拒绝创建）
    if data.get("platform"):
        try:
            from providers import get_platform_spec  # 局部导入避免加载顺序耦合
            get_platform_spec(str(data["platform"]))
        except ValueError as exc:
            return str(exc)

    tz = str(tz or DEFAULT_SETTINGS["timezone"])
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
            parse_date_bound(value, tz)
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


# ---------- v1→v2 一次性迁移 ----------

def migrate_config_v1_to_v2(pkgvar: Path) -> None:
    """将 v1 平铺 config.json + 根目录状态文件迁移到 v2 多账号布局。

    - v2 或全新安装（无 config.json）→ 幂等直接返回
    - 备份原 config.json → config.json.bak-v1
    - 顶层账号字段包装为 accounts[0]（固定 id=acc-hw-0）
    - 状态文件（auth/curl/cas_*/state.db/health.json）移动到 accounts/acc-hw-0/
    - photos_dir 为空（即旧默认 pkgvar/photos）时，photos 根下已有内容
      移动到 photos/acc-hw-0/（新默认根 pkgvar/photos/<id>/）
    - 任一步失败 → fail-fast 回滚所有文件移动 + 恢复配置，抛 ConfigMigrationError
    """
    pkgvar = Path(pkgvar)
    path = pkgvar / "config.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return  # 全新安装
    except Exception:
        logger.warning("config.json 读取失败，跳过迁移（交由 AppConfig 容错）: %s", path)
        return
    if not isinstance(raw, dict) or not raw or raw.get("version") == CONFIG_VERSION:
        return  # v2 或空配置

    backup = path.with_name("config.json.bak-v1")
    moved: list[tuple[Path, Path]] = []  # (迁移后位置, 原位置)
    acc_id = "acc-hw-0"
    try:
        shutil.copy2(path, backup)
        acc_dir = pkgvar / "accounts" / acc_id
        acc_dir.mkdir(parents=True, exist_ok=True)
        for name in V1_ACCOUNT_STATE_FILES:
            src = pkgvar / name
            if src.exists():
                dst = acc_dir / name
                os.replace(src, dst)
                moved.append((dst, src))

        # 旧默认照片根下沉：pkgvar/photos/* → pkgvar/photos/acc-hw-0/
        if not str(raw.get("photos_dir") or "").strip():
            photos_root = pkgvar / "photos"
            if photos_root.is_dir():
                entries = [e for e in photos_root.iterdir() if e.name != acc_id]
                if entries:
                    target = photos_root / acc_id
                    target.mkdir(parents=True, exist_ok=True)
                    for entry in entries:
                        dst = target / entry.name
                        shutil.move(str(entry), str(dst))
                        moved.append((dst, entry))

        settings = {k: raw[k] for k in DEFAULT_SETTINGS if k in raw}
        account = {k: raw[k] for k in DEFAULT_ACCOUNT if k in raw}
        account["id"] = acc_id
        account["platform"] = "huawei"
        account["enabled"] = bool(account.get("enabled", True))
        if not str(account.get("name") or "").strip():
            account["name"] = "华为账号"
        AppConfig(path, pkgvar).save(settings, [account])
        logger.info(
            "config v1 → v2 迁移完成：账号 %s（%s），原配置备份于 %s",
            acc_id, account.get("username") or "无凭据", backup.name,
        )
    except Exception as exc:
        for dst, src in reversed(moved):
            try:
                src.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(dst), str(src))
            except Exception:
                logger.exception("迁移回滚失败: %s -> %s", dst, src)
        try:
            if backup.exists():
                shutil.copy2(backup, path)
        except Exception:
            logger.exception("迁移回滚：恢复 config.json 失败")
        raise ConfigMigrationError(f"v1→v2 迁移失败（已回滚）: {exc}") from exc


class AppConfig:
    """config.json（v2）读写 + SyncConfig 映射。

    load() 返回补齐默认值与 photos_dir 回退后的「运行时视图」；
    save() 仅持久化已知字段并把等于默认回退值的 photos_dir 归一为空串。
    """

    def __init__(self, path: Path, pkgvar: Path) -> None:
        self.path = Path(path)
        self.pkgvar = Path(pkgvar)

    # ---- 读取 ----

    def load_raw(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except FileNotFoundError:
            return {}
        except Exception as exc:
            logger.warning("读取 config.json 失败，使用默认值: %s", exc)
            return {}

    @staticmethod
    def _merge(dst: dict[str, Any], src: dict[str, Any]) -> dict[str, Any]:
        for key in dst:
            if key in src:
                dst[key] = src[key]
        return dst

    def default_photos_dir(self, account_id: str) -> str:
        return str(self.pkgvar / "photos" / account_id)

    def _fill_account(self, account: dict[str, Any]) -> dict[str, Any]:
        account = self._merge(dict(DEFAULT_ACCOUNT), account)
        if not str(account.get("photos_dir") or "").strip():
            account["photos_dir"] = self.default_photos_dir(account["id"])
        return account

    def load(self) -> dict[str, Any]:
        """运行时视图：{"version", "settings", "accounts"}（默认值已补齐）。"""
        raw = self.load_raw()
        if raw.get("version") == CONFIG_VERSION:
            settings = self._merge(dict(DEFAULT_SETTINGS), raw.get("settings") or {})
            accounts_raw = raw.get("accounts")
            if not isinstance(accounts_raw, list):
                accounts_raw = []
        elif raw:
            # 防御性兜底：迁移器应在启动前完成；容错按 v1 平铺解读
            logger.warning("config.json 非 v2 结构，按 v1 平铺容错解读")
            settings = self._merge(dict(DEFAULT_SETTINGS), raw)
            v1_account = dict(raw)
            v1_account.setdefault("id", "acc-hw-0")
            accounts_raw = [v1_account]
        else:
            settings = dict(DEFAULT_SETTINGS)
            accounts_raw = []
        accounts = [self._fill_account(a) if isinstance(a, dict) else None
                    for a in accounts_raw]
        accounts = [a for a in accounts if a is not None and str(a.get("id") or "").strip()]
        return {"version": CONFIG_VERSION, "settings": settings, "accounts": accounts}

    # ---- 写入 ----

    def save(self, settings: dict[str, Any], accounts: list[dict[str, Any]]) -> None:
        """持久化 v2 配置（原子写 + chmod 600）。photos_dir 等于默认回退值时归一为空串。"""
        clean_settings = {k: settings.get(k, DEFAULT_SETTINGS[k]) for k in DEFAULT_SETTINGS}
        clean_accounts: list[dict[str, Any]] = []
        for account in accounts:
            acc = {k: account.get(k, DEFAULT_ACCOUNT[k]) for k in DEFAULT_ACCOUNT}
            if acc["photos_dir"] == self.default_photos_dir(acc["id"]):
                acc["photos_dir"] = ""
            clean_accounts.append(acc)
        payload = {
            "version": CONFIG_VERSION,
            "settings": clean_settings,
            "accounts": clean_accounts,
        }
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

    # ---- SyncConfig 映射 ----

    def to_sync_config(self, account: dict[str, Any], settings: dict[str, Any], *,
                       dry_run: bool = False) -> SyncConfig:
        tz = str(settings.get("timezone") or DEFAULT_SETTINGS["timezone"])
        created_after = account.get("created_after") or None
        created_before = account.get("created_before") or None
        account_dir = self.pkgvar / "accounts" / str(account.get("id") or "")
        return SyncConfig(
            directory=Path(str(account["photos_dir"])),
            config_dir=account_dir,  # health.json / state.db 随账号目录隔离
            username=(str(account.get("username") or "").strip() or None),
            password=(str(account.get("password") or "") or None),
            folder_structure=str(account.get("folder_structure") or DEFAULT_ACCOUNT["folder_structure"]),
            timezone=tz,
            albums=[str(a) for a in (account.get("albums") or [])],
            exclude_albums=[str(a) for a in (account.get("exclude_albums") or [])],
            photo_size=str(account.get("photo_size") or "original"),
            file_match_policy=str(account.get("file_match_policy") or "name-size-dedup-with-suffix"),
            live_photo_mov_filename_policy=str(account.get("live_photo_mov_filename_policy") or "none"),
            set_exif_datetime=bool(account.get("set_exif_datetime")),
            xmp_sidecar=bool(account.get("xmp_sidecar")),
            skip_videos=bool(account.get("skip_videos")),
            skip_photos=bool(account.get("skip_photos")),
            skip_live_photos=bool(account.get("skip_live_photos")),
            skip_bursts=bool(account.get("skip_bursts")),
            only_favorites=bool(account.get("only_favorites")),
            created_after_ms=parse_date_bound(created_after, tz) if created_after else None,
            created_before_ms=parse_date_bound(created_before, tz, end_of_day=True) if created_before else None,
            min_size=account.get("min_size"),
            max_size=account.get("max_size"),
            recent=account.get("recent"),
            until_found=account.get("until_found"),
            auto_delete=bool(account.get("auto_delete")),
            delete_after_download=bool(account.get("delete_after_download")),
            keep_cloud_recent_days=account.get("keep_cloud_recent_days"),
            dry_run=dry_run,
            download_concurrency=int(account.get("download_concurrency") or 2),
            page_size=int(account.get("page_size") or 100),
            request_delay_ms=int(account.get("request_delay_ms") or 120),
            cron=(str(account["cron"]).strip() or None) if account.get("cron") else None,
            watch_interval=account.get("watch_interval"),
            keepalive_interval=int(account.get("keepalive_interval") or 60),
            run_on_startup=bool(account.get("run_on_startup")),
            full_scan_interval_hours=account.get("full_scan_interval_hours"),
            webhook_url=(str(account["webhook_url"]).strip() or None) if account.get("webhook_url") else None,
            telegram_chat_id=(str(account["telegram_chat_id"]).strip() or None) if account.get("telegram_chat_id") else None,
            notification_script=(str(account["notification_script"]).strip() or None) if account.get("notification_script") else None,
            log_level=str(settings.get("log_level") or "INFO"),
        )


# ---------- 每账号日志上下文 ----------

_LOGGING_LOCK = threading.Lock()
_CURRENT_ACCOUNT: ContextVar[str] = ContextVar("albumsync.account", default="")


class _AccountLogFilter(logging.Filter):
    """仅放行当前上下文账号的记录（ContextVar 随 daemon 线程/asyncio 任务传播）。"""

    def __init__(self, account_id: str) -> None:
        super().__init__()
        self.account_id = account_id

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        return _CURRENT_ACCOUNT.get() == self.account_id


class _SerialSyncGate:
    """跨账号串行闸门：包装 engine.run_once，全局同一时刻仅一个同步在跑。

    cancelled 置位（账号热重载/停用/删除）后，等待闸门的旧引擎直接放弃本次
    执行（返回空报告），避免旧配置的同步在新运行时就绪后仍然落盘。
    """

    def __init__(self, gate: threading.Lock, cancelled: threading.Event,
                 poll_sec: float = 1.0) -> None:
        self.gate = gate
        self.cancelled = cancelled
        self.poll_sec = poll_sec

    def run_once(self, inner: SyncEngine, *, force_full_scan: bool = False) -> SyncReport:
        while not self.cancelled.is_set():
            if self.gate.acquire(timeout=self.poll_sec):
                try:
                    if self.cancelled.is_set():
                        return SyncReport()  # 已取消：不执行
                    return inner.run_once(force_full_scan=force_full_scan)
                finally:
                    self.gate.release()
        return SyncReport()


class AccountRuntime:
    """单账号作用域运行时：组装引擎组件并向 REST 层暴露该账号的操作。

    生命周期：SchedulerManager 构建（enabled 时后台线程运行 SyncDaemon），
    配置保存后由管理器 stop() + 重建实现按账号热重载，进程退出时统一 stop()。
    """

    def __init__(self, pkgvar: Path, account: dict[str, Any], settings: dict[str, Any], *,
                 sync_gate: threading.Lock | None = None) -> None:
        self.pkgvar = Path(pkgvar).resolve()
        self.account_id = str(account["id"])
        self.platform = str(account.get("platform") or "huawei")
        self.enabled = bool(account.get("enabled", True))
        self.account_dir = self.pkgvar / "accounts" / self.account_id
        self.account_dir.mkdir(parents=True, exist_ok=True)
        (self.account_dir / "logs").mkdir(parents=True, exist_ok=True)
        self.started_at = time.time()

        self.account = dict(account)
        self.settings = dict(settings)
        self.app_config = AppConfig(self.pkgvar / "config.json", self.pkgvar)

        self.auth_manager = AuthManager(self.account_dir)   # auth/curl/cas 状态随账号目录隔离
        # T25.5：平台工厂接入——provider/auth strategy 由 PLATFORMS[platform] 构造
        self.platform_spec = get_platform_spec(self.platform)
        self.capabilities: ProviderCapabilities = self.platform_spec.capabilities
        self.strategy = self.platform_spec.create_auth_strategy(self.auth_manager, self.account)
        # client 即 PhotoProvider（鸭子类型兼容 HuaweiGalleryClient，引擎调用面零改动）
        self.client = self.platform_spec.create_provider(self.auth_manager, self.account)
        self.notifier = Notifier(
            webhook_url=account.get("webhook_url") or None,
            telegram_chat_id=account.get("telegram_chat_id") or None,
            notification_script=account.get("notification_script") or None,
        )
        self.store = StateStore(self.account_dir / "state.db")

        self.sync_gate = sync_gate
        self._engine_cancelled = threading.Event()
        self._daemon: SyncDaemon | None = None
        self._daemon_thread: threading.Thread | None = None
        self._runtime_lock = threading.RLock()  # 串行化本账号 daemon 重建
        self._login_lock = threading.Lock()
        self._dry_lock = threading.Lock()
        self._dry_state: dict[str, Any] = {
            "running": False, "report": None, "error": None,
            "started_at": None, "finished_at": None,
        }
        self._log_handler: RotatingFileHandler | None = None
        self._attach_account_log_handler()
        if self.enabled:
            self._start_daemon()
            logger.info("AccountRuntime[%s] started (cron=%s watch=%s)", self.account_id,
                        account.get("cron"), account.get("watch_interval"))
        else:
            logger.info("AccountRuntime[%s] loaded (disabled)", self.account_id)

    # ---------- 日志（每账号独立文件，T24.5） ----------

    def _sync_log_path(self) -> Path:
        return self.account_dir / "logs" / "sync.log"

    def _attach_account_log_handler(self) -> None:
        """向 root logger 挂本账号文件 handler（按 ContextVar 过滤）。"""
        handler = RotatingFileHandler(
            self._sync_log_path(), maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        ))
        handler.addFilter(_AccountLogFilter(self.account_id))
        with _LOGGING_LOCK:
            logging.getLogger().addHandler(handler)
        self._log_handler = handler

    def _detach_account_log_handler(self) -> None:
        handler, self._log_handler = self._log_handler, None
        if handler is None:
            return
        with _LOGGING_LOCK:
            logging.getLogger().removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass

    @contextlib.contextmanager
    def _log_ctx(self) -> Iterator[None]:
        """标记当前线程上下文的账号（HTTP 处理线程内的短操作）。"""
        token = _CURRENT_ACCOUNT.set(self.account_id)
        try:
            yield
        finally:
            _CURRENT_ACCOUNT.reset(token)

    # ---------- daemon ----------

    def _make_engine(self, *, dry_run: bool = False) -> SyncEngine:
        sync_cfg = self.app_config.to_sync_config(self.account, self.settings, dry_run=dry_run)
        self._apply_capabilities(sync_cfg)
        return SyncEngine(sync_cfg, self.client, self.store)

    def _apply_capabilities(self, sync_cfg: SyncConfig) -> None:
        """按平台能力声明降级（T25.5）：不支持的能力强制钳制用户配置项。"""
        caps = self.capabilities
        if not caps.supports_delete and sync_cfg.auto_delete:
            sync_cfg.auto_delete = False
            logger.info("account %s: auto_delete disabled (platform %s lacks delete support)",
                        self.account_id, caps.platform)
        if not caps.supports_favorites_filter and sync_cfg.only_favorites:
            sync_cfg.only_favorites = False
            logger.info("account %s: only_favorites disabled (platform %s lacks favorites filter)",
                        self.account_id, caps.platform)
        if not caps.supports_live_photo_mov and sync_cfg.live_photo_mov_filename_policy != "none":
            sync_cfg.live_photo_mov_filename_policy = "none"
            logger.info("account %s: live_photo_mov disabled (platform %s lacks MOV support)",
                        self.account_id, caps.platform)

    def _make_daemon_engine_factory(self) -> Any:
        """daemon 引擎工厂：每次同步经全局串行闸门排队（跨账号串行 + 热重载取消）。"""
        runtime = self

        class _GatedDaemonEngine:
            def run_once(self, force_full_scan: bool = False) -> SyncReport:
                gate = _SerialSyncGate(
                    runtime.sync_gate or threading.Lock(), runtime._engine_cancelled
                )
                return gate.run_once(runtime._make_engine(), force_full_scan=force_full_scan)

        return _GatedDaemonEngine

    def _start_daemon(self) -> None:
        sync_cfg = self.app_config.to_sync_config(self.account, self.settings)
        daemon_auth = self.strategy.build_authenticator()
        engine_factory = self._make_daemon_engine_factory() if self.sync_gate else None
        daemon = SyncDaemon(
            sync_cfg, self.auth_manager, self.client, self.store, self.notifier,
            authenticator=daemon_auth if daemon_auth.can_attempt_login else None,
            engine_factory=engine_factory,
        )
        daemon.write_health()
        thread = threading.Thread(
            target=self._run_daemon, args=(daemon,),
            name=f"sync-daemon-{self.account_id}", daemon=True
        )
        self._daemon, self._daemon_thread = daemon, thread
        thread.start()

    def _run_daemon(self, daemon: SyncDaemon) -> None:
        _CURRENT_ACCOUNT.set(self.account_id)  # 该线程全部日志落到本账号文件
        try:
            asyncio.run(daemon.run_forever())
        except Exception:
            logger.exception("sync daemon crashed (account=%s)", self.account_id)

    def restart_daemon(self) -> None:
        """[保留] 直接热重建本账号 daemon（管理器常规路径为 stop+rebuild）。"""
        with self._runtime_lock:
            self._engine_cancelled.set()  # 让等闸门的旧同步放弃
            old_daemon, old_thread = self._daemon, self._daemon_thread
            if old_daemon is not None:
                old_daemon.request_stop()
            if old_thread is not None and old_thread.is_alive():
                # 5s 上限：daemon 的 sleep/等待均可中断，空闲时秒退；若正在执行同步
                # 周期则不等它跑完（state.db 为 WAL 事务原子提交，下载中断不影响一致性，
                # 下次扫描按大小/校验策略自愈）。20s 会超出 fnOS 停止等待窗口导致
                # 卸载/停止被平台判失败（0.1.6 实测：心跳 sync 中停止耗时 21s）。
                old_thread.join(timeout=5)
            self._engine_cancelled.clear()
            if self.enabled:
                self._start_daemon()
            logger.info("AccountRuntime[%s] daemon reloaded (enabled=%s)", self.account_id, self.enabled)

    def stop(self) -> None:
        with self._runtime_lock:
            self._engine_cancelled.set()
            if self._daemon is not None:
                self._daemon.request_stop()
            if self._daemon_thread is not None and self._daemon_thread.is_alive():
                # 同 restart_daemon：5s 上限，避免超出 fnOS 停止等待窗口（0.1.6 实测教训）
                self._daemon_thread.join(timeout=5)
            try:
                self.store.close()
            except Exception:
                pass
            self._detach_account_log_handler()
            logger.info("AccountRuntime[%s] stopped", self.account_id)

    # ---------- 状态 ----------

    def _read_health(self) -> dict[str, Any]:
        try:
            data = json.loads((self.account_dir / "health.json").read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def summary(self) -> dict[str, Any]:
        """账号摘要（聚合列表用，轻量）。"""
        health = self._read_health()
        thread = self._daemon_thread
        return {
            "id": self.account_id,
            "name": self.account.get("name") or self.account_id,
            "platform": self.platform,
            "enabled": self.enabled,
            "username": self.account.get("username") or "",
            "ok": bool(health.get("ok")) if self.enabled else None,
            "auth_valid": bool(health.get("auth_valid")) if self.enabled else None,
            "daemon_running": bool(thread and thread.is_alive()),
            "last_sync_at": health.get("last_sync_at"),
            "last_error": health.get("last_error") or "",
        }

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
            "id": self.account_id,
            "name": self.account.get("name") or self.account_id,
            "platform": self.platform,
            "enabled": self.enabled,
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
        with self._log_ctx():
            session = None
            try:
                session = self.strategy.get_session_if_present()
            except Exception as exc:
                logger.warning("get_session_if_present failed: %s", exc)
            # 防御：非华为平台（小米）无 cas_probe → 用 hasattr 兜底
            if hasattr(self.strategy, "cas_probe"):
                try:
                    probe = self.strategy.cas_probe()
                except Exception as exc:
                    logger.warning("cas_probe failed: %s", exc)
                    probe = {"pending_2fa": None, "has_cas_tgt": False, "credentials_configured": False}
            else:
                probe = {"pending_2fa": None, "has_cas_tgt": False,
                         "credentials_configured": self.strategy.has_credentials()}
            pending = probe["pending_2fa"]
            # 防御：session 可能是 XiaomiClient 实例（无 .user_id/.cookies/.updated_at 属性）
            user_id = ""
            login_sec_level = None
            session_updated_at = None
            if session is not None:
                user_id = getattr(session, "user_id", "") or getattr(session, "account_id", "") or ""
                cookies = getattr(session, "cookies", None)
                if isinstance(cookies, dict):
                    login_sec_level = cookies.get("loginSecLevel")
                cookie_obj = getattr(session, "cookiejar", None)
                if cookie_obj is not None and hasattr(cookie_obj, "__iter__"):
                    for c in cookie_obj:
                        if c.name == "userId":
                            user_id = user_id or c.value
                            break
                session_updated_at = getattr(session, "updated_at", None)
            return {
                "has_session": session is not None,
                "user_id": user_id,
                "login_sec_level": login_sec_level,
                "session_updated_at": session_updated_at,
                "has_cas_tgt": probe["has_cas_tgt"],
                "credentials_configured": probe["credentials_configured"],
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
        if not self.enabled:
            return {"status": "error", "message": "账号已停用，请先启用"}
        daemon, thread = self._daemon, self._daemon_thread
        if not (daemon and thread and thread.is_alive()):
            return {"status": "error", "message": "同步守护进程未运行，请重启应用"}
        daemon._immediate_sync_event.set()
        return {"status": "ok", "message": "已触发立即同步（登录态有效后自动执行）"}

    def start_dry_run(self) -> dict[str, Any]:
        if not self.enabled:
            return {"status": "error", "message": "账号已停用，请先启用"}
        if self._dry_state.get("running"):
            return {"status": "busy", "message": "已有预览任务在进行中"}
        if not self._dry_lock.acquire(blocking=False):
            return {"status": "busy", "message": "已有预览任务在进行中"}

        def work() -> None:
            token = _CURRENT_ACCOUNT.set(self.account_id)
            gate_held = False
            try:
                if self.sync_gate is not None:
                    gate_held = self.sync_gate.acquire(timeout=30)
                    if not gate_held:
                        self._dry_state["error"] = "预览等待同步队列超时，请稍后重试"
                        return
                engine = self._make_engine(dry_run=True)
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
                if gate_held:
                    self.sync_gate.release()
                self._dry_state["running"] = False
                self._dry_state["finished_at"] = time.time()
                self._dry_lock.release()
                _CURRENT_ACCOUNT.reset(token)

        self._dry_state.update(
            {"running": True, "report": None, "error": None, "started_at": time.time()}
        )
        threading.Thread(target=work, name=f"dry-run-{self.account_id}", daemon=True).start()
        return {"status": "ok", "message": "dry-run 预览已开始"}

    def dry_run_status(self) -> dict[str, Any]:
        return dict(self._dry_state)

    def tail_logs(self, lines: int = 200) -> list[str]:
        lines = max(1, min(int(lines), 1000))
        try:
            with open(self._sync_log_path(), "r", encoding="utf-8", errors="replace") as fh:
                return list(deque(fh, maxlen=lines))
        except FileNotFoundError:
            return []

    # ---------- 认证 ----------

    def web_login(self) -> dict[str, Any]:
        """账号密码登录（非交互）。触发 2FA 时返回验证通道列表。"""
        if not self._login_lock.acquire(blocking=False):
            return {"status": "busy", "message": "已有登录/验证流程进行中，请稍候"}
        token = _CURRENT_ACCOUNT.set(self.account_id)
        lines: list[str] = []
        try:
            if not self.strategy.has_credentials():
                return {"status": "error", "message": "请先在「同步设置」中填写华为账号与密码"}
            try:
                session = self.strategy.web_login(output_fn=lines.append)
            except TwoFactorRequiredError:
                pending = self.strategy.pending_challenge()
                return {
                    "status": "2fa_required",
                    "message": "需要二次验证，验证码已发送",
                    "channels": (pending or {}).get("channels") or [],
                    "output": lines,
                }
            except (InvalidCredentialsError, CaptchaRequiredError, AuthExpiredError) as exc:
                return {"status": "error", "message": str(exc), "output": lines}
            except Exception as exc:
                return {"status": "error", "message": f"登录失败: {exc}", "output": lines}
            return self._post_login_success(session, lines)
        finally:
            _CURRENT_ACCOUNT.reset(token)
            self._login_lock.release()

    def submit_2fa(self, code: str) -> dict[str, Any]:
        """提交 6 位二次验证码，恢复 pending 2FA 流程。"""
        code = str(code or "").strip()
        if not re.fullmatch(r"\d{6}", code):
            return {"status": "error", "message": "验证码须为 6 位数字"}
        if not self._login_lock.acquire(blocking=False):
            return {"status": "busy", "message": "已有登录/验证流程进行中，请稍候"}
        token = _CURRENT_ACCOUNT.set(self.account_id)
        try:
            lines: list[str] = []
            try:
                session = self.strategy.submit_challenge(code, output_fn=lines.append)
            except TwoFactorRequiredError as exc:
                return {
                    "status": "2fa_required",
                    "message": f"验证码校验未通过: {exc}",
                    "channels": (self.strategy.pending_challenge() or {}).get("channels") or [],
                    "output": lines,
                }
            except (InvalidCredentialsError, CaptchaRequiredError, AuthExpiredError) as exc:
                return {"status": "error", "message": str(exc), "output": lines}
            except Exception as exc:
                return {"status": "error", "message": f"二次验证失败: {exc}", "output": lines}
            return self._post_login_success(session, lines)
        finally:
            _CURRENT_ACCOUNT.reset(token)
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
        with self._log_ctx():
            try:
                session = self.strategy.import_session(text)
            except Exception as exc:
                return {"status": "error", "message": f"导入失败: {exc}"}
            return {
                "status": "ok",
                "message": "cURL 会话导入成功（daemon 将在 15 秒内热重载并校验）",
                "user_id": getattr(session, "user_id", "") or "",
            }

    # ---------- 相册 ----------

    def list_albums(self) -> list[dict[str, Any]]:
        with self._log_ctx():
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
        data = dict(self.account)
        if data.get("password"):
            data["password"] = _PASSWORD_MASK
        return data
