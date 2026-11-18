#!/usr/bin/env python3
"""SchedulerManager：全局调度管理器（多账号版服务核心）。

职责（docs/multi-account-multi-platform-architecture.md §6.2）：
1. 账号注册表：dict[account_id, AccountRuntime]，启动时按 config 全量构建
2. 串行执行队列：全局 sync_gate（Lock）+ 引擎包装（_SerialSyncGate），
   手动触发 / 定时到点 / 启动即同步全部跨账号排队逐个执行
3. 调度：每账号 cron/watch 由各自 daemon 的 scheduler_loop 负责（不变），
   跨账号串行由闸门实现；改哪只账号重启哪只（按账号热重载）
4. 聚合健康：汇总各账号 health.json + daemon 状态 → /api/status、/health
5. 全局设置：时区/日志级别/可选目录登记；保存后广播重建全部运行时
"""
from __future__ import annotations

import base64
import binascii
import logging
import os
import re
import shutil
import threading
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from app_runtime import (
    APP_NAME,
    APP_VERSION,
    AccountRuntime,
    AppConfig,
    DEFAULT_ACCOUNT,
    DEFAULT_SETTINGS,
    _PASSWORD_CLEAR,
    _PASSWORD_MASK,
    derive_photos_dir,
    generate_account_id,
    migrate_config_v1_to_v2,
    validate_account,
    validate_settings,
)
import backup as backup_pkg
from identity import Requestor, current_requestor

logger = logging.getLogger("albumsync.scheduler")


class SchedulerManager:
    """多账号运行时管理器：server.py 的唯一 runtime 入口。"""

    def __init__(self, pkgvar: Path) -> None:
        self.pkgvar = Path(pkgvar).resolve()
        (self.pkgvar / "logs").mkdir(parents=True, exist_ok=True)
        (self.pkgvar / "photos").mkdir(parents=True, exist_ok=True)

        # v1→v2 一次性迁移（幂等；失败 fail-fast，服务拒绝启动）
        migrate_config_v1_to_v2(self.pkgvar)

        self.app_config = AppConfig(self.pkgvar / "config.json", self.pkgvar)
        # v2 明文密码 → v3 密文信封（幂等；失败不阻塞启动，仅告警）
        try:
            self.app_config.migrate_encrypt_passwords()
        except Exception:
            logger.exception("明文密码加密迁移失败（配置保持原样）")
        self.started_at = time.time()
        self.sync_gate = threading.Lock()  # 全局串行闸门（跨账号同步排队）
        self._lock = threading.RLock()
        self._runtimes: dict[str, AccountRuntime] = {}

        cfg = self.app_config.load()
        self._setup_service_logging(str(cfg["settings"].get("log_level") or "INFO"))
        for account in cfg["accounts"]:
            self._runtimes[account["id"]] = AccountRuntime(
                self.pkgvar, account, cfg["settings"], sync_gate=self.sync_gate
            )
        logger.info(
            "SchedulerManager initialized: pkgvar=%s version=%s accounts=%d",
            self.pkgvar, APP_VERSION, len(self._runtimes),
        )

    # ---------- 服务级日志 ----------

    def _setup_service_logging(self, level_name: str) -> None:
        """root logger：stream + logs/service.log（幂等替换全部 handler）。

        注意：会移除 root 上的全部 handler，AccountRuntime 的账号 handler
        在其之后挂载（init 顺序保证；save_settings 重建时先 setup 再重建运行时）。
        """
        service_log = self.pkgvar / "logs" / "service.log"
        root = logging.getLogger()
        root.setLevel(getattr(logging, level_name.upper(), logging.INFO))
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler = RotatingFileHandler(
            service_log, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(fmt)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(fmt)
        for old in list(root.handlers):
            root.removeHandler(old)
            try:
                old.close()
            except Exception:
                pass
        root.addHandler(file_handler)
        root.addHandler(stream_handler)

    # ---------- 内部工具 ----------

    def _load_cfg(self) -> dict[str, Any]:
        return self.app_config.load()

    def _find_account(self, cfg: dict[str, Any], account_id: str) -> dict[str, Any] | None:
        for account in cfg["accounts"]:
            if account.get("id") == account_id:
                return account
        return None

    def _persist(self, cfg: dict[str, Any]) -> None:
        self.app_config.save(cfg["settings"], cfg["accounts"])

    def _build_runtime(self, account: dict[str, Any], settings: dict[str, Any]) -> AccountRuntime:
        return AccountRuntime(self.pkgvar, account, settings, sync_gate=self.sync_gate)

    def _hot_reload_account(self, account_id: str) -> None:
        """按账号热重载：仅重建该账号的 AccountRuntime（改哪只重启哪）。"""
        cfg = self._load_cfg()
        account = self._find_account(cfg, account_id)
        if account is None:
            return
        old = self._runtimes.get(account_id)
        if old is not None:
            old.stop()
        self._runtimes[account_id] = self._build_runtime(account, cfg["settings"])
        logger.info("account %s hot-reloaded (enabled=%s)", account_id, account.get("enabled"))

    def _reload_all(self) -> None:
        """全局设置变更：广播重建全部运行时（先建新后停旧，缩短不可用窗口）。"""
        cfg = self._load_cfg()
        self._setup_service_logging(str(cfg["settings"].get("log_level") or "INFO"))
        old_runtimes = self._runtimes
        self._runtimes = {}
        for account in cfg["accounts"]:
            self._runtimes[account["id"]] = self._build_runtime(account, cfg["settings"])
        for rt in old_runtimes.values():
            rt.stop()
        logger.info("all runtimes reloaded (settings changed)")

    def _require_runtime(self, account_id: str) -> AccountRuntime:
        """取运行时并校验可见性；不存在与不可见一律 KeyError（API 层 404）。"""
        cfg = self._load_cfg()
        self._require_visible_account(cfg, account_id)
        rt = self._runtimes.get(account_id)
        if rt is None:
            raise KeyError(f"账号不存在: {account_id}")
        return rt

    # ---------- 多用户可见性（T30 路线 A：网关身份头直信） ----------

    @staticmethod
    def _is_visible(account: dict[str, Any], requestor: Requestor) -> bool:
        """单账号可见性：admin/系统/直连全可见；普通用户仅 owner=自己。"""
        if requestor.sees_all:
            return True
        return str(account.get("owner") or "") == requestor.user_id

    def _visible_accounts(self, cfg: dict[str, Any]) -> list[dict[str, Any]]:
        """按当前请求身份过滤 cfg 中的可见账号（不修改 cfg）。"""
        requestor = current_requestor()
        if requestor.sees_all:
            return cfg["accounts"]
        return [a for a in cfg["accounts"] if self._is_visible(a, requestor)]

    def _require_visible_account(self, cfg: dict[str, Any],
                                 account_id: str) -> dict[str, Any]:
        """取账号并校验可见性；不可见与不存在一律 KeyError（404，不泄露存在性）。"""
        account = self._find_account(cfg, account_id)
        if account is None or not self._is_visible(account, current_requestor()):
            raise KeyError(f"账号不存在: {account_id}")
        return account

    # ---------- 账号 CRUD ----------

    def list_accounts(self) -> list[dict[str, Any]]:
        """账号列表（脱敏摘要，附运行状态；按请求者身份过滤，T30.4）。"""
        with self._lock:
            cfg = self._load_cfg()
            visible_ids = {a["id"] for a in self._visible_accounts(cfg)}
            items = []
            for account in cfg["accounts"]:
                if account["id"] not in visible_ids:
                    continue
                rt = self._runtimes.get(account["id"])
                if rt is not None:
                    items.append(rt.summary())
                else:
                    items.append({
                        "id": account["id"], "name": account.get("name") or account["id"],
                        "platform": account.get("platform"), "enabled": account.get("enabled", True),
                        "username": account.get("username") or "",
                        "daemon_running": False, "ok": None, "auth_valid": None,
                        "last_sync_at": None, "last_error": "",
                    })
            return items

    @staticmethod
    def _mask_account(account: dict[str, Any]) -> dict[str, Any]:
        data = dict(account)
        if data.get("password"):
            data["password"] = _PASSWORD_MASK
        return data

    def get_account(self, account_id: str) -> dict[str, Any]:
        """账号详情（脱敏，photos_dir 为回退后的有效值；非 owner 一律 404，T30.4）。"""
        with self._lock:
            account = self._require_visible_account(self._load_cfg(), account_id)
            return self._mask_account(account)

    def create_account(self, payload: dict[str, Any]) -> dict[str, Any]:
        """创建账号：生成 id → 校验 → 持久化 → 构建运行时。"""
        with self._lock:
            cfg = self._load_cfg()
            account = dict(DEFAULT_ACCOUNT)
            for key in DEFAULT_ACCOUNT:
                if key in payload:
                    account[key] = payload[key]
            account["id"] = generate_account_id(
                payload.get("platform") or "huawei",
                {a["id"] for a in cfg["accounts"]},
            )
            if not str(account.get("name") or "").strip():
                account["name"] = f"账号 {account['id'][-6:]}"
            # 新账号强制停用：认证（含 2FA）完成前不启动 daemon/自动登录，
            # 用户显式启用后才运行（0.2.1 缺陷修复①②）
            account["enabled"] = False
            # T30.4 归属规则：admin/系统/直连可指定 owner（缺省=无主，admin 可见）；
            # 普通网关用户强制归属本人，payload 中的 owner 一律忽略
            if not current_requestor().sees_all:
                account["owner"] = current_requestor().user_id
            # photos_dir 子目录派生：显式给目录时落盘为 <目录>/<安全化账号名>，
            # 避免多账号共享同一目录互相覆盖（0.2.1 缺陷④）；留空走默认根 photos/<id>
            photos_dir = str(payload.get("photos_dir") or "").strip()
            if photos_dir:
                derived, err = derive_photos_dir(
                    photos_dir, account["name"], account["id"], cfg["accounts"])
                if err:
                    return {"status": "error", "message": err}
                account["photos_dir"] = derived
            else:
                account["photos_dir"] = ""
            error = validate_account(account, tz=cfg["settings"].get("timezone"))
            if error:
                return {"status": "error", "message": error}
            cfg["accounts"].append(account)
            try:
                self._persist(cfg)
            except Exception as exc:
                return {"status": "error", "message": f"写入配置失败: {exc}"}
            self._runtimes[account["id"]] = self._build_runtime(account, cfg["settings"])
            logger.info("account created: %s (platform=%s, enabled=false)", account["id"], account["platform"])
            return {
                "status": "ok",
                "message": "账号已创建（默认停用，请完成认证后启用）",
                "account": self._mask_account(account),
            }

    def update_account(self, account_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """更新账号配置（密码掩码语义）→ 校验 → 持久化 → 按账号热重载。

        T30.4：非 owner 一律 404；普通用户不可变更归属（owner 强制保留原值）。
        """
        with self._lock:
            cfg = self._load_cfg()
            account = self._require_visible_account(cfg, account_id)
            data = dict(account)
            for key in DEFAULT_ACCOUNT:
                if key not in payload:
                    continue
                if key == "password":
                    value = payload["password"]
                    if value == _PASSWORD_CLEAR:
                        data["password"] = ""
                    elif value in (_PASSWORD_MASK, "", None):
                        pass  # 保留已存密码
                    else:
                        data["password"] = str(value)
                    continue
                data[key] = payload[key]
            data["id"] = account_id  # id 不可变
            if "platform" in payload and payload["platform"] != account.get("platform"):
                return {"status": "error", "message": "账号平台不支持修改"}
            # 普通用户不可变更归属（防止把账号挂到他人名下或窃取他人账号）
            if not current_requestor().sees_all:
                data["owner"] = str(account.get("owner") or "")
            # 向导创建流程专用：photos_dir 派生 <目录>/<安全化账号名> 子目录。
            # 普通设置页保存不携带该标记，存量路径原样保留（0.2.1 缺陷④）
            if payload.get("derive_subdir"):
                pd = str(data.get("photos_dir") or "").strip()
                if pd:
                    others = [a for a in cfg["accounts"] if a["id"] != account_id]
                    derived, err = derive_photos_dir(
                        pd, str(data.get("name") or ""), account_id, others)
                    if err:
                        return {"status": "error", "message": err}
                    data["photos_dir"] = derived
            error = validate_account(data, tz=cfg["settings"].get("timezone"))
            if error:
                return {"status": "error", "message": error}
            cfg["accounts"] = [data if a["id"] == account_id else a for a in cfg["accounts"]]
            try:
                self._persist(cfg)
            except Exception as exc:
                return {"status": "error", "message": f"写入配置失败: {exc}"}
            self._hot_reload_account(account_id)
            logger.info("account %s config saved", account_id)
            return {
                "status": "ok",
                "message": "配置已保存并热生效",
                "account": self._mask_account(data),
            }

    def set_account_enabled(self, account_id: str, enabled: bool) -> dict[str, Any]:
        with self._lock:
            cfg = self._load_cfg()
            account = self._require_visible_account(cfg, account_id)  # 非 owner 404（T30.4）
            account["enabled"] = bool(enabled)
            try:
                self._persist(cfg)
            except Exception as exc:
                return {"status": "error", "message": f"写入配置失败: {exc}"}
            self._hot_reload_account(account_id)
            return {
                "status": "ok",
                "message": "账号已启用" if enabled else "账号已停用",
                "account": self._mask_account(account),
            }

    def delete_account(self, account_id: str) -> dict[str, Any]:
        """删除账号：停 daemon → 移除注册表 → 删配置 → 删账号目录（photos_dir 用户数据不动）。"""
        with self._lock:
            cfg = self._load_cfg()
            account = self._require_visible_account(cfg, account_id)  # 非 owner 404（T30.4）
            rt = self._runtimes.pop(account_id, None)
            if rt is not None:
                rt.stop()
            cfg["accounts"] = [a for a in cfg["accounts"] if a["id"] != account_id]
            try:
                self._persist(cfg)
            except Exception as exc:
                # 配置写失败则恢复运行时，避免注册表与配置不一致
                self._runtimes[account_id] = self._build_runtime(account, cfg["settings"])
                return {"status": "error", "message": f"写入配置失败: {exc}"}
            import shutil as _shutil
            _shutil.rmtree(self.pkgvar / "accounts" / account_id, ignore_errors=True)
            logger.info("account deleted: %s", account_id)
            return {"status": "ok", "message": "账号已删除"}

    # ---------- 账号级操作（转发 AccountRuntime） ----------

    def account_status(self, account_id: str) -> dict[str, Any]:
        return self._require_runtime(account_id).status_snapshot()

    def account_auth_status(self, account_id: str) -> dict[str, Any]:
        return self._require_runtime(account_id).auth_status()

    def trigger_sync(self, account_id: str) -> dict[str, Any]:
        return self._require_runtime(account_id).trigger_sync()

    def start_dry_run(self, account_id: str) -> dict[str, Any]:
        return self._require_runtime(account_id).start_dry_run()

    def dry_run_status(self, account_id: str) -> dict[str, Any]:
        return self._require_runtime(account_id).dry_run_status()

    def tail_logs(self, account_id: str, lines: int = 200) -> list[str]:
        return self._require_runtime(account_id).tail_logs(lines)

    def web_login(self, account_id: str) -> dict[str, Any]:
        return self._require_runtime(account_id).web_login()

    def submit_2fa(self, account_id: str, code: str) -> dict[str, Any]:
        return self._require_runtime(account_id).submit_2fa(code)

    def import_curl(self, account_id: str, curl_text: str) -> dict[str, Any]:
        return self._require_runtime(account_id).import_curl(curl_text)

    def list_albums(self, account_id: str) -> list[dict[str, Any]]:
        return self._require_runtime(account_id).list_albums()

    # ---------- 聚合状态 / 健康 ----------

    def status_snapshot(self) -> dict[str, Any]:
        """聚合状态：应用信息 + 各账号摘要。"""
        with self._lock:
            return {
                "app": APP_NAME,
                "version": APP_VERSION,
                "uptime_sec": round(time.time() - self.started_at, 1),
                "accounts": self.list_accounts(),
                "updated_at": time.time(),
            }

    def service_health(self) -> dict[str, Any]:
        """/health：可见的启用账号 daemon 线程均存活（无可见账号视为正常，T30.4）。"""
        with self._lock:
            runtimes = list(self._runtimes.values())
        cfg = self._load_cfg()
        visible_ids = {a["id"] for a in self._visible_accounts(cfg)}
        visible = [rt for rt in runtimes if rt.account_id in visible_ids]
        alive_all = True
        for rt in visible:
            if rt.enabled:
                thread = rt._daemon_thread
                if not (thread and thread.is_alive()):
                    alive_all = False
                    break
        return {
            "success": True,
            "status": "ok" if alive_all else "degraded",
            "app": APP_NAME,
            "version": APP_VERSION,
            "accounts_total": len(visible),
            "daemon_running": alive_all,
            "uptime_sec": round(time.time() - self.started_at, 1),
        }

    # ---------- 全局设置 ----------

    def get_settings(self) -> dict[str, Any]:
        return dict(self._load_cfg()["settings"])

    def save_settings(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            cfg = self._load_cfg()
            settings = dict(cfg["settings"])
            for key in DEFAULT_SETTINGS:
                if key in payload:
                    settings[key] = payload[key]
            error = validate_settings(settings)
            if error:
                return {"status": "error", "message": error}
            cfg["settings"] = settings
            try:
                self._persist(cfg)
            except Exception as exc:
                return {"status": "error", "message": f"写入配置失败: {exc}"}
            self._reload_all()
            logger.info("global settings saved; all runtimes reloaded")
            return {"status": "ok", "message": "全局设置已保存并热生效",
                    "settings": dict(settings)}

    # ---------- 目录探测（全局） ----------

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
        customs = self.get_settings().get("custom_photos_dirs") or []
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
        """探测单个目录的当前访问权限（供前端对用户手输路径实时校验）。"""
        p = os.path.normpath(str(path or "").strip())  # 尾斜杠等归一，避免同目录重复登记
        if not p or not os.path.isabs(p):
            return {"path": p, "exists": False, "readable": False,
                    "writable": False, "registered": False, "error": "需为绝对路径"}
        registered = p in (self.get_settings().get("custom_photos_dirs") or [])
        return {
            "path": p,
            "exists": os.path.isdir(p),
            "readable": os.access(p, os.R_OK),
            "writable": os.access(p, os.W_OK),
            "registered": registered,
        }

    def add_custom_photos_dir(self, path: str) -> dict[str, Any]:
        """登记手输路径到「可选目录」清单：探测可写才入库（去重）。

        仅写 config.json 的 settings.custom_photos_dirs 单字段、不重建运行时。
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
        with self._lock:
            cfg = self._load_cfg()
            customs = cfg["settings"].get("custom_photos_dirs")
            if not isinstance(customs, list):
                customs = []
            customs = [str(v) for v in customs if isinstance(v, str) and v.strip()]
            if p in customs:
                return {"status": "ok", "message": "该目录已在可选目录清单中",
                        "custom_photos_dirs": customs}
            customs.append(p)
            cfg["settings"]["custom_photos_dirs"] = customs
            try:
                self._persist(cfg)
            except Exception as exc:
                return {"status": "error", "message": f"写入配置失败: {exc}"}
            logger.info("custom photos dir added: %s", p)
            return {"status": "ok", "message": "已添加到可选目录",
                    "custom_photos_dirs": customs}

    # ---------- 凭据备份（0.3.0） ----------

    def _backup_dir(self, settings: dict[str, Any]) -> Path:
        raw = str(settings.get("backup_dir") or "").strip()
        return Path(raw) if raw else (self.pkgvar / "backups")

    def list_backups(self) -> dict[str, Any]:
        """列出备份目录中的 .asbak 文件（新→旧，最多 50 条）。"""
        directory = self._backup_dir(self._load_cfg()["settings"])
        items: list[dict[str, Any]] = []
        if directory.is_dir():
            try:
                entries = sorted(directory.glob("*.asbak"), reverse=True)
            except OSError:
                entries = []
            for entry in entries[:50]:
                try:
                    st = entry.stat()
                except OSError:
                    continue
                items.append({
                    "name": entry.name,
                    "size": st.st_size,
                    "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                })
        return {"directory": str(directory), "files": items}

    def export_backup(self, payload: dict[str, Any]) -> dict[str, Any]:
        """导出凭据备份：整包口令加密 → 落盘到备份目录 + 返回 base64 供浏览器下载。"""
        passphrase = str(payload.get("passphrase") or "")
        if len(passphrase) < 8:
            return {"status": "error", "message": "导出口令至少 8 个字符"}
        include_passwords = bool(payload.get("include_passwords", True))
        include_sessions = bool(payload.get("include_sessions", True))
        raw_ids = payload.get("account_ids")
        if isinstance(raw_ids, str):
            raw_ids = [raw_ids]
        wanted = {str(x) for x in raw_ids} if raw_ids else None

        with self._lock:
            cfg = self._load_cfg()
            visible = {a["id"] for a in self._visible_accounts(cfg)}
            accounts = [a for a in cfg["accounts"] if a["id"] in visible]
            if wanted is not None:
                accounts = [a for a in accounts if a["id"] in wanted]
            try:
                archive, manifest = backup_pkg.build_archive(
                    pkgvar=self.pkgvar, settings=cfg["settings"], accounts=accounts,
                    app_version=APP_VERSION, include_passwords=include_passwords,
                    include_sessions=include_sessions,
                )
                blob = backup_pkg.seal_container(archive, passphrase, manifest)
            except backup_pkg.BackupError as exc:
                return {"status": "error", "message": str(exc)}

            directory = self._backup_dir(cfg["settings"])
            try:
                directory.mkdir(parents=True, exist_ok=True)
                os.chmod(directory, 0o700)
            except OSError as exc:
                return {"status": "error", "message": f"备份目录不可用: {directory}（{exc}）"}

            name = f"albumsync-backup-{time.strftime('%Y%m%d-%H%M%S')}.asbak"
            path = directory / name
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(blob)
            except OSError as exc:
                return {"status": "error", "message": f"写入备份文件失败: {exc}"}

        logger.info(
            "credentials export ok: accounts=%d include_passwords=%s include_sessions=%s file=%s",
            len(accounts), include_passwords, include_sessions, path,
        )
        return {
            "status": "ok",
            "message": f"备份已导出到 {path}",
            "file": str(path),
            "filename": name,
            "size": len(blob),
            "data_b64": base64.b64encode(blob).decode("ascii"),
            "accounts": manifest["accounts"],
        }

    def inspect_backup(self, payload: dict[str, Any]) -> dict[str, Any]:
        """解密校验并预览备份包内容（不写盘）。"""
        blob = self._decode_backup_blob(payload)
        if isinstance(blob, dict):
            return blob
        try:
            header, archive = backup_pkg.open_container(blob, str(payload.get("passphrase") or ""))
            files = backup_pkg.parse_archive(archive)
            imported_cfg = backup_pkg.load_config_from_archive(files)
            secrets_map = backup_pkg.load_secrets_from_archive(files)
        except backup_pkg.BackupError as exc:
            return {"status": "error", "message": str(exc)}
        existing = {a["id"] for a in self._load_cfg()["accounts"]}
        accounts = []
        for acc in imported_cfg["accounts"]:
            if not isinstance(acc, dict):
                continue
            acc_id = str(acc.get("id") or "")
            accounts.append({
                "id": acc_id,
                "platform": acc.get("platform") or "huawei",
                "name": acc.get("name") or acc_id,
                "username": acc.get("username") or "",
                "conflict": acc_id in existing,
                "has_password": bool(secrets_map.get(acc_id)),
                "sessions": sorted(backup_pkg.collect_session_files(files, acc_id).keys()),
            })
        return {
            "status": "ok",
            "header": {k: header.get(k) for k in
                       ("schema", "app_version", "created_at", "flags") if k in header},
            "accounts": accounts,
        }

    def import_backup(self, payload: dict[str, Any]) -> dict[str, Any]:
        """导入备份包：merge（默认，按 id 覆盖）或 replace（清空后导入）。"""
        blob = self._decode_backup_blob(payload)
        if isinstance(blob, dict):
            return blob
        mode = str(payload.get("mode") or "merge")
        if mode not in ("merge", "replace"):
            return {"status": "error", "message": "mode 仅支持 merge / replace"}
        try:
            _header, archive = backup_pkg.open_container(blob, str(payload.get("passphrase") or ""))
            files = backup_pkg.parse_archive(archive)
            imported_cfg = backup_pkg.load_config_from_archive(files)
            secrets_map = backup_pkg.load_secrets_from_archive(files)
        except backup_pkg.BackupError as exc:
            return {"status": "error", "message": str(exc)}

        requestor = current_requestor()
        restored: list[str] = []
        with self._lock:
            cfg = self._load_cfg()
            incoming: list[dict[str, Any]] = []
            for raw_acc in imported_cfg["accounts"]:
                if not isinstance(raw_acc, dict):
                    continue
                acc_id = str(raw_acc.get("id") or "").strip()
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", acc_id):
                    return {"status": "error", "message": f"备份包含非法账号 id: {acc_id!r}"}
                merged = {k: v for k, v in raw_acc.items() if k in DEFAULT_ACCOUNT}
                merged["id"] = acc_id
                merged["password"] = str(secrets_map.get(acc_id) or "")
                merged["password_enc"] = None
                account = self.app_config.normalize_account(merged)
                if not requestor.sees_all:
                    account["owner"] = requestor.user_id
                error = validate_account(account, tz=cfg["settings"].get("timezone"))
                if error:
                    return {"status": "error", "message": f"账号 {acc_id} 配置非法: {error}"}
                incoming.append(account)

            if not incoming:
                return {"status": "error", "message": "备份包中没有可导入的账号"}

            if mode == "replace":
                final = incoming
            else:
                by_id = {a["id"]: a for a in cfg["accounts"]}
                for account in incoming:
                    by_id[account["id"]] = account
                final = list(by_id.values())

            # 会话文件先落盘，再写配置，最后整体热重载
            for account in incoming:
                self._restore_session_files(files, account["id"])
            cfg["accounts"] = final
            try:
                self._persist(cfg)
            except Exception as exc:
                return {"status": "error", "message": f"写入配置失败: {exc}"}
            try:
                self._reload_all()
            except Exception as exc:
                logger.exception("导入后热重载失败")
                return {"status": "error", "message": f"配置已写入但热重载失败: {exc}"}
            restored = [a["id"] for a in incoming]

        logger.info("credentials import ok: mode=%s accounts=%s", mode, ",".join(restored))
        return {
            "status": "ok",
            "message": f"已导入 {len(restored)} 个账号（{mode}）",
            "mode": mode,
            "accounts": restored,
        }

    def _restore_session_files(self, files: dict[str, bytes], account_id: str) -> None:
        sessions = backup_pkg.collect_session_files(files, account_id)
        if not sessions:
            return
        acc_dir = self.pkgvar / "accounts" / account_id
        acc_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(acc_dir, 0o700)
        except OSError:
            pass
        for name, data in sessions.items():
            target = acc_dir / name
            try:
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
            except OSError as exc:
                logger.warning("恢复会话文件失败 %s: %s", target, exc)

    @staticmethod
    def _decode_backup_blob(payload: dict[str, Any]) -> bytes | dict[str, Any]:
        raw = payload.get("data_b64")
        if not isinstance(raw, str) or not raw.strip():
            return {"status": "error", "message": "缺少备份文件内容（data_b64）"}
        data = raw.strip()
        if data.startswith("data:"):
            data = data.split(",", 1)[-1]
        try:
            blob = base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError):
            return {"status": "error", "message": "备份文件内容不是有效的 base64"}
        if len(blob) > backup_pkg.MAX_CONTAINER_BYTES:
            return {"status": "error", "message": "备份包过大（超过 16MB）"}
        return blob

    # ---------- 生命周期 ----------

    def stop(self) -> None:
        with self._lock:
            for rt in self._runtimes.values():
                rt.stop()
            logger.info("SchedulerManager stopped")
