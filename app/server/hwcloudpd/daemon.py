"""Unattended Docker daemon: heartbeat keep-alive, cron/interval scheduling, and hot-reload."""

from __future__ import annotations

import asyncio
from datetime import datetime
import json
import logging
import os
from pathlib import Path
import random
import signal
import sqlite3
import threading
import time
from typing import Any, Callable
from zoneinfo import ZoneInfo

from hwcloudpd.auth import AuthManager
from hwcloudpd.cron import CronSchedule
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

logger = logging.getLogger(__name__)


class SyncDaemon:
    """Concurrent keep-alive + scheduled sync runner with zero stdin interaction."""

    def __init__(
        self,
        config: SyncConfig,
        auth_manager: AuthManager,
        client: Any,  # PhotoProvider 实现（鸭子类型；华为=HuaweiGalleryClient）
        store: StateStore,
        notifier: Notifier,
        *,
        authenticator: Any | None = None,  # 自动重登认证器；不支持的平台为 None
        engine_factory: Callable[[], SyncEngine] | None = None,
        auto_relogin_cooldown_sec: float = 1800.0,
        platform_label: str = "",
        auth_recovery_hint: str = "",
    ) -> None:
        self.config = config
        self.auth_manager = auth_manager
        self.client = client
        self.store = store
        self.notifier = notifier
        self.authenticator = authenticator
        # 平台显示名与恢复指引由账号平台注入（providers），通知文案不再硬编码华为
        self.platform_label = str(platform_label or "").strip() or "云相册"
        self.auth_recovery_hint = str(auth_recovery_hint or "").strip()
        self._engine_factory = engine_factory or (
            lambda: SyncEngine(self.config, self.client, self.store)
        )
        self.health_file = Path(config.config_dir) / "health.json"
        self._tz = ZoneInfo(config.timezone)

        self._stop_event = asyncio.Event()
        self._auth_ready_event = asyncio.Event()
        self._immediate_sync_event = asyncio.Event()
        self._sync_lock = asyncio.Lock()
        # Set by run_forever; lets foreign threads wake the scheduler safely.
        self._loop: asyncio.AbstractEventLoop | None = None

        self._auth_valid = False
        self._credentials_rejected = False
        self._auto_relogin_blocked_until: float = 0.0
        self._auto_relogin_cooldown_sec = auto_relogin_cooldown_sec
        self._last_heartbeat_at: float | None = None
        self._last_sync_at: float | None = None
        self._last_full_scan_at: float = self._load_last_full_scan_at()
        self._last_error: str = ""
        self._last_report: SyncReport | None = None

        # T46.2: 同步进度快照（纯内存瞬态，不落盘）——引擎 progress_cb 的落点。
        # 状态机: waiting(闸门排队) → scanning → downloading → done/error；
        # 重启后自然清零，符合「本次同步」语义；health.json 语义不变。
        self._progress: dict[str, Any] = {}
        self._progress_lock = threading.Lock()

        self._cron_schedule = (
            CronSchedule.parse(config.cron) if config.cron and config.cron.strip() else None
        )

    def _load_last_full_scan_at(self) -> float:
        if not self.health_file.exists():
            return 0.0
        try:
            data = json.loads(self.health_file.read_text(encoding="utf-8"))
            return float(data.get("last_full_scan_at") or 0.0)
        except Exception:
            return 0.0

    def request_stop(self) -> None:
        """Signal all daemon loops to shut down gracefully."""
        self._stop_event.set()
        self._auth_ready_event.set()
        self._immediate_sync_event.set()

    def write_health(self) -> None:
        """Atomically persist container health state for Docker HEALTHCHECK."""
        self.health_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "ok": not self._stop_event.is_set(),
            "auth_valid": self._auth_valid,
            "last_heartbeat_at": self._last_heartbeat_at,
            "last_sync_at": self._last_sync_at,
            "last_full_scan_at": self._last_full_scan_at or None,
            "last_error": self._last_error,
            "last_report": self._last_report.summary_text() if self._last_report else None,
            "updated_at": time.time(),
        }
        tmp = self.health_file.with_name(f".health.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.health_file)

    # ---------- 同步进度快照（T46.2） ----------

    def _on_engine_progress(self, fields: dict[str, Any]) -> None:
        """引擎进度回调落点（多并发下载线程会并发调用，锁内合并绝对量快照）。"""
        with self._progress_lock:
            prev_phase = self._progress.get("phase")
            self._progress.update(fields)
            if fields.get("phase") == "downloading" and prev_phase != "downloading":
                self._progress["download_started_at"] = time.time()

    def progress_snapshot(self) -> dict[str, Any] | None:
        """读取一致进度快照（供 REST 层轮询）；从未同步/空闲返回 None。

        eta_sec/speed_per_min 为读时派生字段：按已完成项均速线性外推
        （照片/视频混合场景按项数估算，字节加权口径留待二期）。
        """
        with self._progress_lock:
            snap = dict(self._progress)
        phase = snap.get("phase")
        if not phase:
            return None
        total = int(snap.get("total") or 0)
        done = int(snap.get("done") or 0)
        t0 = snap.get("download_started_at")
        if phase == "downloading" and total > 0 and done > 0 and t0:
            elapsed = max(time.time() - float(t0), 1e-6)
            snap["eta_sec"] = round(elapsed / done * (total - done), 1)
            snap["speed_per_min"] = round(done / elapsed * 60.0, 1)
        return snap

    def _set_progress_error(self, message: str) -> None:
        """异常终态（登录态失效/同步异常/中止），供前端收尾展示。"""
        with self._progress_lock:
            self._progress["phase"] = "error"
            self._progress["error"] = message
            self._progress["finished_at"] = time.time()

    def _reset_progress_waiting(self, started_ts: float) -> None:
        """轮次起点：整体重置快照（清掉上一轮 total/done/current_file 残留）。"""
        with self._progress_lock:
            self._progress.clear()
            self._progress["phase"] = "waiting"
            self._progress["started_at"] = started_ts

    async def _sleep_or_stop(self, seconds: float) -> bool:
        """Sleep up to `seconds`; return True if stopped early."""
        if seconds <= 0:
            return self._stop_event.is_set()
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=seconds)
            return True
        except asyncio.TimeoutError:
            return False

    async def _handle_auth_expired(
        self,
        reason: str,
        *,
        notify_title: str | None = None,
        notify_msg: str | None = None,
    ) -> None:
        self._auth_valid = False
        self._auth_ready_event.clear()
        self._last_error = reason
        self.write_health()
        logger.warning(
            "%s session unavailable/expired: %s. Restore the session (re-import "
            "credentials or re-login); daemon will recover automatically.",
            self.platform_label,
            reason,
        )
        if notify_msg:
            default_msg = notify_msg
        elif self.auth_recovery_hint:
            default_msg = f"{reason}。{self.auth_recovery_hint}"
        else:
            default_msg = f"{reason}。请在「认证与安全」重新导入登录态后自动恢复。"
        self.notifier.notify(
            "auth_expired", notify_title or f"{self.platform_label}登录态失效", default_msg
        )

    async def _try_silent_auto_relogin(self) -> bool:
        if (
            self.authenticator is None
            or not getattr(self.authenticator, "can_attempt_login", self.authenticator.has_credentials)
            or self._credentials_rejected
            or time.monotonic() < self._auto_relogin_blocked_until
        ):
            return False

        logger.info("Session expired/missing; attempting silent CAS protocol auto-relogin...")
        try:
            await asyncio.to_thread(self.authenticator.login, interactive=False)
            # T28.3: relogin may rotate the CASTGC cookie; make sure the jar on
            # disk matches memory (idempotent when login() already saved it).
            if hasattr(self.authenticator, "persist_cookie_jar_if_changed"):
                await asyncio.to_thread(self.authenticator.persist_cookie_jar_if_changed)
            await asyncio.to_thread(self.client.heartbeat_check)
            self._auth_valid = True
            self._last_heartbeat_at = time.time()
            self._last_error = ""
            self._auth_ready_event.set()
            self.notifier.reset_auth_cooldown()
            self.write_health()
            self._immediate_sync_event.set()
            logger.info("Silent auto-relogin succeeded; session restored.")
            return True
        except InvalidCredentialsError as exc:
            self._credentials_rejected = True
            await self._handle_auth_expired(
                str(exc),
                notify_title=f"{self.platform_label}账号或密码错误",
                notify_msg=f"{exc}。已停止自动登录重试以防账号锁定，请在「同步设置」修正账号密码后重启应用。",
            )
            return False
        except TwoFactorRequiredError as exc:
            self._auto_relogin_blocked_until = time.monotonic() + self._auto_relogin_cooldown_sec
            await self._handle_auth_expired(
                str(exc),
                notify_title=f"{self.platform_label}需要二次验证",
                notify_msg=f"{exc}。请在「认证与安全」完成二次验证并勾选信任设备，之后将自动恢复。",
            )
            return False
        except CaptchaRequiredError as exc:
            self._auto_relogin_blocked_until = time.monotonic() + self._auto_relogin_cooldown_sec
            await self._handle_auth_expired(
                str(exc),
                notify_title=f"{self.platform_label}触发人机验证",
                notify_msg=str(exc),
            )
            return False
        except Exception as exc:
            self._auto_relogin_blocked_until = time.monotonic() + min(300.0, self._auto_relogin_cooldown_sec)
            await self._handle_auth_expired(f"静默自动登录失败: {exc}")
            return False

    async def keepalive_step(self) -> bool:
        """Execute a single heartbeat/hot-reload check. Return True if session is healthy."""
        was_valid = self._auth_valid
        try:
            reloaded = self.auth_manager.load_or_reload()
            if reloaded:
                logger.info("Detected updated credentials on disk; validating session...")
                self._auto_relogin_blocked_until = 0.0
            await asyncio.to_thread(self.client.heartbeat_check)
            self._auth_valid = True
            self._last_heartbeat_at = time.time()
            self._last_error = ""
            self._auth_ready_event.set()
            self.notifier.reset_auth_cooldown()
            self.write_health()
            # T28.3: heartbeat may receive rotated CASTGC cookies that only land
            # in the in-memory jar; persist when it differs from disk so a
            # process restart keeps the rotated session.
            if self.authenticator is not None and hasattr(
                self.authenticator, "persist_cookie_jar_if_changed"
            ):
                if await asyncio.to_thread(self.authenticator.persist_cookie_jar_if_changed):
                    logger.info("CAS cookie jar rotated at runtime; persisted to disk.")
            if not was_valid and reloaded:
                # Credentials just recovered while running: kick off a sync promptly.
                self._immediate_sync_event.set()
            return True
        except AuthExpiredError as exc:
            if await self._try_silent_auto_relogin():
                return True
            if self._credentials_rejected:
                self._auth_valid = False
                self._auth_ready_event.clear()
                self.write_health()
                return False
            if time.monotonic() < self._auto_relogin_blocked_until:
                # Notification already dispatched inside _try_silent_auto_relogin().
                return False
            await self._handle_auth_expired(str(exc))
            return False
        except Exception as exc:
            # Transient network errors should not mark credentials expired prematurely.
            self._last_error = str(exc)
            self.write_health()
            logger.warning("Heartbeat check transient failure: %s", exc)
            return self._auth_valid

    async def keepalive_loop(self) -> None:
        """Background loop keeping the platform session (cookies/tokens) active."""
        while not self._stop_event.is_set():
            healthy = await self.keepalive_step()
            if healthy:
                base = max(15, self.config.keepalive_interval)
                jitter = random.uniform(-min(5.0, base * 0.1), min(5.0, base * 0.1))
                delay = max(10.0, base + jitter)
            else:
                # Poll volume quickly for newly dropped curl.txt / updated auth.json.
                delay = 15.0
            await self._sleep_or_stop(delay)

    async def execute_sync_once(self, mode: str = "scheduled") -> SyncReport | None:
        """Run one sync cycle guarded by _sync_lock."""
        async with self._sync_lock:
            now_ts = time.time()
            force_full = False
            if self.config.full_scan_interval_hours is not None and self.config.full_scan_interval_hours > 0:
                if (now_ts - self._last_full_scan_at) >= self.config.full_scan_interval_hours * 3600.0:
                    force_full = True

            logger.info(
                "Sync started (mode=%s, scan=%s)",
                mode,
                "full" if force_full else "incremental",
            )

            # T46.2: 先置排队态再进引擎——全局串行闸门的等待期对前端可见
            # （排队中），快照整体重置避免上一轮 total/done/current_file 残留。
            self._reset_progress_waiting(now_ts)

            try:
                engine = self._engine_factory()
                report = await asyncio.to_thread(
                    engine.run_once,
                    force_full_scan=force_full,
                    progress_cb=self._on_engine_progress,
                )
                self._last_sync_at = time.time()
                if force_full:
                    self._last_full_scan_at = self._last_sync_at
                self._last_report = report
                self._last_error = ""
                self.write_health()
                # T46.2: 终态收尾时间戳（done 快照由引擎回调携带最终计数）。
                with self._progress_lock:
                    self._progress["finished_at"] = time.time()
                logger.info(
                    "Sync completed (%s): %s",
                    "full" if force_full else "incremental",
                    report.summary_text(),
                )
                return report
            except AuthExpiredError as exc:
                self._set_progress_error(str(exc))
                await self._handle_auth_expired(str(exc))
                return None
            except sqlite3.ProgrammingError as exc:
                # 账号停止/热重载后残留线程触碰已关闭的 state.db（停止语义：
                # 5s 后不再等待同步周期跑完，0.1.7）——WAL 原子提交数据无损，
                # 属预期中止：降噪为 INFO，不写健康、不通知、不留裸 traceback（T31.9）
                logger.info("Sync aborted after account stop: %s", exc)
                self._set_progress_error("已中止（账号停止或重载）")
                return None
            except Exception as exc:
                self._last_error = str(exc)
                self._set_progress_error(str(exc))
                self.write_health()
                logger.exception("Sync run failed: %s", exc)
                self.notifier.notify(
                    "sync_error",
                    f"{self.platform_label}同步异常",
                    f"同步执行失败: {exc}",
                )
                return None

    def request_immediate_sync(self) -> None:
        """Wake the scheduler from a non-asyncio thread (e.g. HTTP handler).

        asyncio.Event.set() is not thread-safe: called from a plain thread it
        flips the flag but never wakes the event loop's selector, so a waiting
        scheduler_loop keeps sleeping until its cron timeout and the web
        "trigger sync" button silently does nothing (T35 real-machine finding).
        """
        loop = self._loop
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(self._immediate_sync_event.set)
        else:
            self._immediate_sync_event.set()

    async def scheduler_loop(self) -> None:
        """Wait for valid auth and execute syncs on startup + cron/watch schedule."""
        await self._auth_ready_event.wait()
        if self._stop_event.is_set():
            return

        if self.config.run_on_startup:
            await self.execute_sync_once(mode="startup")

        while not self._stop_event.is_set():
            if not self._auth_valid:
                await self._auth_ready_event.wait()
                if self._stop_event.is_set():
                    break

            wait_sec: float
            if self._cron_schedule is not None:
                now_dt = datetime.now(tz=self._tz)
                next_dt = self._cron_schedule.next_after(now_dt, self.config.timezone)
                wait_sec = max(1.0, (next_dt - now_dt).total_seconds())
                logger.info("Next scheduled sync at %s (%s)", next_dt.isoformat(), self._cron_schedule.expression)
            elif self.config.watch_interval is not None and self.config.watch_interval > 0:
                wait_sec = float(self.config.watch_interval)
                logger.info("Next scheduled sync in %ds", int(wait_sec))
            else:
                # Default fallback if neither cron nor watch_interval was given in daemon mode.
                wait_sec = 7200.0
                logger.info("Next scheduled sync in %ds", int(wait_sec))

            # Consume AFTER the wait: clearing before it would wipe a trigger
            # that arrived while this iteration was still running.
            done, pending = await asyncio.wait(
                [
                    asyncio.create_task(self._stop_event.wait()),
                    asyncio.create_task(self._immediate_sync_event.wait()),
                ],
                timeout=wait_sec,
                return_when=asyncio.FIRST_COMPLETED,
            )
            triggered = self._immediate_sync_event.is_set()
            self._immediate_sync_event.clear()
            for t in pending:
                t.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            for t in done:
                t.result()

            if self._stop_event.is_set():
                break

            if not self._auth_valid:
                continue

            await self.execute_sync_once(
                mode="immediate" if triggered else "scheduled"
            )

    async def run_forever(self) -> None:
        """Start keep-alive and scheduler loops until SIGTERM/SIGINT."""
        loop = asyncio.get_running_loop()
        self._loop = loop
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self.request_stop)
            except (NotImplementedError, RuntimeError):
                pass

        self.write_health()
        try:
            await asyncio.gather(
                self.keepalive_loop(),
                self.scheduler_loop(),
            )
        finally:
            self.write_health()
