#!/usr/bin/env python3
"""T43: 同步轮次可观测性日志测试。

- T43.1 daemon.execute_sync_once 入口打 "Sync started (mode=..., scan=...)"
- T43.2 引擎分页扫描首页 + 每 5 页打 "scan progress: album=... page=... scanned=... pending=..."

运行：PYTHONPATH=app/server python3 -m unittest tests.test_sync_observability -v
"""
from __future__ import annotations

import asyncio
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent.parent / "app" / "server"
sys.path.insert(0, str(SERVER_DIR))

from hwcloudpd.auth import AuthManager
from hwcloudpd.daemon import SyncDaemon
from hwcloudpd.models import MediaStub, SyncConfig, SyncReport
from hwcloudpd.store import StateStore
from hwcloudpd.sync import SyncEngine


def _stub(n: int) -> MediaStub:
    return MediaStub(
        unique_id=f"uid-{n}",
        album_id="alb-1",
        album_name="相机",
        file_type="1",
        create_time_ms=1700000000000,
        file_name=f"IMG_{n:04d}.jpg",
    )


class _FakePageClient:
    """iter_simple_files 返回固定页数的假数据（每页 per_page 条）。"""

    def __init__(self, pages: int, per_page: int = 3) -> None:
        self._pages = pages
        self._per_page = per_page

    def iter_simple_files(self, album_id, **kwargs):
        counter = 0
        for _ in range(self._pages):
            page = [_stub(counter + i) for i in range(self._per_page)]
            counter += self._per_page
            yield page


class _FakeStore:
    def is_synced_and_present(self, uid, directory, photo_size):
        return False


class _StubNotifier:
    def __init__(self) -> None:
        self.notifications: list = []

    def notify(self, *args, **kwargs) -> None:
        self.notifications.append(args)


class ScanProgressLogTest(unittest.TestCase):
    """T43.2：分页扫描进度日志（首页 + 每 5 页一条）。"""

    def _engine(self, pages: int) -> SyncEngine:
        tmp = Path(tempfile.mkdtemp(prefix="obs-scan-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        return SyncEngine(
            SyncConfig(directory=tmp),
            client=_FakePageClient(pages),
            store=_FakeStore(),
        )

    def _collect(self, engine: SyncEngine):
        return engine._collect_pending_from_source(
            album_id="alb-1",
            album_name="相机",
            album_version="",
            owner_id=None,
            query_type=None,
            excluded_ids=set(),
            name_by_id={},
            seen_uids=set(),
            previously_synced_uids=set(),
            effective_until_found=None,
            recent_remaining=[None],
            report=SyncReport(),
        )

    def test_first_and_every_5th_page_logged(self):
        engine = self._engine(12)
        with self.assertLogs("hwcloudpd.sync", level="INFO") as logs:
            pending = self._collect(engine)
        self.assertEqual(len(pending), 36, "12 页 × 3 条应全部进入 pending")
        progress = [m for m in logs.output if "scan progress" in m]
        self.assertEqual(len(progress), 3, f"12 页应打第 1/5/10 页共 3 条: {progress}")
        self.assertIn("page=1 ", progress[0])
        self.assertIn("page=5 ", progress[1])
        self.assertIn("page=10 ", progress[2])

    def test_single_page_still_logged(self):
        engine = self._engine(1)
        with self.assertLogs("hwcloudpd.sync", level="INFO") as logs:
            pending = self._collect(engine)
        self.assertEqual(len(pending), 3)
        progress = [m for m in logs.output if "scan progress" in m]
        self.assertEqual(len(progress), 1)
        self.assertIn("album=相机", progress[0])


class _OkEngine:
    def run_once(self, force_full_scan: bool = False, progress_cb=None) -> SyncReport:
        return SyncReport(downloaded=1)


class SyncStartedLogTest(unittest.TestCase):
    """T43.1：轮次开始日志（mode 可辨、先于完成日志）。"""

    def _make_daemon(self) -> SyncDaemon:
        tmp = Path(tempfile.mkdtemp(prefix="obs-daemon-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        return SyncDaemon(
            SyncConfig(config_dir=tmp, directory=tmp, full_scan_interval_hours=None),
            AuthManager(tmp),
            type("StubClient", (), {"heartbeat_check": staticmethod(lambda: True)})(),
            StateStore(tmp / "state.db"),
            _StubNotifier(),
            engine_factory=lambda: _OkEngine(),
        )

    def test_started_log_default_scheduled(self):
        d = self._make_daemon()
        with self.assertLogs("hwcloudpd.daemon", level="INFO") as logs:
            report = asyncio.run(d.execute_sync_once())
        self.assertIsNotNone(report)
        started = [m for m in logs.output if "Sync started" in m]
        completed = [m for m in logs.output if "Sync completed" in m]
        self.assertEqual(len(started), 1, f"应有且仅有一条开始日志: {logs.output}")
        self.assertIn("mode=scheduled", started[0])
        self.assertIn("scan=incremental", started[0])
        self.assertEqual(len(completed), 1)
        self.assertLess(
            logs.output.index(started[0]),
            logs.output.index(completed[0]),
            "开始日志必须先于完成日志",
        )

    def test_started_log_mode_startup(self):
        d = self._make_daemon()
        with self.assertLogs("hwcloudpd.daemon", level="INFO") as logs:
            asyncio.run(d.execute_sync_once(mode="startup"))
        self.assertTrue(
            any("Sync started (mode=startup" in m for m in logs.output),
            f"应记录 startup 模式: {logs.output}",
        )


if __name__ == "__main__":
    unittest.main()
