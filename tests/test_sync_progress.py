#!/usr/bin/env python3
"""T46: 每账号同步进度统计测试（进度条 + 百分比 + 预计剩余时间）。

- T46.1 引擎回调：阶段序列（scanning→downloading→done）、总量/完成计数、
  多并发线程安全、回调异常隔离、dry-run 不发 downloading 阶段
- T46.2 daemon 快照：waiting 重置 → 引擎合并 → done/error 终态、eta 派生、
  并发回调一致、快照为副本、空闲返回 None
- T46.3 REST 透出：summary()/status_snapshot() 携带 progress 字段（空闲 None）

运行：PYTHONPATH=app/server python3 -m unittest tests.test_sync_progress -v
"""
from __future__ import annotations

import asyncio
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent.parent / "app" / "server"
sys.path.insert(0, str(SERVER_DIR))
# Windows 解释器无系统 tzdb：注册 icloud vendor 的 tzdata 包（机制同
# providers/icloud/icloud_client.py 导入期 sys.path 注册；全量套件由 icloud
# 测试先行注册，本文件单独运行时必须自备）
_ICLOUD_VENDOR = SERVER_DIR / "providers" / "icloud" / "vendor"
if _ICLOUD_VENDOR.is_dir() and str(_ICLOUD_VENDOR) not in sys.path:
    sys.path.append(str(_ICLOUD_VENDOR))

from hwcloudpd.auth import AuthManager  # noqa: E402
from hwcloudpd.client import DownloadResult  # noqa: E402
from hwcloudpd.daemon import SyncDaemon  # noqa: E402
from hwcloudpd.models import (  # noqa: E402
    AlbumInfo,
    AuthExpiredError,
    MediaItem,
    MediaStub,
    SyncConfig,
    SyncReport,
)
from hwcloudpd.store import StateStore  # noqa: E402
from hwcloudpd.sync import SyncEngine  # noqa: E402

CONTENT = b"sync-progress-payload-0123456789abcdef"


# ---------- 引擎层（T46.1） ----------

def _stub(n: int) -> MediaStub:
    return MediaStub(
        unique_id=f"uid-{n:03d}",
        album_id="alb-1",
        album_name="相机",
        file_type="1",
        create_time_ms=1700000000000,
        file_name=f"IMG_{n:04d}.jpg",
    )


class _FakeClient:
    """端到端假客户端：1 个相册 N 个条目，可选按 unique_id 注入下载失败。"""

    def __init__(self, n_items: int = 3, fail_ids: tuple = (), delay: float = 0.0) -> None:
        self.n_items = n_items
        self.fail_ids = set(fail_ids)
        self.delay = delay

    def list_albums(self, include_stats=False):
        return [AlbumInfo(album_id="alb-1", name="相机", album_version="v1")]

    def iter_simple_files(self, album_id, **kwargs):
        # 时间线补扫（album_id=None）会再取一轮，seen_uids 去重后无副作用
        stubs = [_stub(i) for i in range(self.n_items)]
        yield stubs

    def enrich_metadata(self, stubs):
        return [
            MediaItem(
                unique_id=s.unique_id,
                album_id=s.album_id,
                album_name=s.album_name,
                file_type=s.file_type,
                create_time_ms=s.create_time_ms,
                file_name=s.file_name,
                file_size=len(CONTENT),
            )
            for s in stubs
        ]

    def pre_process(self):
        pass

    def get_download_url(self, item, size):
        # 失败标记编码进 URL（download_to_part 拿不到 item，多并发下也不能串号）
        if item.unique_id in self.fail_ids:
            return f"http://cdn.example/fail/{item.unique_id}"
        return "http://cdn.example/download"

    def download_to_part(self, url, part_path):
        if self.delay:
            time.sleep(self.delay)
        if "/fail/" in url:
            raise RuntimeError(f"simulated download failure: {url.rsplit('/', 1)[-1]}")
        Path(part_path).write_bytes(CONTENT)
        return DownloadResult(bytes_written=len(CONTENT), sha256_hex=None, md5_hex=None)


class _FakeStore:
    def is_synced_and_present(self, uid, directory, photo_size):
        return False

    def find_by_rel_path(self, rel_path):
        return None

    def upsert_downloaded(self, item, *args, **kwargs):
        pass


class _CollectCb:
    """线程安全的进度事件收集器（多并发下载线程并发调用）。"""

    def __init__(self) -> None:
        self.events: list[dict] = []
        self.lock = threading.Lock()

    def __call__(self, fields: dict) -> None:
        with self.lock:
            self.events.append(dict(fields))


def _engine(tmp: Path, client: _FakeClient, **cfg) -> SyncEngine:
    return SyncEngine(SyncConfig(directory=tmp, **cfg), client=client, store=_FakeStore())


class EngineProgressCallbackTest(unittest.TestCase):
    """T46.1：run_once 进度回调三阶段语义。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="prog-engine-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_phase_sequence_and_counts(self):
        cb = _CollectCb()
        report = _engine(self.tmp, _FakeClient(n_items=3)).run_once(progress_cb=cb)
        self.assertEqual(report.downloaded, 3)
        phases = [e["phase"] for e in cb.events]
        self.assertEqual(phases[0], "scanning", "首事件必须是 scanning")
        self.assertEqual(phases[-1], "done", "末事件必须是 done")
        self.assertIn("downloading", phases)
        # downloading 起点带 total；done 终点带最终计数
        dl = [e for e in cb.events if e["phase"] == "downloading"]
        self.assertEqual(dl[0]["total"], 3)
        self.assertEqual(dl[0]["done"], 0)
        self.assertEqual(cb.events[-1]["done"], 3)
        self.assertEqual(cb.events[-1]["failed"], 0)
        # 完成计数单调不减（单并发路径严格递增）
        dones = [e.get("done", 0) for e in dl]
        self.assertEqual(dones, sorted(dones))
        self.assertEqual(dones[-1], 3)
        # 无回调默认路径零影响
        report2 = _engine(self.tmp, _FakeClient(n_items=2)).run_once()
        self.assertEqual(report2.downloaded, 2)

    def test_concurrent_thread_safety(self):
        cb = _CollectCb()
        report = _engine(
            self.tmp, _FakeClient(n_items=12, delay=0.005), download_concurrency=4
        ).run_once(progress_cb=cb)
        self.assertEqual(report.downloaded, 12)
        dl = [e for e in cb.events if e["phase"] == "downloading"]
        self.assertTrue(dl, "并发路径必须上报 downloading 事件")
        self.assertEqual(dl[-1]["done"] + dl[-1]["failed"], 12, "最终快照计数必须齐全")

    def test_failure_counted_in_snapshot(self):
        cb = _CollectCb()
        report = _engine(
            self.tmp, _FakeClient(n_items=4, fail_ids=("uid-001", "uid-003"))
        ).run_once(progress_cb=cb)
        self.assertEqual(report.downloaded, 2)
        self.assertEqual(report.failed, 2)
        self.assertEqual(cb.events[-1]["phase"], "done")
        self.assertEqual(cb.events[-1]["done"], 2)
        self.assertEqual(cb.events[-1]["failed"], 2)
        # 失败条目同样出现在事件流（failed 计数随事件递增）
        self.assertTrue(any(e.get("failed") == 1 for e in cb.events if e["phase"] == "downloading"))

    def test_callback_exception_does_not_affect_sync(self):
        def bad_cb(fields):
            raise RuntimeError("callback must never break the sync loop")

        report = _engine(self.tmp, _FakeClient(n_items=3)).run_once(progress_cb=bad_cb)
        self.assertEqual(report.downloaded, 3, "回调抛异常不得影响下载结果")
        self.assertEqual(report.failed, 0)

    def test_dry_run_never_emits_downloading_phase(self):
        cb = _CollectCb()
        report = _engine(self.tmp, _FakeClient(n_items=3), dry_run=True).run_once(progress_cb=cb)
        self.assertEqual(report.downloaded, 3)
        phases = {e["phase"] for e in cb.events}
        self.assertNotIn("downloading", phases, "dry-run 纯预览不得发下载阶段")
        self.assertIn("scanning", phases)


# ---------- daemon 层（T46.2） ----------

class _StubNotifier:
    def __init__(self) -> None:
        self.notifications: list = []

    def notify(self, *args, **kwargs) -> None:
        self.notifications.append(args)


class _ScriptedEngine:
    """按脚本回调进度事件；可选注入异常模拟失败轮次。"""

    def __init__(self, exc: Exception | None = None, downloaded: int = 3) -> None:
        self.exc = exc
        self.downloaded = downloaded
        self.got_cb = None

    def run_once(self, force_full_scan: bool = False, progress_cb=None) -> SyncReport:
        self.got_cb = progress_cb
        if progress_cb:
            progress_cb({"phase": "scanning"})
            if not isinstance(self.exc, Exception):
                if self.downloaded > 0:
                    progress_cb({"phase": "downloading", "total": 3, "done": 0, "failed": 0})
                    progress_cb({"phase": "downloading", "total": 3, "done": self.downloaded,
                                 "failed": 0, "current_file": "IMG_0003.jpg"})
                progress_cb({"phase": "done", "done": self.downloaded, "failed": 0})
        if isinstance(self.exc, Exception):
            raise self.exc
        return SyncReport(downloaded=self.downloaded)


class DaemonProgressSnapshotTest(unittest.TestCase):
    """T46.2：daemon 进度快照状态机。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="prog-daemon-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _daemon(self, engine) -> SyncDaemon:
        return SyncDaemon(
            SyncConfig(config_dir=self.tmp, directory=self.tmp, full_scan_interval_hours=None),
            AuthManager(self.tmp),
            type("StubClient", (), {"heartbeat_check": staticmethod(lambda: True)})(),
            StateStore(self.tmp / "state.db"),
            _StubNotifier(),
            engine_factory=lambda: engine,
        )

    def test_idle_snapshot_is_none(self):
        d = self._daemon(_ScriptedEngine())
        self.assertIsNone(d.progress_snapshot(), "从未同步时快照必须为 None")

    def test_full_state_machine_via_execute(self):
        engine = _ScriptedEngine()
        d = self._daemon(engine)
        report = asyncio.run(d.execute_sync_once())
        self.assertIsNotNone(report)
        self.assertIs(engine.got_cb.__self__, d, "回调必须绑定本 daemon 实例")
        self.assertIs(engine.got_cb.__func__, SyncDaemon._on_engine_progress)
        snap = d.progress_snapshot()
        self.assertEqual(snap["phase"], "done")
        self.assertEqual(snap["done"], 3)
        self.assertEqual(snap["failed"], 0)
        self.assertEqual(snap["current_file"], "IMG_0003.jpg")
        self.assertIsNotNone(snap["started_at"])
        self.assertIsNotNone(snap["finished_at"])
        self.assertIsNotNone(snap["download_started_at"])

    def test_waiting_resets_stale_fields(self):
        d = self._daemon(_ScriptedEngine(downloaded=0))
        # 上一轮遗留的陈旧计数字段
        d._on_engine_progress({"phase": "done", "done": 9, "failed": 1})
        d._reset_progress_waiting(time.time())
        snap = d.progress_snapshot()
        self.assertEqual(snap["phase"], "waiting")
        self.assertNotIn("done", snap)
        self.assertNotIn("total", snap)
        # 本轮引擎只发 scanning+done（0 项下载）→ done 计数归零而非遗留 9
        asyncio.run(d.execute_sync_once())
        snap = d.progress_snapshot()
        self.assertEqual(snap["phase"], "done")
        self.assertEqual(snap["done"], 0)

    def test_error_terminal_states(self):
        d = self._daemon(_ScriptedEngine(exc=ValueError("boom")))
        asyncio.run(d.execute_sync_once())
        snap = d.progress_snapshot()
        self.assertEqual(snap["phase"], "error")
        self.assertIn("boom", snap["error"])
        self.assertIsNotNone(snap["finished_at"])

        d2 = self._daemon(_ScriptedEngine(exc=AuthExpiredError("session expired")))
        asyncio.run(d2.execute_sync_once())
        snap2 = d2.progress_snapshot()
        self.assertEqual(snap2["phase"], "error")
        self.assertIn("session expired", snap2["error"])

    def test_eta_and_speed_derived_on_read(self):
        d = self._daemon(_ScriptedEngine())
        d._on_engine_progress({"phase": "downloading", "total": 4, "done": 1, "failed": 0})
        with d._progress_lock:
            d._progress["download_started_at"] = time.time() - 60.0
        snap = d.progress_snapshot()
        self.assertAlmostEqual(snap["eta_sec"], 180.0, delta=6.0, msg="60s 完成 1/4 → 剩余约 180s")
        self.assertAlmostEqual(snap["speed_per_min"], 1.0, delta=0.1)
        # 非 downloading 阶段不派生 eta
        d._on_engine_progress({"phase": "done", "done": 4, "failed": 0})
        snap2 = d.progress_snapshot()
        self.assertNotIn("eta_sec", snap2)

    def test_snapshot_is_a_copy(self):
        d = self._daemon(_ScriptedEngine())
        d._on_engine_progress({"phase": "downloading", "total": 4, "done": 2, "failed": 0})
        snap = d.progress_snapshot()
        snap["done"] = 999
        self.assertEqual(d.progress_snapshot()["done"], 2, "快照必须是内部状态的副本")

    def test_concurrent_callback_merge(self):
        d = self._daemon(_ScriptedEngine())
        def worker(base: int) -> None:
            for i in range(1, 101):
                d._on_engine_progress({"phase": "downloading", "total": 800,
                                       "done": base + i, "failed": 0})
        threads = [threading.Thread(target=worker, args=(t * 100,)) for t in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        snap = d.progress_snapshot()
        self.assertEqual(snap["total"], 800)
        self.assertTrue(0 < snap["done"] <= 800)


# ---------- REST 层（T46.3） ----------

class _FakeDaemonWithProgress:
    def __init__(self, snapshot) -> None:
        self._snap = snapshot

    def progress_snapshot(self):
        return self._snap

    def request_stop(self):
        pass  # mgr.stop() → rt.stop() 需要 daemon 侧停止接口


class RestProgressFieldTest(unittest.TestCase):
    """T46.3：summary()/status_snapshot() 携带 progress 字段。"""

    def setUp(self) -> None:
        sys.path.insert(0, str(SERVER_DIR))
        import shutil as _sh
        from scheduler import SchedulerManager
        self.tmp = Path(tempfile.mkdtemp(prefix="prog-rest-"))
        self.mgr = SchedulerManager(self.tmp)
        self.addCleanup(_sh.rmtree, self.tmp, ignore_errors=True)

    def tearDown(self) -> None:
        self.mgr.stop()

    def test_summary_and_status_carry_progress(self):
        result = self.mgr.create_account({"name": "进度号", "username": "u", "password": "p"})
        self.assertEqual(result["status"], "ok")
        rt = self.mgr._runtimes[result["account"]["id"]]
        # 账号创建即停用（T29.1）→ 无 daemon → 空闲 None
        self.assertIsNone(rt._daemon)
        self.assertIsNone(rt.summary()["progress"])
        self.assertIsNone(rt.status_snapshot()["progress"])
        # 注入带进度的假 daemon → 两个出口都透出同一快照
        rt._daemon = _FakeDaemonWithProgress(
            {"phase": "downloading", "total": 4, "done": 2, "failed": 0}
        )
        self.assertEqual(rt.summary()["progress"]["phase"], "downloading")
        self.assertEqual(rt.status_snapshot()["progress"]["done"], 2)

    def test_progress_exception_swallowed(self):
        class _Broken:
            def progress_snapshot(self):
                raise RuntimeError("x")

            def request_stop(self):
                pass
        result = self.mgr.create_account({"name": "异常号", "username": "u", "password": "p"})
        rt = self.mgr._runtimes[result["account"]["id"]]
        rt._daemon = _Broken()
        self.assertIsNone(rt.summary()["progress"], "快照异常必须静默降级为 None")


if __name__ == "__main__":
    unittest.main()
