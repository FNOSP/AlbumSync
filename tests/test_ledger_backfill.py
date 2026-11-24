#!/usr/bin/env python3
"""T44: 账本-文件一致性补齐（ledger backfill）测试。

落位（os.replace）与写账本之间进程被中断 → 文件在盘、账本无记录的孤儿。
下轮下载循环必须：
- 目标文件存在且大小 == 云端 file_size → 补写账本 + 跳过下载（秒级补账）
- 大小不匹配 → 维持原路径：正常重下并覆盖

运行：PYTHONPATH=app/server python3 -m unittest tests.test_ledger_backfill -v
"""
from __future__ import annotations

import hashlib
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent.parent / "app" / "server"
sys.path.insert(0, str(SERVER_DIR))

from hwcloudpd.client import DownloadResult
from hwcloudpd.models import MediaItem, SyncConfig
from hwcloudpd.sync import SyncEngine

CONTENT = b"ledger-backfill-payload-0123456789"
UNIQUE_ID = "abcdefg12345"
FILE_NAME = "IMG_0001.jpg"


class _FakeStore:
    def __init__(self) -> None:
        self.rows: list = []

    def find_by_rel_path(self, rel_path):
        return None

    def upsert_downloaded(self, item, *args, **kwargs) -> None:
        self.rows.append({"unique_id": item.unique_id, **kwargs})


class _FakeClient:
    def __init__(self, content: bytes = CONTENT) -> None:
        self.content = content
        self.download_calls = 0

    def get_download_url(self, item, size):
        return "http://cdn.example/download"

    def download_to_part(self, url, part_path):
        self.download_calls += 1
        Path(part_path).write_bytes(self.content)
        return DownloadResult(
            bytes_written=len(self.content), sha256_hex=None, md5_hex=None
        )


class LedgerBackfillTest(unittest.TestCase):
    FOLDER = "2023" / Path("11") / "15"

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="backfill-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.item = MediaItem(
            unique_id=UNIQUE_ID,
            album_id="alb-1",
            album_name="相机",
            file_type="1",
            create_time_ms=1700000000000,
            file_name=FILE_NAME,
            file_size=len(CONTENT),
        )

    def _engine(self, client: _FakeClient) -> SyncEngine:
        return SyncEngine(
            SyncConfig(directory=self.tmp),
            client=client,
            store=_FakeStore(),
        )

    def _download(self, engine: SyncEngine) -> Path:
        return engine._download_single(
            self.item, path_lock=threading.Lock(), reserved_paths=set()
        )

    def test_matching_file_backfills_ledger_and_skips_download(self):
        target = self.tmp / self.FOLDER / FILE_NAME
        target.parent.mkdir(parents=True)
        target.write_bytes(CONTENT)
        client = _FakeClient()
        engine = self._engine(client)
        with self.assertLogs("hwcloudpd.sync", level="INFO") as logs:
            result = self._download(engine)
        self.assertEqual(result, target)
        self.assertEqual(client.download_calls, 0, "大小匹配必须跳过下载")
        self.assertEqual(target.read_bytes(), CONTENT, "既有文件不得被改动")
        self.assertEqual(len(engine.store.rows), 1, "必须补写账本")
        self.assertEqual(engine.store.rows[0]["unique_id"], UNIQUE_ID)
        self.assertEqual(
            engine.store.rows[0]["local_sha256"],
            hashlib.sha256(CONTENT).hexdigest(),
            "账本 local_sha256 列 NOT NULL，必须落真实文件哈希",
        )
        self.assertTrue(any("ledger backfilled" in m for m in logs.output))

    def test_size_mismatch_reroutes_to_sized_name_and_downloads(self):
        """孤儿大小不匹配（截断/损坏）→ 不补账，按既有语义改道 <stem>-<size> 重下。"""
        target = self.tmp / self.FOLDER / FILE_NAME
        target.parent.mkdir(parents=True)
        target.write_bytes(b"stale-different-size")
        client = _FakeClient()
        engine = self._engine(client)
        result = self._download(engine)
        self.assertEqual(client.download_calls, 1, "大小不匹配必须正常重下")
        self.assertEqual(
            result.name,
            f"IMG_0001-{len(CONTENT)}.jpg",
            "既有孤儿视为他占 → 改道 sized 文件名",
        )
        self.assertEqual(target.read_bytes(), b"stale-different-size", "孤儿文件不得被改动")
        self.assertEqual(len(engine.store.rows), 1)
        self.assertEqual(engine.store.rows[0]["unique_id"], UNIQUE_ID)


if __name__ == "__main__":
    unittest.main()
