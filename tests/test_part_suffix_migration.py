#!/usr/bin/env python3
"""T32: 引擎下载临时文件后缀 .hwpart → .aspart 及存量断点自动迁移测试。

运行：PYTHONPATH=app/server python3 -m unittest tests.test_part_suffix_migration -v
"""
from __future__ import annotations

import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent.parent / "app" / "server"
sys.path.insert(0, str(SERVER_DIR))

from hwcloudpd.client import DownloadResult  # noqa: E402
from hwcloudpd.models import MediaItem, SyncConfig  # noqa: E402
from hwcloudpd.sync import SyncEngine  # noqa: E402

CONTENT = b"aspart-migration-payload-0123456789"
UNIQUE_ID = "abcdefg12345"
FILE_NAME = "IMG_0001.jpg"


class _FakeStore:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str]] = []

    def find_by_rel_path(self, rel_path: str):
        return None

    def upsert_downloaded(self, item, *args, **kwargs) -> None:
        self.rows.append((item.unique_id, kwargs.get("local_rel_path", "")))


class _FakeClient:
    """模拟支持断点续传的 provider 下载：已有 part 内容时追加剩余字节。"""

    def __init__(self) -> None:
        self.seen_parts: list[str] = []

    def get_download_url(self, item, size):
        return "http://cdn.example/download"

    def download_to_part(self, url, part_path):
        part = Path(part_path)
        self.seen_parts.append(part.name)
        if part.is_file():
            existing = part.stat().st_size
            with part.open("ab") as fh:
                fh.write(CONTENT[existing:])
        else:
            part.write_bytes(CONTENT)
        return DownloadResult(
            bytes_written=part.stat().st_size, sha256_hex=None, md5_hex=None
        )


class PartSuffixMigrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="aspart-test-"))
        self.engine = SyncEngine(
            SyncConfig(directory=self.tmp),
            client=_FakeClient(),
            store=_FakeStore(),
        )
        self.item = MediaItem(
            unique_id=UNIQUE_ID,
            album_id="alb-1",
            album_name="相机",
            file_type="1",
            create_time_ms=1700000000000,
            file_name=FILE_NAME,
            file_size=0,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _download(self) -> Path:
        return self.engine._download_single(
            self.item, path_lock=threading.Lock(), reserved_paths=set()
        )

    # create_time_ms=1700000000000 → Asia/Shanghai 2023-11-15，与引擎目录模板一致
    FOLDER = "2023" / Path("11") / "15"

    def test_part_suffix_is_aspart(self):
        target = self._download()
        self.assertTrue(target.is_file())
        self.assertEqual(target.read_bytes(), CONTENT)
        client = self.engine.client
        self.assertEqual(len(client.seen_parts), 1)
        self.assertTrue(client.seen_parts[0].endswith(".aspart"))
        self.assertFalse(client.seen_parts[0].endswith(".hwpart"))
        self.assertEqual(list(self.tmp.rglob("*.hwpart")), [], "不得残留 .hwpart")

    def test_unique_id_with_slash_is_sanitized(self):
        """iCloud 资源 ID 含 / 时不得拼出跨目录的 part 路径（真机 0.3.22 缺陷回归）。"""
        self.item.unique_id = "AbZM/CmMBMDlzR0KaWx"
        target = self._download()
        self.assertTrue(target.is_file())
        self.assertEqual(target.read_bytes(), CONTENT)
        client = self.engine.client
        self.assertEqual(client.seen_parts, [f".{FILE_NAME}.AbZM_Cm.aspart"])
        self.assertEqual(list(self.tmp.rglob("*.hwpart")), [])

    def test_legacy_hwpart_migrated_and_resumed(self):
        """存量 .hwpart 断点必须自动改名并续传，不浪费已下载字节。"""
        legacy = self.tmp / self.FOLDER / f".{FILE_NAME}.{UNIQUE_ID[:7]}.hwpart"
        legacy.parent.mkdir(parents=True)
        offset = 5
        legacy.write_bytes(CONTENT[:offset])
        target = self._download()
        self.assertTrue(target.is_file())
        self.assertEqual(
            target.read_bytes(), CONTENT, "旧断点字节 + 续传必须还原完整内容"
        )
        self.assertFalse(legacy.exists(), "迁移后不得残留旧 .hwpart")
        client = self.engine.client
        self.assertEqual(client.seen_parts, [f".{FILE_NAME}.{UNIQUE_ID[:7]}.aspart"])

    def test_both_present_keeps_aspart_drops_legacy(self):
        """新旧断点并存时以新后缀为准，旧文件视为垃圾丢弃。"""
        folder = self.tmp / self.FOLDER
        folder.mkdir(parents=True)
        legacy = folder / f".{FILE_NAME}.{UNIQUE_ID[:7]}.hwpart"
        current = folder / f".{FILE_NAME}.{UNIQUE_ID[:7]}.aspart"
        legacy.write_bytes(b"stale-junk")
        offset = 4
        current.write_bytes(CONTENT[:offset])
        target = self._download()
        self.assertEqual(target.read_bytes(), CONTENT, "必须续传 .aspart 而非旧 .hwpart")
        self.assertFalse(legacy.exists(), "并存时旧 .hwpart 必须清理")


if __name__ == "__main__":
    unittest.main()
