#!/usr/bin/env python3
"""小米下载断点续传单测（T28.4）。

本地 HTTP 服务模拟小米 download_file：
- 无 Range 的 POST → 200 全量内容
- 带 Range: bytes=N- → 206 + 剩余内容（模拟服务端支持续传）
- Range 起点越界 → 416（触发删 part 重下）
- ignore_range 开关 → 无视 Range 总回 200 全量（部分 CDN 行为）
"""
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app" / "server"))

from providers.xiaomi.xiaomi_client import (  # noqa: E402
    XiaomiAuthExpiredError,
    XiaomiClient,
)

TEST_DOMAIN = "127.0.0.1"
FULL_CONTENT = bytes(range(256)) * 16  # 4096 字节确定性内容


def _make_handler(*, ignore_range: bool = False, range_416: bool = False, status: int = 200):
    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)  # 消费 form body（meta）

            range_header = self.headers.get("Range") or ""
            if status in (401, 403):
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if range_header and range_416:
                self.send_response(416)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            start = 0
            if range_header and not ignore_range:
                # "bytes=N-" → N
                try:
                    start = int(range_header.split("=")[1].rstrip("-"))
                except (IndexError, ValueError):
                    start = 0
            if range_header and not ignore_range:
                payload = FULL_CONTENT[start:]
                self.send_response(206)
                self.send_header("Content-Range", f"bytes {start}-{len(FULL_CONTENT) - 1}/{len(FULL_CONTENT)}")
            else:
                payload = FULL_CONTENT
                self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    return _Handler


class XiaomiResumeTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-mires-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.part = self.tmp / "IMG_0001.jpg.part"

    def _start_server(self, **kw) -> XiaomiClient:
        srv = ThreadingHTTPServer((TEST_DOMAIN, 0), _make_handler(**kw))
        self.addCleanup(srv.server_close)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        self.addCleanup(srv.shutdown)
        self.base = f"http://{TEST_DOMAIN}:{srv.server_port}"
        return XiaomiClient(
            {"userId": "1", "serviceToken": "t"},
            session_cookie_domain=TEST_DOMAIN,
            request_delay_ms=0,
        )

    def _url(self) -> str:
        return f"{self.base}/download_file"


class TestDownloadResume(XiaomiResumeTestBase):
    def test_first_download_full(self):
        """无已有 part → 全量下载。"""
        client = self._start_server()
        outcome = client.download_to_file(self._url(), "meta", self.part)
        self.assertEqual(outcome, "downloaded")
        self.assertEqual(self.part.read_bytes(), FULL_CONTENT)

    def test_resume_appends_after_interrupt(self):
        """T28.4c：中断残留 part → 206 续传追加 → 内容完整校验。"""
        client = self._start_server()
        self.part.write_bytes(FULL_CONTENT[:1000])  # 模拟上次中断残留
        outcome = client.download_to_file(self._url(), "meta", self.part)
        self.assertEqual(outcome, "resumed")
        self.assertEqual(self.part.read_bytes(), FULL_CONTENT, "前半残留 + 后半续传必须还原全文")

    def test_server_ignoring_range_rewrites_full(self):
        """服务端不支持 Range（回 200 全量）→ 覆盖重写不追加。"""
        client = self._start_server(ignore_range=True)
        self.part.write_bytes(FULL_CONTENT[:1000])
        outcome = client.download_to_file(self._url(), "meta", self.part)
        self.assertEqual(outcome, "full")
        self.assertEqual(self.part.read_bytes(), FULL_CONTENT)

    def test_416_deletes_part_and_restarts(self):
        """T28.4b：416（Range 起点越界）→ 删 part 全量重来。"""
        client = self._start_server(range_416=True)
        self.part.write_bytes(b"stale-garbage")
        outcome = client.download_to_file(self._url(), "meta", self.part)
        self.assertEqual(outcome, "downloaded")
        self.assertEqual(self.part.read_bytes(), FULL_CONTENT)

    def test_resume_disabled_ignores_existing(self):
        """resume=False：无视已有 part 全量覆盖（重下语义）。"""
        client = self._start_server()
        self.part.write_bytes(FULL_CONTENT[:1000])
        outcome = client.download_to_file(self._url(), "meta", self.part, resume=False)
        self.assertEqual(outcome, "downloaded")
        self.assertEqual(self.part.read_bytes(), FULL_CONTENT)

    def test_401_raises_auth_expired(self):
        client = self._start_server(status=401)
        with self.assertRaises(XiaomiAuthExpiredError):
            client.download_to_file(self._url(), "meta", self.part)


if __name__ == "__main__":
    unittest.main()
