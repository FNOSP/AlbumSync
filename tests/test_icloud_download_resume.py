#!/usr/bin/env python3
"""iCloud CDN 下载覆盖、断点续传与签名刷新单测（无真实网络）。"""
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app" / "server"))

from hwcloudpd.models import HwCloudError  # noqa: E402
from providers.icloud import ICloudSessionStore  # noqa: E402
from providers.icloud.icloud_client import ICloudClient, requests  # noqa: E402


FULL_CONTENT = bytes(range(256)) * 8


class _FakeResponse:
    def __init__(self, status_code, chunks=(), *, headers=None):
        self.status_code = status_code
        self.chunks = list(chunks)
        self.headers = dict(headers or {})
        self.closed = False

    def iter_content(self, chunk_size=64 * 1024):
        self.requested_chunk_size = chunk_size
        for chunk in self.chunks:
            if isinstance(chunk, Exception):
                raise chunk
            yield chunk

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}", response=self)

    def close(self):
        self.closed = True


class _FakeSession:
    def __init__(self, response):
        self.response = response
        self.cookies = requests.cookies.RequestsCookieJar()
        self.calls = []
        self.closed = False

    def get(self, url, *, headers, stream, timeout):
        self.calls.append({
            "url": url,
            "headers": dict(headers),
            "stream": stream,
            "timeout": timeout,
            "cookies": self.cookies.get_dict(),
        })
        return self.response

    def close(self):
        self.closed = True


class _CdnFactory:
    def __init__(self, *responses):
        self.responses = iter(responses)
        self.sessions = []

    def __call__(self):
        session = _FakeSession(next(self.responses))
        # 即使工厂意外返回带 iCloud cookie 的 session，发请求前也必须隔离清空。
        session.cookies.set("icloud-auth", "secret", domain=".apple.com", path="/")
        self.sessions.append(session)
        return session

    @property
    def calls(self):
        return [call for session in self.sessions for call in session.calls]


def _descriptor(url="https://cdn.example/old", **overrides):
    details = {
        "url": url,
        "asset_id": "asset-1",
        "album_id": "folder-42",
        "size_variant": "original",
    }
    details.update(overrides)
    return json.dumps(details)


class DownloadTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-icloud-download-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.part = self.tmp / "IMG_0001.jpg.part"
        self.store = ICloudSessionStore(self.tmp / "session.json", self.tmp / "cookies.lwp")
        self.store.save({
            "apple_id": "user@example.com",
            "domain": "com",
            "session_token": "trusted-token",
        })
        self.icloud_cookies = requests.cookies.RequestsCookieJar()
        self.icloud_cookies.set("icloud-auth", "secret", domain=".apple.com", path="/")
        self.icloud_session = SimpleNamespace(cookies=self.icloud_cookies)

    def make_client(self, factory):
        client = ICloudClient(
            apple_id="user@example.com",
            password=None,
            domain="com",
            session_path=self.store.auth_file,
            cookiejar_path=self.store.cookie_file,
            store=self.store,
            download_session_factory=factory,
            http_timeout=3.0,
        )
        client._service = SimpleNamespace(session=self.icloud_session)
        return client

    def assert_full_file(self, result):
        self.assertEqual(self.part.read_bytes(), FULL_CONTENT)
        self.assertEqual(result.bytes_written, len(FULL_CONTENT))
        self.assertEqual(result.sha256_hex, hashlib.sha256(FULL_CONTENT).hexdigest())
        self.assertEqual(result.md5_hex, hashlib.md5(FULL_CONTENT).hexdigest())


class TestDownloadAndResume(DownloadTestBase):
    def test_200_overwrites_existing_part(self):
        self.part.write_bytes(b"stale")
        response = _FakeResponse(
            200,
            [FULL_CONTENT[:333], FULL_CONTENT[333:]],
            headers={"Content-Disposition": 'attachment; filename="IMG_0001.jpg"'},
        )
        factory = _CdnFactory(response)
        result = self.make_client(factory).download_to_file(_descriptor(), self.part)

        self.assert_full_file(result)
        self.assertEqual(result.content_disposition_filename, "IMG_0001.jpg")
        self.assertEqual(factory.calls[0]["headers"]["Range"], "bytes=5-")
        self.assertTrue(response.closed)
        self.assertTrue(factory.sessions[0].closed)

    def test_valid_206_appends_and_hashes_whole_file(self):
        offset = 777
        self.part.write_bytes(FULL_CONTENT[:offset])
        response = _FakeResponse(
            206,
            [FULL_CONTENT[offset:offset + 100], FULL_CONTENT[offset + 100:]],
            headers={"Content-Range": f"bytes {offset}-{len(FULL_CONTENT) - 1}/{len(FULL_CONTENT)}"},
        )
        factory = _CdnFactory(response)
        result = self.make_client(factory).download_to_file(_descriptor(), self.part)

        self.assert_full_file(result)
        self.assertEqual(factory.calls[0]["headers"]["Range"], f"bytes={offset}-")

    def test_bad_content_range_restarts_with_full_download(self):
        offset = 123
        bad_headers = (
            "not-a-content-range",
            f"bytes 0-{len(FULL_CONTENT) - offset - 1}/{len(FULL_CONTENT)}",
        )
        for bad_header in bad_headers:
            with self.subTest(content_range=bad_header):
                self.part.write_bytes(FULL_CONTENT[:offset])
                bad = _FakeResponse(
                    206,
                    [b"must-not-be-appended"],
                    headers={"Content-Range": bad_header},
                )
                full = _FakeResponse(200, [FULL_CONTENT])
                factory = _CdnFactory(bad, full)
                result = self.make_client(factory).download_to_file(_descriptor(), self.part)

                self.assert_full_file(result)
                self.assertEqual(len(factory.calls), 2)
                self.assertEqual(factory.calls[0]["headers"]["Range"], f"bytes={offset}-")
                self.assertNotIn("Range", factory.calls[1]["headers"])
                self.assertNotIn(b"must-not-be-appended", self.part.read_bytes())

    def test_416_discards_stale_part_and_retries_full(self):
        self.part.write_bytes(b"x" * (len(FULL_CONTENT) + 100))
        range_error = _FakeResponse(416)
        full = _FakeResponse(200, [FULL_CONTENT])
        factory = _CdnFactory(range_error, full)
        result = self.make_client(factory).download_to_file(_descriptor(), self.part)

        self.assert_full_file(result)
        self.assertEqual(len(factory.calls), 2)
        self.assertIn("Range", factory.calls[0]["headers"])
        self.assertNotIn("Range", factory.calls[1]["headers"])

    def test_interrupted_resume_preserves_partial_file(self):
        offset = 200
        received = FULL_CONTENT[offset:500]
        self.part.write_bytes(FULL_CONTENT[:offset])
        interrupted = _FakeResponse(
            206,
            [received, requests.exceptions.ChunkedEncodingError("simulated connection loss")],
            headers={"Content-Range": f"bytes {offset}-{len(FULL_CONTENT) - 1}/{len(FULL_CONTENT)}"},
        )
        factory = _CdnFactory(interrupted)

        with self.assertRaisesRegex(HwCloudError, "CDN 下载失败"):
            self.make_client(factory).download_to_file(_descriptor(), self.part)
        self.assertEqual(self.part.read_bytes(), FULL_CONTENT[:500])
        self.assertTrue(interrupted.closed, "中断后 response 仍必须关闭")


class TestSignedUrlRefresh(DownloadTestBase):
    def test_401_and_403_refresh_signed_url_once_without_account_invalidation(self):
        for status in (401, 403):
            with self.subTest(status=status):
                old = _FakeResponse(status)
                new = _FakeResponse(200, [FULL_CONTENT])
                factory = _CdnFactory(old, new)
                client = self.make_client(factory)
                client.get_download_url = Mock(return_value=_descriptor("https://cdn.example/new"))
                client.invalidate = Mock()
                original_service = client._service

                result = client.download_to_file(_descriptor(), self.part)

                self.assert_full_file(result)
                self.assertEqual([call["url"] for call in factory.calls], [
                    "https://cdn.example/old", "https://cdn.example/new",
                ])
                client.get_download_url.assert_called_once_with(
                    "asset-1",
                    album_id="folder-42",
                    size_variant="original",
                    refresh=True,
                )
                client.invalidate.assert_not_called()
                self.assertIs(client._service, original_service)
                self.assertTrue(self.store.has_session(apple_id="user@example.com", domain="com"))

    def test_second_authorization_failure_does_not_refresh_again(self):
        factory = _CdnFactory(_FakeResponse(401), _FakeResponse(403))
        client = self.make_client(factory)
        client.get_download_url = Mock(return_value=_descriptor("https://cdn.example/new"))
        client.invalidate = Mock()

        with self.assertRaisesRegex(HwCloudError, "刷新后仍无法下载"):
            client.download_to_file(_descriptor(), self.part)
        self.assertEqual(client.get_download_url.call_count, 1)
        self.assertEqual(len(factory.calls), 2)
        client.invalidate.assert_not_called()
        self.assertTrue(self.store.has_session())


class TestCdnSessionIsolation(DownloadTestBase):
    def test_download_session_never_sends_icloud_cookies(self):
        factory = _CdnFactory(_FakeResponse(200, [FULL_CONTENT]))
        client = self.make_client(factory)
        result = client.download_to_file(_descriptor(), self.part)

        self.assert_full_file(result)
        self.assertEqual(len(factory.sessions), 1)
        cdn_session = factory.sessions[0]
        self.assertIsNot(cdn_session, self.icloud_session)
        self.assertEqual(cdn_session.calls[0]["cookies"], {})
        self.assertNotIn("Cookie", cdn_session.calls[0]["headers"])
        self.assertEqual(self.icloud_cookies.get_dict(), {"icloud-auth": "secret"})


if __name__ == "__main__":
    unittest.main()
