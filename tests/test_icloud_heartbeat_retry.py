#!/usr/bin/env python3
"""T42 iCloud 心跳连接抖动重试单元测试（mock list_albums，无真实网络）。

运行：PYTHONPATH=app/server python3 -m pytest tests/test_icloud_heartbeat_retry.py -q
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SERVER_DIR = Path(__file__).resolve().parent.parent / "app" / "server"
sys.path.insert(0, str(SERVER_DIR))

from pyicloud_ipd.exceptions import PyiCloudConnectionException  # noqa: E402

from hwcloudpd.models import AuthExpiredError, HwCloudError  # noqa: E402
from providers.icloud.icloud_client import ICloudClient  # noqa: E402


def _bare_client() -> ICloudClient:
    client = object.__new__(ICloudClient)  # 绕过重构造器，仅测 heartbeat 行为
    client.apple_id = "test@icloud.com"
    return client


class IcloudHeartbeatRetryTest(unittest.TestCase):
    def test_transient_recovered_on_retry(self):
        """T42.2：单发连接抖动 → 退避重试一次即恢复，不产生告警。"""
        c = _bare_client()
        calls = {"n": 0}

        def list_albums():
            calls["n"] += 1
            if calls["n"] == 1:
                raise PyiCloudConnectionException("conn reset")
            return [{"id": "a", "name": "Recent", "is_virtual": False}]

        c.list_albums = list_albums
        with patch("providers.icloud.icloud_client.time.sleep") as sl:
            self.assertTrue(c.heartbeat())
        sl.assert_called_once()
        self.assertEqual(calls["n"], 2)

    def test_persistent_failure_raises_translated(self):
        """持续断网：重试仍失败 → 翻译为 HwCloudError 上抛（daemon 照常警告）。"""
        c = _bare_client()

        def list_albums():
            raise PyiCloudConnectionException("down")

        c.list_albums = list_albums
        with patch("providers.icloud.icloud_client.time.sleep") as sl:
            with self.assertRaises(HwCloudError) as ctx:
                c.heartbeat()
        self.assertIn("网络请求失败", str(ctx.exception))
        sl.assert_called_once()  # 重试过一次才放弃

    def test_auth_error_no_retry(self):
        """鉴权类错误不走连接重试（避免无谓退避），直接上抛。"""
        c = _bare_client()
        calls = {"n": 0}

        def list_albums():
            calls["n"] += 1
            raise AuthExpiredError("iCloud 会话不存在或已失效")

        c.list_albums = list_albums
        with patch("providers.icloud.icloud_client.time.sleep") as sl:
            with self.assertRaises(AuthExpiredError):
                c.heartbeat()
        sl.assert_not_called()
        self.assertEqual(calls["n"], 1)


if __name__ == "__main__":
    unittest.main()
