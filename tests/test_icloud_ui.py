#!/usr/bin/env python3
"""iCloud 前端平台注册与通用 hook 的静态回归测试（不需要浏览器）。"""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = (ROOT / "app" / "ui" / "index.html").read_text(encoding="utf-8")
ICLOUD_UI = (ROOT / "app" / "ui" / "js" / "platform-icloud.js").read_text(encoding="utf-8")


class TestICloudUiHooks(unittest.TestCase):
    def test_platform_module_is_registered_and_loaded(self):
        self.assertIn('PlatformUI.register("icloud"', ICLOUD_UI)
        self.assertIn('<script src="js/platform-icloud.js"></script>', INDEX)
        self.assertNotIn('platform === "icloud"', INDEX)
        self.assertNotIn("platform === 'icloud'", INDEX)

    def test_complete_platform_credentials_survive_save_and_wizard(self):
        self.assertIn("...(cred || {})", INDEX)
        self.assertIn("wiz.input = { ...wiz.input, ...cred, name, platform }", INDEX)
        self.assertIn("body: { ...cred, name, platform }", INDEX)
        self.assertIn("body: { ...cred, name, platform,", INDEX)
        self.assertNotIn("if (cred.username != null)", INDEX)
        self.assertIn('domain: $("f-domain").value === "cn" ? "cn" : "com"', ICLOUD_UI)
        self.assertIn('domain: ($("w-domain") ? $("w-domain").value : wiz.input.domain) === "cn" ? "cn" : "com"', ICLOUD_UI)

    def test_curl_card_uses_generic_capability_hook(self):
        self.assertIn("const supportsCurlImport = !!(mod && mod.applyCurlCopy);", INDEX)
        self.assertIn('$("curl-card").style.display = supportsCurlImport ? "" : "none";', INDEX)
        self.assertNotIn("applyCurlCopy()", ICLOUD_UI)

    def test_apple_login_and_challenge_hooks_exist(self):
        for marker in (
            "iCloudWebLogin()",
            "iCloudSubmit2fa()",
            "iCloudShowChallenge(",
            'a.pending_2fa.flow === "2sa"',
            "accounts/${id}/auth/login",
            "accounts/${curId()}/auth/2fa",
        ):
            self.assertIn(marker, ICLOUD_UI)


if __name__ == "__main__":
    unittest.main()
