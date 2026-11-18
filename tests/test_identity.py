#!/usr/bin/env python3
"""AlbumSync 身份层单元测试（T30 路线 A：网关身份头直信，不触网）。"""
from __future__ import annotations

import sys
import tempfile
import shutil
import threading
import unittest
from email.message import Message
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent.parent / "app" / "server"
sys.path.insert(0, str(SERVER_DIR))

from identity import (  # noqa: E402
    SYSTEM_REQUESTOR,
    Requestor,
    bind_requestor,
    current_requestor,
    parse_requestor,
)
from scheduler import SchedulerManager  # noqa: E402


def _headers(**kv: str) -> Message:
    m = Message()
    for k, v in kv.items():
        m[k] = v
    return m


class TestParseRequestor(unittest.TestCase):
    def test_no_headers_is_local_admin(self):
        # 无身份头 = 直连 = 本机 admin 信任
        r = parse_requestor(_headers(Host="nas:9801"))
        self.assertEqual(r.user_id, "")
        self.assertTrue(r.is_admin)
        self.assertFalse(r.via_gateway)
        self.assertTrue(r.sees_all)
        self.assertIs(r, SYSTEM_REQUESTOR)

    def test_gateway_headers_parsed(self):
        r = parse_requestor(_headers(
            **{"X-Trim-Userid": "1000", "X-Trim-Username": "alice",
               "X-Trim-Isadmin": "1"}))
        self.assertEqual(r.user_id, "1000")
        self.assertEqual(r.username, "alice")
        self.assertTrue(r.is_admin)
        self.assertTrue(r.via_gateway)
        self.assertTrue(r.sees_all)

    def test_isadmin_value_variants(self):
        for raw in ("1", "true", "TRUE", "Yes", "on"):
            r = parse_requestor(_headers(**{"X-Trim-Userid": "u", "X-Trim-Isadmin": raw}))
            self.assertTrue(r.is_admin, raw)
        for raw in ("0", "false", "", "no"):
            r = parse_requestor(_headers(**{"X-Trim-Userid": "u", "X-Trim-Isadmin": raw}))
            self.assertFalse(r.is_admin, repr(raw))

    def test_normal_user_not_admin(self):
        r = parse_requestor(_headers(
            **{"X-Trim-Userid": "2001", "X-Trim-Username": "bob",
               "X-Trim-Isadmin": "0"}))
        self.assertFalse(r.is_admin)
        self.assertFalse(r.sees_all)

    def test_uid_required_for_gateway_identity(self):
        # 有 Isadmin 但无 Userid → 仍按直连处理（uid 是身份主键）
        r = parse_requestor(_headers(**{"X-Trim-Isadmin": "0"}))
        self.assertFalse(r.via_gateway)

    def test_value_length_capped(self):
        r = parse_requestor(_headers(**{"X-Trim-Userid": "x" * 300,
                                        "X-Trim-Username": "y" * 300}))
        self.assertEqual(len(r.user_id), 128)
        self.assertEqual(len(r.username), 128)


class TestContextBinding(unittest.TestCase):
    def test_default_is_system(self):
        self.assertEqual(current_requestor(), SYSTEM_REQUESTOR)

    def test_bind_then_read(self):
        r = Requestor("42", "carol", False, True)
        bind_requestor(r)
        self.assertIs(current_requestor(), r)
        # 模拟请求结束：重新绑定系统身份
        bind_requestor(SYSTEM_REQUESTOR)
        self.assertEqual(current_requestor(), SYSTEM_REQUESTOR)

    def test_no_leak_across_threads(self):
        barrier = threading.Barrier(2, timeout=5)
        results: dict[str, object] = {}

        def worker_bind():
            bind_requestor(Requestor("77", "dave", False, True))
            barrier.wait()
            results["bound"] = current_requestor().user_id

        def worker_other():
            barrier.wait()
            results["other"] = current_requestor().user_id

        t1 = threading.Thread(target=worker_bind)
        t2 = threading.Thread(target=worker_other)
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(results["bound"], "77")
        self.assertEqual(results["other"], "")


class TestVisibilityHelpers(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-ident-"))
        self.mgr = SchedulerManager(self.tmp)
        self.mgr.create_account({"name": "A", "username": "a", "owner": "1000"})
        self.mgr.create_account({"name": "B", "username": "b", "owner": "2000"})
        self.mgr.create_account({"name": "C", "username": "c"})  # owner=""（存量/无主）

    def tearDown(self) -> None:
        self.mgr.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _bind(self, **kw) -> None:
        bind_requestor(Requestor(
            kw.get("user_id", ""), kw.get("username", ""),
            kw.get("is_admin", False), kw.get("via_gateway", True)))
        self.addCleanup(bind_requestor, SYSTEM_REQUESTOR)

    def _ids(self, accounts: list[dict]) -> set[str]:
        return {a["name"] for a in accounts}

    def test_admin_sees_all(self):
        self._bind(user_id="1000", is_admin=True)
        cfg = self.mgr._load_cfg()
        self.assertEqual(self._ids(self.mgr._visible_accounts(cfg)), {"A", "B", "C"})

    def test_direct_connect_sees_all(self):
        self._bind(via_gateway=False)
        cfg = self.mgr._load_cfg()
        self.assertEqual(self._ids(self.mgr._visible_accounts(cfg)), {"A", "B", "C"})

    def test_normal_user_sees_own_only(self):
        self._bind(user_id="1000", is_admin=False)
        cfg = self.mgr._load_cfg()
        self.assertEqual(self._ids(self.mgr._visible_accounts(cfg)), {"A"})

    def test_orphan_accounts_hidden_from_normal_users(self):
        self._bind(user_id="2000", is_admin=False)
        cfg = self.mgr._load_cfg()
        self.assertEqual(self._ids(self.mgr._visible_accounts(cfg)), {"B"})

    def test_require_visible_account_404_semantics(self):
        self._bind(user_id="1000", is_admin=False)
        cfg = self.mgr._load_cfg()
        # 自己的账号可见
        self.assertIsNotNone(self.mgr._require_visible_account(cfg, self._aid("A")))
        # 他人账号与不存在账号一律 KeyError（API 层转 404）
        with self.assertRaises(KeyError):
            self.mgr._require_visible_account(cfg, self._aid("B"))
        with self.assertRaises(KeyError):
            self.mgr._require_visible_account(cfg, "acc-huawei-ffffff")

    def test_is_visible_static(self):
        owner_view = Requestor("1", "u", False, True)
        admin_view = Requestor("1", "u", True, True)
        system = Requestor("", "system", True, False)
        acc = {"owner": "1"}
        self.assertTrue(SchedulerManager._is_visible(acc, owner_view))
        self.assertTrue(SchedulerManager._is_visible(acc, admin_view))
        self.assertTrue(SchedulerManager._is_visible(acc, system))
        self.assertFalse(SchedulerManager._is_visible({"owner": ""}, owner_view))
        self.assertFalse(SchedulerManager._is_visible({"owner": "2"}, owner_view))

    def _aid(self, name: str) -> str:
        cfg = self.mgr._load_cfg()
        for a in cfg["accounts"]:
            if a["name"] == name:
                return a["id"]
        raise AssertionError(name)


class TestApiVisibilityFiltering(unittest.TestCase):
    """T30.4：manager 方法按请求身份过滤（非 owner 一律 404 语义）。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-api-ident-"))
        self.mgr = SchedulerManager(self.tmp)
        self.mgr.create_account({"name": "A", "username": "a", "owner": "1000"})
        self.mgr.create_account({"name": "B", "username": "b", "owner": "2000"})
        self.mgr.create_account({"name": "C", "username": "c"})  # 无主（存量）
        self.aid_a = self._aid("A")
        self.aid_b = self._aid("B")
        self.aid_c = self._aid("C")

    def tearDown(self) -> None:
        self.mgr.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _bind(self, user_id: str, *, is_admin: bool = False,
              via_gateway: bool = True) -> None:
        bind_requestor(Requestor(user_id, "u", is_admin, via_gateway))
        self.addCleanup(bind_requestor, SYSTEM_REQUESTOR)

    def _aid(self, name: str) -> str:
        cfg = self.mgr._load_cfg()
        for a in cfg["accounts"]:
            if a["name"] == name:
                return a["id"]
        raise AssertionError(name)

    def test_list_accounts_filtered(self):
        self._bind("1000")
        names = {a["name"] for a in self.mgr.list_accounts()}
        self.assertEqual(names, {"A"})
        # admin 经网关也全可见
        self._bind("1000", is_admin=True)
        names = {a["name"] for a in self.mgr.list_accounts()}
        self.assertEqual(names, {"A", "B", "C"})
        # status_snapshot 走同一过滤
        self._bind("2000")
        names = {a["name"] for a in self.mgr.status_snapshot()["accounts"]}
        self.assertEqual(names, {"B"})

    def test_get_account_invisible_404(self):
        self._bind("1000")
        self.assertEqual(self.mgr.get_account(self.aid_a)["name"], "A")
        with self.assertRaises(KeyError):
            self.mgr.get_account(self.aid_b)
        with self.assertRaises(KeyError):
            self.mgr.get_account(self.aid_c)  # 无主账号对普通用户不可见

    def test_create_owner_forced_for_normal_user(self):
        self._bind("3000")
        result = self.mgr.create_account({"name": "D", "username": "d",
                                          "owner": "9999"})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["account"]["owner"], "3000")  # payload owner 被忽略
        # admin 可指定 owner（缺省空 = 无主）
        self._bind("1000", is_admin=True)
        result = self.mgr.create_account({"name": "E", "username": "e",
                                          "owner": "2000"})
        self.assertEqual(result["account"]["owner"], "2000")

    def test_update_owner_immutable_for_normal_user(self):
        self._bind("1000")
        result = self.mgr.update_account(self.aid_a, {"owner": "9999",
                                                      "name": "A2"})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["account"]["name"], "A2")
        self.assertEqual(result["account"]["owner"], "1000")  # 归属不可自改
        # admin 可改归属
        self._bind("1000", is_admin=True)
        result = self.mgr.update_account(self.aid_a, {"owner": "2000"})
        self.assertEqual(result["account"]["owner"], "2000")
        self.mgr.update_account(self.aid_a, {"owner": "1000"})  # 还原

    def test_account_level_ops_invisible_404(self):
        self._bind("1000")
        # 可见：正常返回
        self.assertIn("name", self.mgr.account_status(self.aid_a))
        # 不可见：KeyError → API 层 404（覆盖 _require_runtime 的全部转发操作）
        for op in (lambda: self.mgr.account_status(self.aid_b),
                   lambda: self.mgr.account_auth_status(self.aid_b),
                   lambda: self.mgr.tail_logs(self.aid_b),
                   lambda: self.mgr.dry_run_status(self.aid_b),
                   lambda: self.mgr.list_albums(self.aid_b)):
            with self.assertRaises(KeyError):
                op()

    def test_enable_delete_invisible_404(self):
        self._bind("1000")
        with self.assertRaises(KeyError):
            self.mgr.set_account_enabled(self.aid_b, True)
        with self.assertRaises(KeyError):
            self.mgr.delete_account(self.aid_b)
        # 自己的账号可启停/删除
        self.assertEqual(self.mgr.set_account_enabled(self.aid_a, True)["status"], "ok")

    def test_service_health_scoped(self):
        self._bind("1000")
        health = self.mgr.service_health()
        self.assertEqual(health["accounts_total"], 1)  # 仅可见账号计数
        # 系统/直连身份：全量计数
        bind_requestor(SYSTEM_REQUESTOR)
        self.assertEqual(self.mgr.service_health()["accounts_total"], 3)


if __name__ == "__main__":
    unittest.main()
