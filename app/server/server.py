#!/usr/bin/env python3
"""AlbumSync 业务后端服务（fnOS 原生应用服务壳，多账号版）。

架构模式（参照 FreePower/LastDiscard 已验证模型）：
- 同时监听 TCP 端口和 Unix domain socket，兼容 fnOS 统一网关
- TCP 端口：供 checkport 健康检查与直连访问
- Unix socket：供 fnOS 网关（nginx）通过 gatewaySocket=app.sock 代理流量
- 进程内组装 SchedulerManager（多账号运行时管理器），每账号后台线程运行 SyncDaemon

API 形态：
  全局：/api/status /api/settings /api/photos_dirs* /api/accounts（列表/创建）
  账号：/api/accounts/{id}[/{status|albums|auth/*|logs|sync/*}]（PUT 更新、DELETE 删除）

启动方式：
  # fnOS 部署模式（TCP + Unix socket，参数顺序与 cmd/main 一致）
  python server.py <ui_dir> <tcp_port> <socket_path> [gateway_prefix]

  # 本地开发模式（仅 TCP）
  TRIM_PKGVAR=./dev-data python server.py   # 或 PORT=9801
"""
from __future__ import annotations

import json
import os
import re
import signal
import socket
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)  # vendored 引擎 app/server/hwcloudpd/

from app_runtime import APP_NAME, APP_VERSION  # noqa: E402
from hwcloudpd.models import AuthExpiredError, InvalidCredentialsError  # noqa: E402
from identity import (  # noqa: E402
    Requestor,
    bind_requestor,
    current_requestor,
    parse_requestor,
)
from scheduler import SchedulerManager  # noqa: E402

MAX_BODY_BYTES = 1 * 1024 * 1024  # 1MB（cURL 粘贴足够）
_ACCOUNT_PATH_RE = re.compile(r"^/api/accounts/([^/]+)(?:/(.+))?$")


# ========== fnOS 网关兼容 ==========

class GatewayMixin:
    """解决 Unix socket 下两个已知问题（FreePower 同款修复）：

    1. address_string 崩溃：Unix socket 的 client_address 是空字符串，
       默认 self.client_address[0] 取首字符会抛 IndexError。
    2. 路径前缀：网关转发请求时路径带 gatewayPrefix（如 /app/AlbumSync），
       需要去掉前缀才能正确路由到业务 API 和静态文件。
    """

    gateway_prefix = "/app/AlbumSync"

    def address_string(self) -> str:
        try:
            if isinstance(self.client_address, str):
                return "unix"
            return self.client_address[0] or "unix"
        except (IndexError, TypeError):
            return "unix"

    def strip_gateway_prefix(self, path: str) -> str:
        prefix = self.gateway_prefix
        if path.startswith(prefix):
            path = path[len(prefix):]
            if not path.startswith("/"):
                path = "/" + path
        return path


# ========== 请求处理器 ==========

class RequestHandler(GatewayMixin, BaseHTTPRequestHandler):
    """业务 API + 静态文件，兼容 fnOS 网关与直连两种访问方式。"""

    static_dir = str(Path(SERVER_DIR).parent / "ui")
    manager: SchedulerManager | None = None

    MIME_TYPES = {
        ".html": "text/html", ".htm": "text/html", ".css": "text/css",
        ".js": "application/javascript", ".json": "application/json",
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".gif": "image/gif", ".svg": "image/svg+xml", ".ico": "image/x-icon",
        ".webp": "image/webp", ".txt": "text/plain", ".md": "text/markdown",
        ".woff": "font/woff", ".woff2": "font/woff2", ".ttf": "font/ttf",
        ".otf": "font/otf", ".xml": "text/xml",
    }

    # --- 安全写入辅助（处理客户端断连） ---

    def handle(self) -> None:  # noqa: D102
        try:
            super().handle()
        except (ConnectionAbortedError, BrokenPipeError, socket.timeout, OSError):
            pass
        except Exception as exc:
            print(f"Handle error: {exc}")

    def safe_send_response(self, code: int) -> None:
        try:
            self.send_response(code)
        except (ConnectionAbortedError, BrokenPipeError, OSError):
            pass

    def safe_send_header(self, keyword: str, value: str) -> None:
        try:
            self.send_header(keyword, value)
        except (ConnectionAbortedError, BrokenPipeError, OSError):
            pass

    def safe_end_headers(self) -> None:
        try:
            self.end_headers()
        except (ConnectionAbortedError, BrokenPipeError, OSError):
            pass

    def safe_write(self, data: bytes) -> None:
        try:
            self.wfile.write(data)
        except (ConnectionAbortedError, BrokenPipeError, OSError):
            pass

    def send_json_response(self, status_code: int, data: dict) -> None:
        try:
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.safe_send_response(status_code)
            self.safe_send_header("Content-Type", "application/json; charset=utf-8")
            self.safe_send_header("Access-Control-Allow-Origin", "*")
            self.safe_send_header("Content-Length", str(len(body)))
            self.safe_end_headers()
            self.safe_write(body)
        except (ConnectionAbortedError, BrokenPipeError, OSError):
            pass

    def send_error_json(self, status_code: int, message: str) -> None:
        self.send_json_response(status_code, {"success": False, "error": message})

    # --- 请求体 ---

    def read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY_BYTES:
            raise ValueError("请求体超过 1MB 限制")
        raw = self.rfile.read(length)
        if not raw.strip():
            return {}
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("请求体必须是 JSON 对象")
        return data

    # --- CORS 预检 ---

    def do_OPTIONS(self) -> None:  # noqa: N802
        try:
            self.safe_send_response(200)
            self.safe_send_header("Access-Control-Allow-Origin", "*")
            self.safe_send_header("Access-Control-Allow-Methods",
                                  "GET, POST, PUT, DELETE, OPTIONS")
            self.safe_send_header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept")
            self.safe_send_header("Access-Control-Max-Age", "86400")
            self.safe_end_headers()
        except Exception:
            pass

    # --- 身份层（T30 路线 A：网关身份头直信，直连=本机 admin） ---

    def begin_request(self) -> Requestor:
        """解析并绑定当前请求身份。Threading 服务器每请求独立线程/上下文，
        manager 方法经 identity.current_requestor() 读取。"""
        requestor = parse_requestor(self.headers)
        bind_requestor(requestor)
        return requestor

    @staticmethod
    def _me_payload(r: Requestor) -> dict:
        return {
            "user_id": r.user_id,
            "username": r.username,
            "is_admin": r.is_admin,
            "via_gateway": r.via_gateway,
            "sees_all": r.sees_all,
        }

    def handle_me(self) -> None:
        """当前请求者身份（前端 T30.5 用于身份显示与可见性推断）。"""
        self.send_json_response(200, {
            "success": True, "me": self._me_payload(current_requestor()),
        })

    def handle_debug_headers(self) -> None:
        """T30.3 诊断端点：经网关访问确认 CGI 注入的身份头取值与防伪造。"""
        r = current_requestor()
        self.send_json_response(200, {
            "success": True,
            "requestor": self._me_payload(r),
            "headers": {k: str(v) for k, v in self.headers.items()},
        })

    # --- 路由分发 ---

    def do_GET(self) -> None:  # noqa: N802
        self.begin_request()
        parsed = urlparse(self.path)
        original_path = parsed.path
        path = self.strip_gateway_prefix(original_path)

        # 根路径补尾斜杠：保证前端相对路径 ./api/... 挂到 /app/AlbumSync/ 下
        if path == "/" and not original_path.endswith("/"):
            try:
                self.send_response(301)
                self.send_header("Location", original_path + "/")
                self.end_headers()
            except (ConnectionAbortedError, BrokenPipeError, OSError):
                pass
            return

        query = parse_qs(parsed.query)
        try:
            if path == "/health":
                self.handle_health()
            elif path == "/api/me":
                self.handle_me()
            elif path == "/api/debug/headers":
                self.handle_debug_headers()
            elif path == "/api/status":
                self.api_get(self.manager.status_snapshot)
            elif path == "/api/settings":
                self.api_get(self.manager.get_settings, wrap_key="settings")
            elif path == "/api/backup/list":
                self.api_get(self.manager.list_backups)
            elif path == "/api/accounts":
                self.api_get(self.manager.list_accounts, wrap_key="accounts")
            elif path == "/api/photos_dirs":
                self.api_get(self.manager.probe_photos_dirs, wrap_key="dirs")
            elif path == "/api/photos_dirs/check":
                target = query.get("path", [""])[0]
                self.api_get(lambda: self.manager.probe_single_dir(target),
                             wrap_key="probe")
            elif path.startswith("/api/accounts/"):
                self.handle_account_get(path, query)
            else:
                self.serve_static_file(path)
        except KeyError as exc:
            self.send_error_json(404, str(exc.args[0] if exc.args else exc))
        except (AuthExpiredError, InvalidCredentialsError) as exc:
            self.handle_auth_error(exc)
        except Exception as exc:
            self.send_error_json(500, f"内部错误: {exc}")

    def do_POST(self) -> None:  # noqa: N802
        self.begin_request()
        path = self.strip_gateway_prefix(urlparse(self.path).path)
        try:
            body = self.read_json_body()
        except ValueError as exc:
            self.send_error_json(400, str(exc))
            return
        except Exception as exc:
            self.send_error_json(400, f"请求体解析失败: {exc}")
            return

        mg = self.manager
        try:
            if path == "/api/accounts":
                self.api_post(mg.create_account, body)
            elif path == "/api/settings":
                self.api_post(mg.save_settings, body)
            elif path == "/api/backup/export":
                self.api_post(mg.export_backup, body)
            elif path == "/api/backup/inspect":
                self.api_post(mg.inspect_backup, body)
            elif path == "/api/backup/import":
                self.api_post(mg.import_backup, body)
            elif path == "/api/photos_dirs/custom":
                self.api_post(mg.add_custom_photos_dir, str(body.get("path") or ""))
            elif path.startswith("/api/accounts/"):
                self.handle_account_post(path, body)
            else:
                self.send_error_json(404, "Not Found")
        except KeyError as exc:
            self.send_error_json(404, str(exc.args[0] if exc.args else exc))
        except Exception as exc:
            self.send_error_json(500, f"内部错误: {exc}")

    def do_PUT(self) -> None:  # noqa: N802
        self.begin_request()
        path = self.strip_gateway_prefix(urlparse(self.path).path)
        try:
            body = self.read_json_body()
        except ValueError as exc:
            self.send_error_json(400, str(exc))
            return
        except Exception as exc:
            self.send_error_json(400, f"请求体解析失败: {exc}")
            return

        mg = self.manager
        try:
            if path == "/api/settings":
                self.api_post(mg.save_settings, body)
            else:
                m = _ACCOUNT_PATH_RE.match(path)
                if m and not m.group(2):
                    self.api_post(mg.update_account, m.group(1), body)
                else:
                    self.send_error_json(404, "Not Found")
        except KeyError as exc:
            self.send_error_json(404, str(exc.args[0] if exc.args else exc))
        except Exception as exc:
            self.send_error_json(500, f"内部错误: {exc}")

    def do_DELETE(self) -> None:  # noqa: N802
        self.begin_request()
        path = self.strip_gateway_prefix(urlparse(self.path).path)
        try:
            m = _ACCOUNT_PATH_RE.match(path)
            if m and not m.group(2):
                self.api_post(self.manager.delete_account, m.group(1))
            else:
                self.send_error_json(404, "Not Found")
        except KeyError as exc:
            self.send_error_json(404, str(exc.args[0] if exc.args else exc))
        except Exception as exc:
            self.send_error_json(500, f"内部错误: {exc}")

    # --- 账号级路由 ---

    def handle_account_get(self, path: str, query: dict) -> None:
        m = _ACCOUNT_PATH_RE.match(path)
        if not m:
            self.send_error_json(404, "Not Found")
            return
        acct, action = m.group(1), m.group(2) or ""
        mg = self.manager
        if action == "":
            self.api_get(lambda: mg.get_account(acct), wrap_key="account")
        elif action == "status":
            self.api_get(lambda: mg.account_status(acct), wrap_key="status")
        elif action == "auth/status":
            self.api_get(lambda: mg.account_auth_status(acct), wrap_key="auth")
        elif action == "auth/qr/poll":
            # 长轮询：lp 挂起最长 ~65s；前端 fetch 需 ≥70s 超时
            self.api_get(lambda: mg.qr_login_status(acct), wrap_key="qr")
        elif action == "albums":
            self.api_get(lambda: mg.list_albums(acct), wrap_key="albums")
        elif action == "logs":
            lines = int(query.get("lines", ["200"])[0])
            self.send_json_response(200, {"success": True, "lines": mg.tail_logs(acct, lines)})
        elif action == "sync/dry-run":
            self.send_json_response(200, {"success": True, "dry_run": mg.dry_run_status(acct)})
        else:
            self.send_error_json(404, "Not Found")

    def handle_account_post(self, path: str, body: dict) -> None:
        m = _ACCOUNT_PATH_RE.match(path)
        if not m:
            self.send_error_json(404, "Not Found")
            return
        acct, action = m.group(1), m.group(2) or ""
        mg = self.manager
        if action == "enable":
            self.api_post(mg.set_account_enabled, acct, bool(body.get("enabled", True)))
        elif action == "disable":
            self.api_post(mg.set_account_enabled, acct, False)
        elif action == "sync/trigger":
            self.api_post(mg.trigger_sync, acct)
        elif action == "sync/dry-run":
            self.api_post(mg.start_dry_run, acct)
        elif action == "auth/login":
            self.api_post(mg.web_login, acct)
        elif action == "auth/2fa":
            self.api_post(mg.submit_2fa, acct, str(body.get("code") or ""))
        elif action == "auth/import-curl":
            self.api_post(mg.import_curl, acct, str(body.get("curl") or ""))
        elif action == "auth/import-longterm":
            self.api_post(mg.import_longterm, acct, body if isinstance(body, dict) else {})
        elif action == "auth/qr/start":
            self.api_post(mg.start_qr_login, acct)
        else:
            self.send_error_json(404, "Not Found")

    def handle_auth_error(self, exc: Exception) -> None:
        """登录态/凭据类错误 → 409，前端据此提示先完成认证。"""
        self.send_json_response(409, {
            "success": False,
            "status": "auth_expired",
            "error": f"登录态无效：{exc}（请先在「认证与安全」登录或导入 cURL）",
        })

    # --- API 结果包装 ---

    def api_get(self, func, *, wrap_key: str | None = None) -> None:
        result = func()
        payload = {"success": True}
        if wrap_key:
            payload[wrap_key] = result
        else:
            payload.update(result if isinstance(result, dict) else {"data": result})
        self.send_json_response(200, payload)

    def api_post(self, func, *args) -> None:
        result = func(*args)
        if isinstance(result, dict) and result.get("status") == "error":
            self.send_json_response(400, {"success": False, **result})
        elif isinstance(result, dict) and result.get("status") == "busy":
            self.send_json_response(409, {"success": False, **result})
        else:
            self.send_json_response(200, {"success": True, **result})

    # --- 健康检查 ---

    def handle_health(self) -> None:
        health = self.manager.service_health() if self.manager else {
            "success": True, "status": "degraded", "app": APP_NAME,
            "version": APP_VERSION, "daemon_running": False, "uptime_sec": 0,
        }
        self.send_json_response(200, health)

    # --- 静态文件服务 ---

    def serve_static_file(self, path: str) -> None:
        content = None
        content_type = None
        full_path = None
        file_ext = ""
        status = 200
        error_msg = None

        try:
            decoded_path = unquote(path.lstrip("/"))
            if decoded_path == "":
                decoded_path = "index.html"

            static_dir = os.path.normpath(self.static_dir)
            full_path = os.path.normpath(os.path.join(static_dir, decoded_path))

            if not full_path.startswith(static_dir):
                status, error_msg = 403, "Forbidden"
            elif not os.path.exists(full_path):
                # SPA 回退：未知非 API 路径回 index.html
                index_path = os.path.join(static_dir, "index.html")
                if os.path.exists(index_path) and not decoded_path.startswith("api/"):
                    full_path, file_ext = index_path, ".html"
                else:
                    status, error_msg = 404, "File not found"
            elif os.path.isdir(full_path):
                index_path = os.path.join(full_path, "index.html")
                if os.path.exists(index_path):
                    full_path = index_path
                else:
                    status, error_msg = 403, "Directory listing not allowed"

            if status == 200:
                file_ext = os.path.splitext(full_path)[1].lower()
                content_type = self.MIME_TYPES.get(file_ext, "application/octet-stream")
                with open(full_path, "rb") as fh:
                    content = fh.read()
        except Exception as exc:
            print(f"Error serving static file: {exc}")
            status, error_msg = 500, "Internal Server Error"

        try:
            if status == 200 and content is not None:
                self.safe_send_response(200)
                self.safe_send_header("Content-Type", content_type)
                self.safe_send_header("Access-Control-Allow-Origin", "*")
                self.safe_send_header("Content-Length", str(len(content)))
                if file_ext in (".html", ".htm"):
                    # HTML 不缓存：升级后立即生效
                    self.safe_send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                else:
                    # 其余静态资源配合前端 ?v= 版本号刷新
                    self.safe_send_header("Cache-Control", "public, max-age=3600")
                self.safe_end_headers()
                self.safe_write(content)
            else:
                self.send_error_json(status, error_msg or "Error")
        except (ConnectionAbortedError, BrokenPipeError, OSError):
            pass

    def log_message(self, fmt: str, *args) -> None:  # 安静模式：默认不刷访问日志
        pass


# ========== Unix socket 服务器（仅 POSIX） ==========

if hasattr(socket, "AF_UNIX"):
    class ThreadingUnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        """多线程 Unix socket 服务器，供 fnOS 网关代理流量。Windows 上不可用。"""

        daemon_threads = True
        allow_reuse_address = True

        def server_bind(self) -> None:
            socketserver.UnixStreamServer.server_bind(self)
            os.chmod(self.server_address, 0o666)  # 允许 nginx（网关）访问
else:
    ThreadingUnixHTTPServer = None  # type: ignore[assignment,misc]


# ========== 启动入口 ==========

def main() -> None:
    if len(sys.argv) >= 4:
        # fnOS 部署模式：<ui_dir> <tcp_port> <socket_path> [gateway_prefix]
        static_dir = sys.argv[1]
        tcp_port = int(sys.argv[2])
        socket_path = sys.argv[3]
        gateway_prefix = sys.argv[4] if len(sys.argv) > 4 else "/app/AlbumSync"
        pkgvar = os.environ.get("TRIM_PKGVAR", "")
        if not pkgvar:
            print("[serve] ERROR: TRIM_PKGVAR not set (deploy mode requires it)", flush=True)
            sys.exit(1)
    else:
        # 本地开发模式：仅 TCP
        tcp_port = int(os.environ.get("PORT", "9801"))
        socket_path = None
        static_dir = str(Path(SERVER_DIR).parent / "ui")
        gateway_prefix = "/app/AlbumSync"
        pkgvar = os.environ.get("TRIM_PKGVAR", str(Path(SERVER_DIR) / "dev-data"))

    RequestHandler.gateway_prefix = gateway_prefix
    RequestHandler.static_dir = static_dir

    manager = SchedulerManager(Path(pkgvar))
    RequestHandler.manager = manager

    stop_event = threading.Event()

    def _handle_signal(signum, _frame) -> None:
        print(f"[serve] received signal {signum}, shutting down...", flush=True)
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _handle_signal)
        except (ValueError, OSError):
            pass

    # TCP 服务器（健康检查 + 直连访问）
    tcp_server = ThreadingHTTPServer(("0.0.0.0", tcp_port), RequestHandler)
    tcp_server.daemon_threads = True
    threading.Thread(target=tcp_server.serve_forever, daemon=True).start()
    print(f"[serve] TCP listening on 0.0.0.0:{tcp_port}", flush=True)
    print(f"[serve] static_dir={static_dir}", flush=True)
    print(f"[serve] gateway_prefix={gateway_prefix}", flush=True)
    print(f"[serve] pkgvar={pkgvar}", flush=True)

    # Unix socket 服务器（fnOS 网关代理，仅 POSIX 平台）
    unix_server = None
    if socket_path and ThreadingUnixHTTPServer is not None:
        if os.path.exists(socket_path):
            os.unlink(socket_path)
        unix_server = ThreadingUnixHTTPServer(socket_path, RequestHandler)
        threading.Thread(target=unix_server.serve_forever, daemon=True).start()
        print(f"[serve] Unix socket listening on {socket_path}", flush=True)

    print(f"[{APP_NAME}] service ready", flush=True)
    try:
        while not stop_event.wait(1.0):
            pass
    except KeyboardInterrupt:
        print("\n[serve] stopping...", flush=True)
    finally:
        tcp_server.shutdown()
        if unix_server is not None:
            unix_server.shutdown()
            try:
                if os.path.exists(socket_path):
                    os.unlink(socket_path)
            except OSError:
                pass
        manager.stop()
        print("[serve] stopped", flush=True)


if __name__ == "__main__":
    main()
