#!/usr/bin/env python3
"""打包 AlbumSync.fpk（飞牛 fnOS 应用包）。

流程：
1. 校验引擎已 vendor（app/server/hwcloudpd 存在）且补丁标记在位
2. 清理 app/ 下 __pycache__ / *.pyc / .DS_Store
3. 校验 app/ 内无运行时用户配置（config.json / auth.json / curl.txt 等）
4. 调用 tools/fnpack.exe build 打包（自动生成 app.tgz）
5. 校验 .fpk 内容布局（app.tgz / cmd / config / manifest / ICON）与文件行尾
6. 产物重命名为 AlbumSync_<version>.fpk

用法：python tools/build_fpk.py
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
APP_DIR = PROJECT_ROOT / "app"
FNPACK = PROJECT_ROOT / "tools" / "fnpack.exe"
ENGINE_MARKERS = ("cas_auth.py", "daemon.py", "client.py")
ICLOUD_MARKERS = (
    "__init__.py",
    "icloud_client.py",
    "vendor/pyicloud_ipd/base.py",
    "vendor/pyicloud_ipd/services/photos.py",
    "vendor/foundation/__init__.py",
    "vendor/requests/__init__.py",
    "vendor/licenses/icloudpd-LICENSE.md",
    "vendor/source.json",
)

# 运行时生成的用户数据/凭据，绝不能打进包里（FreePower 教训）
RUNTIME_FILES = (
    "config.json", "auth.json", "curl.txt", "cas_pending_2fa.json",
    "cas_cookies.lwp", "cas_state.json", "state.db", "state.db-wal",
    "state.db-shm", "health.json",
)
REQUIRED_FPK_ENTRIES = ("manifest", "cmd/main", "config/privilege", "config/resource",
                        "ICON.PNG", "ICON_256.PNG", "app.tgz")


def fail(msg: str) -> int:
    print(f"[ERROR] {msg}")
    return 1


def clean_junk() -> None:
    removed = 0
    for pattern in ("__pycache__", "*.pyc", ".DS_Store"):
        for path in APP_DIR.rglob(pattern):
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            removed += 1
    print(f"[OK] 清理垃圾文件 {removed} 个")


def precheck() -> int:
    engine = APP_DIR / "server" / "hwcloudpd"
    if not engine.is_dir():
        return fail("引擎未 vendor：请先运行 python tools/sync_engine.py")
    missing = [m for m in ENGINE_MARKERS if not (engine / m).is_file()]
    if missing:
        return fail(f"引擎不完整，缺少 {missing}")
    cas = (engine / "cas_auth.py").read_text(encoding="utf-8")
    if cas.count("_select_2fa_channel_and_send") < 4:
        print("[WARN] cas_auth.py 补丁标记偏少，请确认 patches 已应用")
    icloud_dir = APP_DIR / "server" / "providers" / "icloud"
    missing = [m for m in ICLOUD_MARKERS if not (icloud_dir / m).is_file()]
    if missing:
        return fail(f"iCloud 平台包不完整，缺少 {missing}")
    probe = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, sys.argv[1]); "
         "import providers.icloud; "
         "from providers.icloud.icloud_client import ICloudClient",
         str(APP_DIR / "server")],
        capture_output=True, text=True,
    )
    if probe.returncode != 0:
        return fail(f"iCloud Provider 导入失败（需要 Python >= 3.11）:\n{probe.stderr}")
    print("[OK] iCloud Provider 与 vendor 依赖导入成功")
    for junk in RUNTIME_FILES:
        for path in APP_DIR.rglob(junk):
            return fail(f"app/ 内存在运行时文件 {path}，先删除再打包")
    ui = APP_DIR / "ui"
    for need in ("index.html", "config", "js/platform-icloud.js",
                 "images/icon_256.png", "images/icon_64.png"):
        if not (ui / need).is_file():
            return fail(f"app/ui 缺少 {need}")
    for need in ("manifest", "ICON.PNG", "ICON_256.PNG"):
        if not (PROJECT_ROOT / need).is_file():
            return fail(f"项目根缺少 {need}")
    return 0


def check_lf() -> int:
    bad = []
    for sub in ("cmd", "config"):
        for path in (PROJECT_ROOT / sub).iterdir():
            if path.is_file() and b"\r\n" in path.read_bytes():
                bad.append(path.name)
    if bad:
        return fail(f"以下文件含 CRLF 行尾，需转 LF: {bad}")
    print("[OK] cmd/config 行尾全部为 LF")
    return 0


def build() -> int:
    if not FNPACK.is_file():
        return fail(f"缺少打包工具 {FNPACK}（从 FreePower 复制 fnpack.exe 到 tools/）")
    result = subprocess.run([str(FNPACK), "build", "-d", str(PROJECT_ROOT)],
                            capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        return fail(f"fnpack build 失败:\n{result.stderr}")
    return 0


def verify_fpk() -> int:
    fpks = sorted(PROJECT_ROOT.glob("*.fpk"))
    if not fpks:
        return fail("未找到打包产物 .fpk")
    fpk = fpks[0]
    with tarfile.open(fpk, "r:gz") as tf:
        names = set(tf.getnames())
        missing = [e for e in REQUIRED_FPK_ENTRIES if e not in names]
        if missing:
            return fail(f".fpk 缺少必需条目: {missing}")
        unexpected = [
            n for n in names
            if n.endswith((".md", ".log", ".exe", ".fpk", ".pyc")) or "__pycache__" in n
            or ".DS_Store" in n or n.startswith(".git/") or "/.git/" in n
            or n.startswith(("tools", "patches", "dev-data"))
        ]
        if unexpected:
            return fail(f".fpk 含非交付文件: {unexpected}")
        # 校验 app.tgz 内容
        app_tgz = tf.extractfile("app.tgz")
        with tarfile.open(fileobj=app_tgz, mode="r:gz") as inner:
            inner_names = inner.getnames()
            required = [
                "server/server.py", "server/app_runtime.py", "server/hwcloudpd/daemon.py",
                "ui/index.html", "ui/config", "ui/js/platform-icloud.js",
                "ui/images/icon_256.png",
            ]
            required.extend(f"server/providers/icloud/{m}" for m in ICLOUD_MARKERS)
            for need in required:
                if need not in inner_names:
                    return fail(f"app.tgz 缺少 {need}")
            for junk in RUNTIME_FILES:
                hits = [n for n in inner_names if n.split("/")[-1] == junk]
                if hits:
                    return fail(f"app.tgz 含运行时文件: {hits}")
            print(f"[OK] app.tgz 含 {len(inner_names)} 个条目")
    print(f"[OK] .fpk 校验通过: {fpk.name} ({fpk.stat().st_size / 1024:.0f} KB)")
    print(f"[DONE] 交付物: {fpk}")
    return 0


if __name__ == "__main__":
    if precheck() != 0:
        sys.exit(1)
    clean_junk()
    if check_lf() != 0 or build() != 0 or verify_fpk() != 0:
        sys.exit(1)
