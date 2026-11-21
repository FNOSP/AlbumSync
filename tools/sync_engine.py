#!/usr/bin/env python3
"""同步引擎代码：从原仓库 hwcloudpd 复制引擎源码到本项目的 app/server/hwcloudpd，
再应用 patches/ 目录下的补丁。原仓库保持只读，不做任何修改。

用法：
    python tools/sync_engine.py [--check]
        --check  仅校验引擎可同步且补丁可应用，不落盘
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENGINE_REPO = PROJECT_ROOT.parent / "hwcloudpd"  # ../hwcloudpd（clone 根目录）
ENGINE_SRC = ENGINE_REPO / "src" / "hwcloudpd"
DEST = PROJECT_ROOT / "app" / "server" / "hwcloudpd"
PATCHES_DIR = PROJECT_ROOT / "patches"

# 保留本地自定义的文件（同步时从 DEST 清除引擎同名文件，但跳过此清单）
LOCAL_KEEP: set[str] = set()


def sync(check: bool = False) -> int:
    if not ENGINE_SRC.is_dir():
        print(f"[ERROR] 引擎源码目录不存在: {ENGINE_SRC}")
        return 1
    # 原仓库必须干净，防止把未提交的实验性改动带进包里
    try:
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=ENGINE_REPO, capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"[WARN] 无法校验原仓库 git 状态（{exc}），继续同步")
        dirty = ""
    if dirty:
        print(f"[ERROR] 原仓库存在未提交改动，请先还原/提交后再同步:\n{dirty}")
        return 1

    if check:
        print(f"[CHECK] 引擎: {ENGINE_SRC} (干净) -> {DEST}")
        for patch in sorted(PATCHES_DIR.glob("*.patch")):
            print(f"[CHECK] 补丁: {patch.name}")
        return 0

    # 覆盖式复制（不整树删除，避免污染回收站；引擎极少删文件，残留可忽略）
    # T28.3：drvfs(/mnt/e) 上 git apply 存在 mmap/9p 写缓存不一致问题——
    # 补丁「应用成功」但内容不落盘（daemon.py/cas_auth.py 实测复现）。
    # 因此补丁链先在 ext4 中转目录重放，验证通过后整体拷回 DEST。
    with tempfile.TemporaryDirectory(prefix="albumsync-sync-") as td:
        staging = Path(td) / "hwcloudpd"
        shutil.copytree(ENGINE_SRC, staging, dirs_exist_ok=True)
        # 应用补丁：自动探测 strip 级别（patch1 为 a/src/hwcloudpd/... 需 -p3；
        # patch2 为 a/hwcloudpd/... 需 -p2），以 --check 试探后真实应用
        for patch in sorted(PATCHES_DIR.glob("*.patch")):
            chosen = None
            last_err = ""
            for strip in (3, 2, 1):
                probe = subprocess.run(
                    ["git", "apply", f"-p{strip}", "--check", str(patch)],
                    cwd=staging, capture_output=True, text=True,
                )
                if probe.returncode == 0:
                    chosen = strip
                    break
                last_err = probe.stderr.strip()
            if chosen is None:
                print(f"[ERROR] 应用补丁失败 {patch.name}:\n{last_err}")
                return 1
            result = subprocess.run(
                ["git", "apply", f"-p{chosen}", str(patch)],
                cwd=staging, capture_output=True, text=True,
            )
            if result.returncode != 0:
                print(f"[ERROR] 应用补丁失败 {patch.name}:\n{result.stdout}\n{result.stderr}")
                return 1
            print(f"[OK] 已应用补丁 {patch.name} (-p{chosen})")

        # 中转目录 → DEST：逐文件覆盖（行为等价于 copytree dirs_exist_ok）
        for f in sorted(staging.rglob("*")):
            target = DEST / f.relative_to(staging)
            if f.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, target)

    count = sum(1 for _ in DEST.rglob("*.py"))
    print(f"[DONE] 引擎已同步 {count} 个 .py 到 {DEST}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    sys.exit(sync(parser.parse_args().check))
