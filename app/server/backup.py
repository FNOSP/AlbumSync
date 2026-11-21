"""凭据备份包（.asbak）打包 / 解包。

容器格式：
    b"ASBK1" | header_len(uint32 BE) | header(JSON) | ciphertext(ChaCha20-Poly1305)

- 整个 zip 被口令派生的密钥加密，明文头只含账号摘要（不含任何凭据值），
  便于导入前预览与 schema 兼容判断。
- 包内不含 state.db / logs / photos：下载索引可由云端重新枚举，且体积可观。

设计见 docs/credential-encryption-and-backup-plan.md。
"""

from __future__ import annotations

import io
import json
import time
import zipfile
from pathlib import Path
from typing import Any, Iterable

import crypto_box as cb
from providers import get_platform_spec

BACKUP_MAGIC = b"ASBK1"
BACKUP_SCHEMA = 1
MAX_CONTAINER_BYTES = 16 * 1024 * 1024

# 未知平台回退清单（历史华为会话文件；正常路径不会走到——账号平台创建时已校验）
LEGACY_SESSION_FILES = ("auth.json", "curl.txt.imported", "cas_cookies.lwp", "cas_state.json")
# manifest 与 secrets 为保留名，不允许作为账号文件名
RESERVED_NAMES = {"manifest.json", "config.json", "secrets.json"}


def session_file_names(platform: str, account_id: str) -> tuple[str, ...]:
    """按账号平台返回需随备份包迁移的会话文件清单。

    清单由各平台在 providers 注册表（PlatformSpec.session_files）声明，
    本模块不感知平台差异（如小米 xiaomi_{id}_auth.json）。
    """
    try:
        spec = get_platform_spec(platform)
    except ValueError:
        return LEGACY_SESSION_FILES
    files = spec.session_files
    return files(str(account_id or "")) if files else LEGACY_SESSION_FILES


class BackupError(Exception):
    """备份包损坏、口令错误或 schema 不兼容。"""


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _strip_secret_fields(account: dict[str, Any]) -> dict[str, Any]:
    data = dict(account)
    data.pop("password", None)
    data.pop("password_enc", None)
    return data


def build_archive(*, pkgvar: Path, settings: dict[str, Any],
                  accounts: Iterable[dict[str, Any]], app_version: str,
                  include_passwords: bool, include_sessions: bool,
                  account_ids: Iterable[str] | None = None) -> tuple[bytes, dict[str, Any]]:
    """生成 zip 字节 + 明文 manifest（用于容器头）。"""
    wanted = set(account_ids) if account_ids else None
    selected = [a for a in accounts if wanted is None or a.get("id") in wanted]
    if not selected:
        raise BackupError("没有可导出的账号")

    pkgvar = Path(pkgvar)
    summary: list[dict[str, Any]] = []
    secrets_map: dict[str, str] = {}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        config_copy = {
            "version": 3,
            "settings": {k: v for k, v in settings.items() if k != "backup_dir"},
            "accounts": [_strip_secret_fields(a) for a in selected],
        }
        zf.writestr("config.json", json.dumps(config_copy, ensure_ascii=False, indent=2))

        for account in selected:
            acc_id = str(account.get("id") or "")
            if not acc_id or acc_id in RESERVED_NAMES:
                raise BackupError(f"账号 id 非法: {acc_id!r}")
            password = str(account.get("password") or "")
            if password:
                secrets_map[acc_id] = password
            has_sessions = False
            if include_sessions:
                acc_dir = pkgvar / "accounts" / acc_id
                platform = str(account.get("platform") or "huawei")
                for name in session_file_names(platform, acc_id):
                    src = acc_dir / name
                    if not src.is_file():
                        continue
                    try:
                        data = src.read_bytes()
                    except OSError as exc:
                        raise BackupError(f"读取 {src} 失败: {exc}") from exc
                    zf.writestr(f"accounts/{acc_id}/{name}", data)
                    has_sessions = True
            summary.append({
                "id": acc_id,
                "platform": str(account.get("platform") or "huawei"),
                "name": str(account.get("name") or acc_id),
                "username": str(account.get("username") or ""),
                "has_password": acc_id in secrets_map,
                "has_sessions": has_sessions,
            })

        if include_passwords and secrets_map:
            zf.writestr("secrets.json",
                        json.dumps(secrets_map, ensure_ascii=False, indent=2))

    manifest = {
        "schema": BACKUP_SCHEMA,
        "app_version": app_version,
        "created_at": _now_iso(),
        "flags": {
            "include_passwords": bool(include_passwords),
            "include_sessions": bool(include_sessions),
        },
        "accounts": summary,
    }
    return buf.getvalue(), manifest


def seal_container(archive: bytes, passphrase: str,
                   manifest: dict[str, Any]) -> bytes:
    """口令加密整包；返回可直接落盘/下载的 .asbak 字节。"""
    if len(passphrase) < 8:
        raise BackupError("导出口令至少 8 个字符")
    key, salt, params = cb.derive_key(passphrase)
    blob = cb.aead_seal(key, archive, aad=BACKUP_MAGIC)
    header = dict(manifest)
    header["kdf"] = {"alg": "scrypt", **params, "salt": cb.b64e(salt)}
    header["aead"] = {"alg": "chacha20poly1305", "nonce_len": cb.NONCE_LEN}
    header_bytes = json.dumps(header, ensure_ascii=False).encode("utf-8")
    if len(header_bytes) > 0xFFFFFF:
        raise BackupError("备份头过大")
    import struct
    return BACKUP_MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + blob


def read_header(blob: bytes) -> dict[str, Any]:
    """只读明文头（不校验口令），用于 UI 预检文件类型。"""
    import struct
    if not blob.startswith(BACKUP_MAGIC):
        raise BackupError("不是有效的 AlbumSync 备份包")
    if len(blob) < 9:
        raise BackupError("备份包长度异常")
    header_len = struct.unpack(">I", blob[5:9])[0]
    body = blob[9:]
    if header_len > len(body):
        raise BackupError("备份包头长度异常")
    try:
        header = json.loads(body[:header_len].decode("utf-8"))
    except Exception as exc:
        raise BackupError(f"备份包头解析失败: {exc}") from exc
    if not isinstance(header, dict):
        raise BackupError("备份包头格式错误")
    return header


def open_container(blob: bytes, passphrase: str) -> tuple[dict[str, Any], bytes]:
    """校验口令并解密整包，返回 (header, zip 字节)。"""
    if len(blob) > MAX_CONTAINER_BYTES:
        raise BackupError("备份包过大")
    header = read_header(blob)
    if int(header.get("schema") or 0) > BACKUP_SCHEMA:
        raise BackupError(
            f"备份包 schema {header.get('schema')} 高于当前支持版本 {BACKUP_SCHEMA}，请升级应用"
        )
    kdf = header.get("kdf") or {}
    if kdf.get("alg") != "scrypt":
        raise BackupError(f"不支持的 KDF: {kdf.get('alg')}")
    try:
        salt = cb.b64d(str(kdf.get("salt") or ""))
        params = {k: int(kdf[k]) for k in ("n", "r", "p", "dklen") if k in kdf}
        key, _, _ = cb.derive_key(passphrase, salt, params or None)
    except cb.CryptoError as exc:
        raise BackupError(str(exc)) from exc
    except (TypeError, ValueError) as exc:
        raise BackupError(f"KDF 参数错误: {exc}") from exc
    import struct
    header_len = struct.unpack(">I", blob[5:9])[0]
    try:
        archive = cb.aead_open(key, blob[9 + header_len:], aad=BACKUP_MAGIC)
    except cb.CryptoError:
        raise BackupError("口令错误或备份包已损坏") from None
    return header, archive


def parse_archive(archive: bytes) -> dict[str, bytes]:
    """解未加密的 zip 内容；拒绝可疑路径。"""
    try:
        zf = zipfile.ZipFile(io.BytesIO(archive))
    except Exception as exc:
        raise BackupError(f"备份包内容损坏: {exc}") from exc
    files: dict[str, bytes] = {}
    with zf:
        for info in zf.infolist():
            name = info.filename
            if name.startswith("/") or ".." in Path(name).parts:
                raise BackupError(f"备份包含非法路径: {name}")
            files[name] = zf.read(info)
    return files


def load_config_from_archive(files: dict[str, bytes]) -> dict[str, Any]:
    raw = files.get("config.json")
    if raw is None:
        raise BackupError("备份包缺少 config.json")
    try:
        config = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise BackupError(f"config.json 解析失败: {exc}") from exc
    if not isinstance(config, dict) or not isinstance(config.get("accounts"), list):
        raise BackupError("config.json 结构错误")
    return config


def load_secrets_from_archive(files: dict[str, bytes]) -> dict[str, str]:
    raw = files.get("secrets.json")
    if raw is None:
        return {}
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise BackupError(f"secrets.json 解析失败: {exc}") from exc
    if not isinstance(data, dict):
        raise BackupError("secrets.json 结构错误")
    return {str(k): str(v) for k, v in data.items()}


def collect_session_files(files: dict[str, bytes], platform: str,
                          account_id: str) -> dict[str, bytes]:
    """按平台会话清单从备份包内容中取出该账号的会话文件。"""
    prefix = f"accounts/{account_id}/"
    names = set(session_file_names(platform, account_id))
    out: dict[str, bytes] = {}
    for name, data in files.items():
        if not name.startswith(prefix):
            continue
        base = name[len(prefix):]
        if base in names:
            out[base] = data
    return out
