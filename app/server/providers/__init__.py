#!/usr/bin/env python3
"""providers 包：多平台 Provider 注册表（T25.5）。

PLATFORMS[platform] = PlatformSpec(能力声明 + provider/strategy 工厂)。
新增平台（如 T27 小米）只需：
1. 实现 providers/<platform>/（PhotoProvider + AuthStrategy）
2. 在 PLATFORMS 登记 PlatformSpec
3. 前端/引擎即自动获得能力降级与工厂接入，无需改 runtime 逻辑。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from hwcloudpd.auth import AuthManager
from providers.base import (
    AuthStrategyFactory,
    AuthStrategy,
    PhotoProvider,
    ProviderCapabilities,
    ProviderFactory,
)
from providers.huawei import (
    HUAWEI_CAPABILITIES,
    HuaweiAuthStrategy,
    HuaweiProvider,
    make_huawei_auth_strategy,
    make_huawei_provider,
)
from providers.icloud import (
    ICLOUD_CAPABILITIES,
    ICloudAuthStrategy,
    ICloudProvider,
    make_icloud_auth_strategy,
    make_icloud_provider,
)
from providers.xiaomi import (
    XIAOMI_CAPABILITIES,
    XiaomiAuthStrategy,
    XiaomiProvider,
    make_xiaomi_auth_strategy,
    make_xiaomi_provider,
)


@dataclass(frozen=True)
class PlatformSpec:
    """平台规格：能力声明 + 工厂 + 平台元数据。"""

    platform: str
    display_name: str
    capabilities: ProviderCapabilities
    provider_factory: ProviderFactory
    auth_strategy_factory: AuthStrategyFactory
    # 需要随凭据备份包（.asbak）迁移的会话文件清单，参数为账号 id。
    # 平台会话文件名差异（如华为 auth.json / 小米 xiaomi_{id}_auth.json）
    # 由各平台在此声明，backup.py 按账号平台查询（平台内容不外泄通用层）。
    session_files: Callable[[str], tuple[str, ...]] | None = None

    def create_provider(self, auth_manager: AuthManager,
                        account: dict[str, Any] | None = None) -> PhotoProvider:
        """工厂默认签名只含 auth_manager；account 附加参数由各工厂自行兼容。"""
        try:
            return self.provider_factory(auth_manager, account)  # type: ignore[misc]
        except TypeError:
            return self.provider_factory(auth_manager)

    def create_auth_strategy(self, auth_manager: AuthManager,
                             account: dict[str, Any] | None = None) -> AuthStrategy:
        return self.auth_strategy_factory(auth_manager, account)


# 各平台会话文件清单（backup.py 打包/导入时按账号平台查询）
def _huawei_session_files(_account_id: str) -> tuple[str, ...]:
    return ("auth.json", "curl.txt.imported", "cas_cookies.lwp", "cas_state.json")


def _xiaomi_session_files(account_id: str) -> tuple[str, ...]:
    return (f"xiaomi_{account_id or 'default'}_auth.json",)


def _icloud_session_files(account_id: str) -> tuple[str, ...]:
    suffix = account_id or "default"
    return (f"icloud_{suffix}_session.json", f"icloud_{suffix}_cookies.lwp")


PLATFORMS: dict[str, PlatformSpec] = {
    "huawei": PlatformSpec(
        platform="huawei",
        display_name="华为云空间",
        capabilities=HUAWEI_CAPABILITIES,
        provider_factory=make_huawei_provider,
        auth_strategy_factory=make_huawei_auth_strategy,
        session_files=_huawei_session_files,
    ),
    "xiaomi": PlatformSpec(
        platform="xiaomi",
        display_name="小米云相册",
        capabilities=XIAOMI_CAPABILITIES,
        provider_factory=make_xiaomi_provider,
        auth_strategy_factory=make_xiaomi_auth_strategy,
        session_files=_xiaomi_session_files,
    ),
    "icloud": PlatformSpec(
        platform="icloud",
        display_name="iCloud 云相册",
        capabilities=ICLOUD_CAPABILITIES,
        provider_factory=make_icloud_provider,
        auth_strategy_factory=make_icloud_auth_strategy,
        session_files=_icloud_session_files,
    ),
}

DEFAULT_PLATFORM = "huawei"


def get_platform_spec(platform: str | None) -> PlatformSpec:
    key = str(platform or DEFAULT_PLATFORM).strip().lower()
    spec = PLATFORMS.get(key)
    if spec is None:
        raise ValueError(f"未知平台: {platform}（支持: {', '.join(sorted(PLATFORMS))}）")
    return spec


def known_platforms() -> list[dict[str, Any]]:
    return [
        {"platform": spec.platform, "display_name": spec.display_name,
         "capabilities": spec.capabilities.to_dict()}
        for spec in PLATFORMS.values()
    ]


__all__ = [
    "PLATFORMS",
    "PlatformSpec",
    "PhotoProvider",
    "AuthStrategy",
    "ProviderCapabilities",
    "HuaweiProvider",
    "HuaweiAuthStrategy",
    "XiaomiProvider",
    "XiaomiAuthStrategy",
    "ICloudProvider",
    "ICloudAuthStrategy",
    "get_platform_spec",
    "known_platforms",
]
