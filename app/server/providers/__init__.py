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
from typing import Any

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


@dataclass(frozen=True)
class PlatformSpec:
    """平台规格：能力声明 + 工厂。"""

    platform: str
    display_name: str
    capabilities: ProviderCapabilities
    provider_factory: ProviderFactory
    auth_strategy_factory: AuthStrategyFactory

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


PLATFORMS: dict[str, PlatformSpec] = {
    "huawei": PlatformSpec(
        platform="huawei",
        display_name="华为云空间",
        capabilities=HUAWEI_CAPABILITIES,
        provider_factory=make_huawei_provider,
        auth_strategy_factory=make_huawei_auth_strategy,
    ),
    # T27 小米接入时在此登记：
    # "xiaomi": PlatformSpec(platform="xiaomi", ...),
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
    "get_platform_spec",
    "known_platforms",
]
