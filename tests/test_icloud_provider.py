#!/usr/bin/env python3
"""iCloud Provider 协议、相册与媒体版本映射单测。"""
import json
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app" / "server"))

from hwcloudpd.models import HwCloudError  # noqa: E402
from providers import get_platform_spec  # noqa: E402
from providers.base import AuthStrategy, PhotoProvider  # noqa: E402
from providers.icloud import ICloudAuthStrategy, ICloudProvider, ICloudSessionStore  # noqa: E402
from providers.icloud.icloud_client import ICloudClient  # noqa: E402
from pyicloud_ipd.item_type import AssetItemType  # noqa: E402
from pyicloud_ipd.version_size import AssetVersionSize, LivePhotoVersionSize  # noqa: E402


class _Album:
    def __init__(self, obj_type):
        self.obj_type = obj_type

    def __len__(self):
        raise AssertionError("iCloud 列表不应触发逐相册 count 请求")


class _AssetCollection:
    def __init__(self, assets):
        self.photos = list(assets)
        self.page_size = 100


class _Photos:
    def __init__(self, *, albums=None, assets=None):
        self.albums = albums or {}
        self.SMART_FOLDERS = {"Videos": {}}
        self.all = _AssetCollection(assets or [])


def _version(name, size=100):
    return SimpleNamespace(
        url=f"https://cdn.example/{name}",
        size=size,
        type="public.jpeg",
        checksum=f"checksum-{name}",
    )


def _versions(prefix="still"):
    return {
        AssetVersionSize.ORIGINAL: _version(f"{prefix}-original", 300),
        AssetVersionSize.MEDIUM: _version(f"{prefix}-medium", 200),
        AssetVersionSize.THUMB: _version(f"{prefix}-thumb", 100),
    }


def _asset(asset_id, filename, item_type, *, versions=None, favorite=False):
    versions = _versions() if versions is None else versions
    return SimpleNamespace(
        id=asset_id,
        filename=filename,
        item_type=item_type,
        asset_date=datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        versions=versions,
        size=300,
        _asset_record={"fields": {"isFavorite": {"value": 1 if favorite else 0}}},
    )


class ProviderTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="albumsync-icloud-provider-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.auth_manager = SimpleNamespace(auth_file=str(self.tmp / "auth.json"))

    def make_provider(self, photos=None, *, domain="com"):
        account = {
            "id": "acc-icloud",
            "username": "user@example.com",
            "password": "pw",
            "domain": domain,
        }
        provider = ICloudProvider(self.auth_manager, account)
        client = ICloudClient(
            apple_id=account["username"],
            password=account["password"],
            domain=domain,
            session_path=self.tmp / "session.json",
            cookiejar_path=self.tmp / "cookies.lwp",
            store=ICloudSessionStore(self.tmp / "session.json", self.tmp / "cookies.lwp"),
        )
        client._service = SimpleNamespace(photos=photos or _Photos())
        provider.auth_strategy.ensure_session = Mock(return_value=client)
        return provider, client


class TestProviderContract(ProviderTestBase):
    def test_provider_and_auth_strategy_conform_protocols(self):
        provider = ICloudProvider(self.auth_manager, {"id": "acc", "domain": "com"})
        self.assertIsInstance(provider, PhotoProvider)
        self.assertIsInstance(provider.auth_strategy, AuthStrategy)

    def test_icloud_is_registered_in_provider_registry(self):
        spec = get_platform_spec("icloud")
        self.assertIsInstance(spec.create_provider(self.auth_manager, {"id": "acc"}), ICloudProvider)
        self.assertIsInstance(
            spec.create_auth_strategy(self.auth_manager, {"id": "acc"}),
            ICloudAuthStrategy,
        )
        self.assertEqual(spec.session_files("acc"), (
            "icloud_acc_session.json", "icloud_acc_cookies.lwp",
        ))

    def test_com_and_cn_domains_are_normalized(self):
        for raw, expected in (("com", "com"), ("COM", "com"), ("cn", "cn"), ("CN", "cn")):
            with self.subTest(domain=raw):
                strategy = ICloudAuthStrategy(
                    self.auth_manager,
                    {"id": "acc", "username": "user@example.com", "domain": raw},
                )
                self.assertEqual(strategy.domain, expected)


class TestAlbums(ProviderTestBase):
    def test_smart_and_user_album_ids_and_zero_counts(self):
        albums = {
            "Videos": _Album("CPLAssetInSmartAlbumByAssetDate:Video"),
            "Travel": _Album("CPLContainerRelationNotDeletedByAssetDate:folder-42"),
        }
        provider, _ = self.make_provider(_Photos(albums=albums))

        infos = provider.list_albums(include_stats=True)
        by_name = {info.name: info for info in infos}
        self.assertEqual(by_name["Videos"].album_id, "smart:Videos")
        self.assertTrue(by_name["Videos"].is_virtual)
        self.assertEqual(by_name["Travel"].album_id, "folder-42")
        self.assertFalse(by_name["Travel"].is_virtual)
        for info in infos:
            self.assertEqual((info.img_num, info.video_num), (0, 0))
        self.assertEqual(provider.get_gallery_stats(), {"total": 0, "albums": 2})


class TestMediaMapping(ProviderTestBase):
    def test_photo_video_and_heic_mapping(self):
        assets = [
            _asset("photo", "IMG_0001.JPG", AssetItemType.IMAGE, favorite=True),
            _asset("video", "IMG_0002.MOV", AssetItemType.MOVIE),
            _asset("heic", "IMG_0003.HEIC", AssetItemType.IMAGE),
        ]
        provider, _ = self.make_provider(_Photos(assets=assets))

        pages = list(provider.iter_simple_files(None, album_name="全部照片", page_size=2))
        self.assertEqual([len(page) for page in pages], [2, 1])
        stubs = [stub for page in pages for stub in page]
        self.assertEqual([stub.file_type for stub in stubs], ["1", "4", "9"])
        self.assertEqual(stubs[0].is_fav, 1)
        self.assertEqual(stubs[0].create_time_ms, 1704164645000)
        self.assertTrue(all(stub.album_id == "0" for stub in stubs))

    def test_live_photo_maps_to_heic_still_not_companion_movie(self):
        versions = _versions("live-still")
        versions.update({
            LivePhotoVersionSize.ORIGINAL: _version("live-movie-original", 900),
            LivePhotoVersionSize.MEDIUM: _version("live-movie-medium", 600),
            LivePhotoVersionSize.THUMB: _version("live-movie-thumb", 300),
        })
        asset = _asset("live", "IMG_0004.HEIC", AssetItemType.IMAGE, versions=versions)
        provider, client = self.make_provider(_Photos(assets=[asset]))

        stub = next(iter(provider.iter_simple_files(None)))[0]
        self.assertEqual(stub.file_type, "9")
        item = provider.enrich_metadata([stub])[0]
        actual_urls = {
            size: json.loads(provider.get_download_url(item, size))["url"]
            for size in ("original", "medium", "thumb")
        }
        self.assertEqual(actual_urls, {
            "original": "https://cdn.example/live-still-original",
            "medium": "https://cdn.example/live-still-medium",
            "thumb": "https://cdn.example/live-still-thumb",
        })
        self.assertIs(client._assets["live"], asset)

    def test_three_size_urls_use_exact_version(self):
        asset = _asset("photo", "IMG_0001.JPG", AssetItemType.IMAGE)
        provider, client = self.make_provider()
        client._assets[asset.id] = asset
        stub = provider._asset_to_stub(
            asset,
            album_id="folder-42",
            album_name="Travel",
            album_version="",
            owner_id=None,
            client=client,
        )
        item = provider.enrich_metadata([stub])[0]
        self.assertEqual(item.file_size, 300)

        for size in ("original", "medium", "thumb"):
            with self.subTest(size=size):
                descriptor = json.loads(provider.get_download_url(item, size))
                self.assertEqual(descriptor, {
                    "url": f"https://cdn.example/still-{size}",
                    "asset_id": "photo",
                    "album_id": "folder-42",
                    "size_variant": size,
                })

    def test_missing_size_never_falls_back_to_original(self):
        asset = _asset(
            "photo",
            "IMG_0001.JPG",
            AssetItemType.IMAGE,
            versions={AssetVersionSize.ORIGINAL: _version("only-original")},
        )
        provider, client = self.make_provider()
        client._assets[asset.id] = asset
        stub = provider._asset_to_stub(
            asset,
            album_id=None,
            album_name="",
            album_version="",
            owner_id=None,
            client=client,
        )
        item = provider.enrich_metadata([stub])[0]

        with self.assertRaisesRegex(HwCloudError, "未降级"):
            provider.get_download_url(item, "medium")
        with self.assertRaisesRegex(HwCloudError, "未降级"):
            provider.get_download_url(item, "thumb")


if __name__ == "__main__":
    unittest.main()
