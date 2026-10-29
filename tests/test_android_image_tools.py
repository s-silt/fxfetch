"""Offline release-tool checks; no official images, downloads or VM operations."""

import hashlib
import importlib.util
import warnings
import zipfile
from pathlib import Path

import pytest


def load_helper(name):
    path = Path(__file__).parents[1] / "scripts/android-worker" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name + "_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("name", ["download_api37", "extract_api37"])
def test_output_is_repository_relative_even_from_another_directory(name, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    helper = load_helper(name)
    downloads = Path(__file__).resolve().parents[1] / ".runtime/android-worker/downloads"
    assert (helper.ROOT if name == "download_api37" else helper.DOWNLOADS) == downloads


@pytest.fixture
def downloader(tmp_path, monkeypatch):
    helper = load_helper("download_api37")
    monkeypatch.setattr(helper, "ROOT", tmp_path)
    monkeypatch.setattr(helper, "DEST", tmp_path / "official.zip")
    monkeypatch.setattr(helper, "TOTAL", 4)
    monkeypatch.setattr(helper, "SHA1", hashlib.sha1(b"good").hexdigest())
    monkeypatch.setattr(
        helper.urllib.request, "build_opener", lambda *args: pytest.fail("No network is permitted")
    )
    return helper


def test_existing_archive_reused_only_with_matching_digest(downloader):
    downloader.DEST.write_bytes(b"good")
    assert downloader.download()["state"] == "verified_existing"
    downloader.DEST.write_bytes(b"evil")
    with pytest.raises(RuntimeError, match="checksum/length"):
        downloader.download()
    assert downloader.DEST.read_bytes() == b"evil"


def test_retained_partial_is_not_retried_implicitly(downloader):
    partial = downloader.DEST.with_suffix(".zip.partial")
    partial.write_bytes(b"go")
    with pytest.raises(RuntimeError, match="explicit reviewed"):
        downloader.download()
    assert partial.read_bytes() == b"go"


def test_oversized_partial_is_rejected_before_network(downloader):
    downloader.DEST.with_suffix(".zip.partial").write_bytes(b"oversized")
    with pytest.raises(RuntimeError, match="exceeds official length"):
        downloader.download(resume=True)


def test_https_downgrade_is_rejected_before_following_redirect():
    helper = load_helper("download_api37")
    with pytest.raises(RuntimeError, match="remain HTTPS"):
        helper.HttpsRedirect().redirect_request(None, None, 302, "", {}, "http://example.invalid/")


@pytest.fixture
def extractor(tmp_path, monkeypatch):
    helper = load_helper("extract_api37")
    for name, filename in [("ARCHIVE", "official.zip"), ("IMAGE", "system.img"), ("PRODUCT", "product.img")]:
        monkeypatch.setattr(helper, name, tmp_path / filename)
    monkeypatch.setattr(helper, "DOWNLOADS", tmp_path)
    return helper


def trust_synthetic_archive(helper, monkeypatch):
    monkeypatch.setattr(helper, "ARCHIVE_BYTES", helper.ARCHIVE.stat().st_size)
    monkeypatch.setattr(helper, "EXPECTED_SHA1", hashlib.sha1(helper.ARCHIVE.read_bytes()).hexdigest())


def test_invalid_archive_checksum_rejected_before_outputs(extractor, monkeypatch):
    extractor.ARCHIVE.write_bytes(b"not-an-official-archive")
    monkeypatch.setattr(extractor, "ARCHIVE_BYTES", extractor.ARCHIVE.stat().st_size)
    with pytest.raises(RuntimeError, match="archive checksum"):
        extractor.extract()
    assert sorted(p.name for p in extractor.DOWNLOADS.iterdir()) == ["official.zip"]


@pytest.mark.parametrize("duplicate", [False, True])
def test_archive_requires_one_exact_member_without_path_extraction(extractor, monkeypatch, duplicate):
    with warnings.catch_warnings(), zipfile.ZipFile(extractor.ARCHIVE, "w") as archive:
        warnings.simplefilter("ignore", UserWarning)
        archive.writestr("../outside.img", b"bad")
        if duplicate:
            archive.writestr("x86_64/system.img", b"good")
            archive.writestr("x86_64/system.img", b"good")
    trust_synthetic_archive(extractor, monkeypatch)
    monkeypatch.setattr(extractor, "IMAGE_BYTES", 4)
    with pytest.raises(RuntimeError, match="entry missing, ambiguous"):
        extractor.extract()
    assert not (extractor.DOWNLOADS.parent / "outside.img").exists()
    assert not extractor.IMAGE.exists()


def test_existing_same_size_image_with_wrong_digest_is_not_reused(extractor, monkeypatch):
    with zipfile.ZipFile(extractor.ARCHIVE, "w") as archive:
        archive.writestr("x86_64/system.img", b"good")
    trust_synthetic_archive(extractor, monkeypatch)
    monkeypatch.setattr(extractor, "IMAGE_BYTES", 4)
    monkeypatch.setattr(extractor, "IMAGE_SHA256", hashlib.sha256(b"good").hexdigest())
    extractor.IMAGE.write_bytes(b"evil")
    with pytest.raises(RuntimeError, match="image checksum/length"):
        extractor.extract()
    assert extractor.IMAGE.read_bytes() == b"evil"
    assert not extractor.PRODUCT.exists()
