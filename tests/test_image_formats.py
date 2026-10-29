"""Synthetic local images only; filenames and MIME do not establish type."""

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest
import qrcode
from PIL import Image
from pillow_heif import register_heif_opener

from fxfetch.core.limits import Limits
from fxfetch.core.qr import decode_image

URL = "https://format.synthetic.test/app.apk?token=a%2Fb"
register_heif_opener(thumbnails=False)


@pytest.mark.parametrize("format", ["PNG", "JPEG", "WEBP", "HEIF", "BMP", "GIF", "TIFF", "AVIF"])
def test_actual_formats_and_safe_preview(tmp_path: Path, format: str):
    image = qrcode.make(URL).convert("RGB")
    path = tmp_path / "not-trusted.zip"
    image.save(path, format=format)
    original = path.read_bytes()
    preview = tmp_path / "thumbnail.jpg"
    result = decode_image(path, thumbnail_path=preview)
    assert result.status == "decoded", result
    assert result.format == format
    assert result.candidates[0].url == URL
    assert result.sha256 == hashlib.sha256(original).hexdigest()
    assert path.read_bytes() == original
    assert result.thumbnail_available
    with Image.open(preview) as thumbnail:
        assert thumbnail.format == "JPEG"
        assert max(thumbnail.size) <= 640
        assert not thumbnail.getexif()
        assert "icc_profile" not in thumbnail.info


@pytest.mark.parametrize("format", ["GIF", "TIFF", "WEBP", "AVIF", "HEIF"])
def test_animated_or_multi_page_not_silently_first_frame(tmp_path, format):
    path = tmp_path / "multiple"
    first = Image.new("RGB", (80, 80), "white")
    second = Image.new("RGB", (80, 80), "black")
    first.save(path, format=format, save_all=True, append_images=[second], duration=100, loop=0)
    result = decode_image(path, thumbnail_path=tmp_path / "preview.jpg")
    assert result.status == "invalid_image", result
    assert result.reason_code in ("animated_image", "multi_page_image")
    assert not result.thumbnail_available
    assert not (tmp_path / "preview.jpg").exists()


@pytest.mark.parametrize("format", ["JPEG", "HEIF"])
def test_exif_rotation_copy_and_coordinates(tmp_path, format):
    image = qrcode.make(URL).convert("RGB")
    canvas = Image.new("RGB", (image.width + 100, image.height + 40), "white")
    canvas.paste(image, (0, 0))
    exif = Image.Exif()
    exif[274] = 6
    exif[270] = "private metadata must not enter preview"
    path = tmp_path / "rotated.jpg"
    canvas.save(path, format=format, quality=95, exif=exif)
    original = path.read_bytes()
    result = decode_image(path, thumbnail_path=tmp_path / "preview.jpg")
    assert result.status == "decoded", result
    assert result.transforms == (
        ["heif_decoder_orientation_6"] if format == "HEIF" else ["exif_orientation_6"]
    )
    assert result.coordinate_space == (
        "decoder_oriented_image_pixels" if format == "HEIF" else "exif_transposed_image_pixels"
    )
    assert path.read_bytes() == original
    with Image.open(tmp_path / "preview.jpg") as preview:
        if format == "HEIF":
            # HEIF stores orientation in container transforms; libheif has
            # already applied those when exposing the decoded dimensions.
            with Image.open(path) as source:
                assert preview.size == source.size
        else:
            assert preview.width < preview.height
        assert not preview.getexif()


@pytest.mark.parametrize(
    "data", [b"not image", b"%PDF-1.7", b"PK\x03\x04", b'<svg xmlns="http://www.w3.org/2000/svg"></svg>']
)
def test_non_images_no_preview(tmp_path, data):
    path = tmp_path / "image.jpg"
    path.write_bytes(data)
    result = decode_image(path, thumbnail_path=tmp_path / "preview.jpg")
    assert result.status == "invalid_image"
    assert not result.thumbnail_available
    assert not (tmp_path / "preview.jpg").exists()


def test_limits_apply_to_added_format(tmp_path):
    path = tmp_path / "large.bmp"
    Image.new("RGB", (100, 100)).save(path, format="BMP")
    result = decode_image(
        path, replace(Limits(), max_image_pixels=1000), thumbnail_path=tmp_path / "preview.jpg"
    )
    assert result.status == "limit_exceeded"
    assert not (tmp_path / "preview.jpg").exists()
    assert decode_image(path, replace(Limits(), max_image_bytes=2)).reason_code == "image_bytes"
