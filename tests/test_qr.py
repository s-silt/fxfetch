import base64
import hashlib
from dataclasses import asdict, replace
from pathlib import Path

import pytest
import qrcode
from PIL import Image

from fxfetch.core.limits import Limits
from fxfetch.core.qr import _classify, decode_image


@pytest.mark.parametrize("format", ["PNG", "JPEG", "WEBP"])
def test_qr_evidence(tmp_path: Path, format: str):
    url = "https://entry.synthetic.test/open?token=a%2Fb&x=1#fragment"
    path = tmp_path / "misleading.dat"
    qrcode.make(url).convert("RGB").save(path, format=format)
    original = path.read_bytes()
    result = decode_image(path)
    assert result.status == "decoded", result
    assert result.format == format
    assert result.sha256 == hashlib.sha256(original).hexdigest()
    assert result.candidates[0].url == url
    assert base64.b64decode(result.candidates[0].raw_bytes_base64) == url.encode()
    assert len(result.candidates[0].position) == 4
    assert result.versions["zxing-cpp"]
    assert asdict(result)["candidates"][0]["text"] == url
    assert path.read_bytes() == original


def test_no_code_and_plain_text(tmp_path: Path):
    path = tmp_path / "image.png"
    Image.new("RGB", (100, 100), "white").save(path)
    assert decode_image(path).status == "no_code"
    qrcode.make("ordinary text").save(path)
    result = decode_image(path)
    assert result.status == "no_supported_url"
    assert result.candidates[0].url is None


def test_invalid_and_limits(tmp_path: Path):
    path = tmp_path / "image.png"
    path.write_bytes(b"not an image")
    assert decode_image(path).status == "invalid_image"
    assert decode_image(path, replace(Limits(), max_image_bytes=2)).reason_code == "image_bytes"
    Image.new("RGB", (100, 100)).save(path)
    assert decode_image(path, replace(Limits(), max_image_pixels=1000)).status == "limit_exceeded"


def test_animation_rejected(tmp_path: Path):
    path = tmp_path / "image.webp"
    Image.new("RGB", (50, 50), "red").save(
        path, save_all=True, append_images=[Image.new("RGB", (50, 50), "blue")], duration=100, loop=0
    )
    assert decode_image(path).reason_code == "animated_image"


def test_multiple_and_truncation(tmp_path: Path):
    first = qrcode.make("https://one.synthetic.test/").convert("RGB")
    second = qrcode.make("https://two.synthetic.test/").convert("RGB")
    image = Image.new("RGB", (first.width + second.width + 50, max(first.height, second.height)), "white")
    image.paste(first, (0, 0))
    image.paste(second, (first.width + 50, 0))
    path = tmp_path / "two.png"
    image.save(path)
    assert len(decode_image(path).candidates) == 2
    result = decode_image(path, replace(Limits(), max_qr_candidates=1))
    assert result.status == "limit_exceeded"
    assert result.truncated
    assert len(result.candidates) == 1


def test_seventeen_codes_report_incomplete(tmp_path: Path):
    tiles = [qrcode.make(f"https://s{index}.synthetic.test/").convert("RGB") for index in range(17)]
    side = max(tile.width for tile in tiles) + 30
    image = Image.new("RGB", (side * 5, side * 4), "white")
    for index, tile in enumerate(tiles):
        image.paste(tile, ((index % 5) * side, (index // 5) * side))
    path = tmp_path / "seventeen.png"
    image.save(path)
    result = decode_image(path)
    assert result.truncated, result
    assert result.status == "limit_exceeded"
    assert len(result.candidates) == 16


@pytest.mark.parametrize("angle,invert", [(90, False), (180, True)])
def test_rotation_and_inversion(tmp_path: Path, angle: int, invert: bool):
    from PIL import ImageOps

    image = qrcode.make("https://rotate.synthetic.test/").convert("RGB").rotate(angle)
    if invert:
        image = ImageOps.invert(image)
    path = tmp_path / "transformed.png"
    image.save(path)
    assert decode_image(path).status == "decoded"


def test_binary_payload_not_promoted(tmp_path: Path):
    path = tmp_path / "binary.png"
    code = qrcode.QRCode()
    code.add_data(b"\xff\xfehttps://entry.synthetic.test/")
    code.make_image().save(path)
    result = decode_image(path)
    assert result.status == "no_supported_url"
    assert result.candidates[0].conversion == "zxing_display_only"
    assert result.candidates[0].url is None


@pytest.mark.parametrize(
    "text",
    [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "example.com",
        "hello",
        "https://user:pass@entry.synthetic.test/",
        "https://apps.apple.com/app/id1",
    ],
)
def test_unsupported_text(text: str):
    assert _classify(text, 8192)[0] is None


def test_strict_itms():
    valid = "itms-services://?action=download-manifest&url=https%3A%2F%2Fentry.synthetic.test%2Fapp.plist"
    assert _classify(valid, 8192)[:2] == ("https://entry.synthetic.test/app.plist", "itms_manifest")
    assert _classify(valid + "&url=https://other.synthetic.test", 8192)[0] is None
    assert _classify(valid + "&unknown=1", 8192)[0] is None
