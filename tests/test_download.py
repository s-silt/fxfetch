import plistlib
import zipfile

import pytest

from fxfetch.core.download import classify_package, is_package_prefix
from fxfetch.core.errors import FxfetchError


@pytest.mark.parametrize("signature", [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"])
def test_package_prefix_sniffing_is_not_package_validation(signature):
    assert is_package_prefix(signature + b"unvalidated")
    for length in range(1, 4):
        assert not is_package_prefix(signature[:length])
        assert is_package_prefix(signature[:length], incomplete=True)
    for ordinary in (b"", b"<html", b"PK text", b"plain"):
        assert not is_package_prefix(ordinary, incomplete=True)


def test_packages(tmp_path):
    apk = tmp_path / "a"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", b"manifest")
        z.writestr("classes.dex", b"dex\n035\0")
    assert classify_package(apk) == "apk"
    ipa = tmp_path / "b"
    with zipfile.ZipFile(ipa, "w") as z:
        z.writestr("Payload/Test.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "test.synthetic"}))
    assert classify_package(ipa) == "ipa"


def test_ambiguous_and_trailing(tmp_path):
    path = tmp_path / "mixed"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", b"x")
        z.writestr("classes.dex", b"x")
        z.writestr("Payload/Test.app/Info.plist", b"x")
    with pytest.raises(FxfetchError, match="ambiguous"):
        classify_package(path)
    with path.open("ab") as stream:
        stream.write(b"junk")
    with pytest.raises(FxfetchError):
        classify_package(path)
