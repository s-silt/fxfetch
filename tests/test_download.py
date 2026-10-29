import plistlib
import zipfile

import pytest

from fxfetch.core.download import classify_package
from fxfetch.core.errors import FxfetchError


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
