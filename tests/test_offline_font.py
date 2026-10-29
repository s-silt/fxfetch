import hashlib
from pathlib import Path

import pytest

from fxfetch.core.offline import OfflineBundle
from fxfetch.core.offline_font import apply_offline_font


def setup_site(tmp_path: Path, text: str = '中文'):
    source = tmp_path / 'source.html'
    source.write_text('<p>' + text + '</p>', encoding='utf-8')
    site = tmp_path / 'site'
    assert OfflineBundle().build(source, 'https://example.test/', {}, site).available
    font = tmp_path / 'font.otf'
    font.write_bytes(b'OTTO' + b'local synthetic font')
    license = tmp_path / 'license.txt'
    license.write_text('SIL OPEN FONT LICENSE Version 1.1', encoding='utf-8')
    raw = font.read_bytes()
    settings = dict(font_path=font, license_path=license,
                    sha256=hashlib.sha256(raw).hexdigest(), size=len(raw),
                    git_blob_sha1=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())
    return site, settings

def test_controlled_mapping_and_csp(tmp_path):
    site, settings = setup_site(tmp_path)
    license = tmp_path / 'licenses/offline-sc.txt'
    result = apply_offline_font(site, license, **settings)
    assert result.applied
    assert (site / 'assets/offline-sc.otf').read_bytes() == settings['font_path'].read_bytes()
    assert 'font-src &#x27;self&#x27;' in (site / 'index.html').read_text()
    assert 'font-family:OfflineSC,sans-serif' in (site / 'assets/style.css').read_text()
    assert license.is_file()

def test_pin_mismatch_no_injection(tmp_path):
    site, settings = setup_site(tmp_path)
    settings['sha256'] = '0' * 64
    assert apply_offline_font(site, tmp_path / 'license-out', **settings).reason == 'font_pin_mismatch'
    assert not (site / 'assets/offline-sc.otf').exists()

def test_english_text_uses_font(tmp_path):
    site, settings = setup_site(tmp_path, 'Hello')
    assert apply_offline_font(site, tmp_path / 'license-out', **settings).applied

def test_budget_preserves_original_resources(tmp_path):
    site, settings = setup_site(tmp_path)
    (site / 'assets/retained.bin').write_bytes(b'a' * (28 * 1024 * 1024))
    assert apply_offline_font(site, tmp_path / 'license-out', **settings).reason == 'font_bundle_budget'
    assert (site / 'assets/retained.bin').stat().st_size == 28 * 1024 * 1024
    assert not (site / 'assets/offline-sc.otf').exists()


@pytest.mark.parametrize('failed_stage', ['license', 'css', 'html'])
def test_mid_write_failure_aborts_instead_of_skipping(tmp_path, monkeypatch, failed_stage):
    site, settings = setup_site(tmp_path)
    license_path = tmp_path / 'licenses/offline-sc.txt'
    targets = {'license': license_path, 'css': site / 'assets/style.css', 'html': site / 'index.html'}
    failed_path = targets[failed_stage]
    original_bytes = Path.write_bytes
    original_text = Path.write_text

    def write_bytes(path, data):
        if path == failed_path:
            raise OSError('synthetic destination write failure')
        return original_bytes(path, data)

    def write_text(path, data, **kwargs):
        if path == failed_path:
            raise OSError('synthetic destination write failure')
        return original_text(path, data, **kwargs)

    monkeypatch.setattr(Path, 'write_bytes', write_bytes)
    monkeypatch.setattr(Path, 'write_text', write_text)
    with pytest.raises(OSError, match='synthetic destination write failure'):
        apply_offline_font(site, license_path, **settings)
    # A font has already been written: returning an optional-font skip here would
    # permit publication of incomplete/unlicensed assets. The builder must abort.
    assert (site / 'assets/offline-sc.otf').is_file()


def test_font_overrides_all_retained_descendants(tmp_path):
    site, settings = setup_site(tmp_path)
    assert apply_offline_font(site, tmp_path / "license-out", **settings).applied
    css = (site / "assets/style.css").read_text(encoding="utf-8")
    assert "body,body *{font-family:OfflineSC,sans-serif!important}" in css
