"""Synthetic static landing sources only; no saved case input or network."""

import base64
import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from fxfetch.core.errors import FxfetchError
from fxfetch.core.landing_adapter import _one, _Unsupported, discover_landing


def synthetic_landing(config=None):
    config = config or {"CDN1": "https://one.example,https://two.example", "loadSource": "@CDN/release/app.apk", "loadMethord": "linkSelf"}
    key, salt = b"synthetic-public-configuration-key", b"12345678"
    derived, previous = b"", b""
    while len(derived) < 48:
        previous = hashlib.md5(previous + key + salt).digest()
        derived += previous
    padder = PKCS7(128).padder()
    padded = padder.update(json.dumps(config).encode()) + padder.finalize()
    encryptor = Cipher(algorithms.AES(derived[:32]), modes.CBC(derived[32:48])).encryptor()
    encoded = base64.b64encode(b"Salted__" + salt + encryptor.update(padded) + encryptor.finalize()).decode()
    html = b'''<html><script>MATOMO_OBJ.matomoaburl = MATOMO_OBJ.urlParma.get("ab");window.ANALYSIS_URL = window.location.hostname;</script><script src="js/index.abcdef.js"></script></html>'''
    entry = '''const key="synthetic-public-configuration-key";
const{search:q}=location,params=new URLSearchParams(q);let view=(params.get("view")||window.ANALYSIS_URL).replace(/^(www.)/,"");window.MATOMO_OBJ.matomoaburl&&(view=window.ANALYSIS_URL);const host=params.get("host")||view,path=`https://${host}/settings/${view}.key.${store.getters["device/isIOS"]?"ios":"and"}.js?v=${parseInt(1e6*Math.random())}`;
window.confView=JSON.parse(crypto.AES.decrypt(window.confView,key).toString(crypto.enc.Utf8));
const{techCore:component="Core"}=window.confView||{},load=()=>req(456)(`./${component}.vue`);
456:function(a,b,c){var table={"./Core.vue":[789,111,222]};}
req.u=function(id){return"js/"+id+"."+{111:"aabbcc",222:"ddeeff"}[id]+".js"};req.p="";
'''
    consumer = '(this.loadSource||"").replace(/@CDN/,this.cdnChoose);this.cdnList=this.CDN1.split(",");href:vm.realSoure'
    resources = {
        "https://landing.example/js/index.abcdef.js": entry.encode(),
        "https://landing.example/settings/landing.example.key.and.js?v=0": f'window.confView="{encoded}";'.encode(),
        "https://landing.example/js/111.aabbcc.js": b"/* synthetic core */",
        "https://landing.example/js/222.ddeeff.js": consumer.encode(),
    }
    return html, resources


def test_synthetic_aes_and_source_order_mirrors():
    html, resources = synthetic_landing()
    calls = []

    def fetch(url, max_bytes):
        calls.append(url)
        return resources[url]

    result = discover_landing(html, "https://landing.example/", "android", fetch)
    assert result.supported and result.mirror_group and not result.gaps
    assert [c.url for c in result.candidates] == ["https://one.example/release/app.apk", "https://two.example/release/app.apk"]
    assert len(calls) == 4
    assert "synthetic-public-configuration-key" not in json.dumps(result.evidence)
    assert all(isinstance(item, dict) for item in result.evidence)


def test_callback_security_errors_propagate():
    html, _ = synthetic_landing()

    def deny(url, max_bytes):
        raise FxfetchError("target_not_public", "Synthetic unsafe resolution")

    with pytest.raises(FxfetchError, match="Synthetic"):
        discover_landing(html, "https://landing.example/", "android", deny)


@pytest.mark.parametrize("config", [
    {"CDN1": "https://one.example", "loadSource": "@CDN/app.apk", "dynamicKey": "active"},
    {"CDN1": "https://one.example", "loadSource": "@CDN/app.apk", "useDynamicPackage": True},
    {"CDN1": "https://one.example", "loadSource": "plain.apk"},
    {"CDN1": "https://one.example", "loadSource": "@CDN/app.ipa"},
    {"CDN1": ",".join(f"https://host{i}.example" for i in range(9)), "loadSource": "@CDN/app.apk"},
])
def test_unknown_config_fails_closed(config):
    html, resources = synthetic_landing(config)
    result = discover_landing(html, "https://landing.example/", "android", lambda url, max_bytes: resources[url])
    assert not result.supported and not result.candidates and result.gaps


def test_cross_origin_settings_not_requested():
    html, resources = synthetic_landing()
    calls = []

    def fetch(url, max_bytes):
        calls.append(url)
        return resources[url]

    result = discover_landing(html, "https://landing.example/?host=other.example", "android", fetch)
    assert not result.supported and result.gaps == ["landing_resource_not_same_origin"]
    assert len(calls) == 1


@pytest.mark.parametrize("mutation", ["consumer", "cipher", "oversize", "context", "dynamic_expression"])
def test_source_mutations_do_not_produce_candidates(mutation):
    html, resources = synthetic_landing()
    entry = "https://landing.example/js/index.abcdef.js"
    if mutation == "consumer":
        resources["https://landing.example/js/222.ddeeff.js"] = b"unknown consumer"
    elif mutation == "cipher":
        resources["https://landing.example/settings/landing.example.key.and.js?v=0"] = b'window.confView="AAAA";'
    elif mutation == "oversize":
        resources[entry] = b"a" * (1024 * 1024 + 1)
    elif mutation == "context":
        resources[entry] = resources[entry].replace(b'"./Core.vue":[789,111,222]', b'"./Other.vue":[789,111,222]')
    else:
        resources[entry] = resources[entry].replace(b'const key="synthetic-public-configuration-key"', b'const key=calculateKey()')
    result = discover_landing(html, "https://landing.example/", "android", lambda url, max_bytes: resources[url])
    assert not result.supported and not result.candidates and result.gaps


def test_no_matching_entry_does_not_fetch():
    def forbidden(url, max_bytes):
        pytest.fail("unreferenced resource requested")

    result = discover_landing(b"<html><p>Static</p></html>", "https://landing.example/", "android", forbidden)
    assert not result.supported and not result.candidates


def test_single_quoted_public_assignments():
    html, resources = synthetic_landing()
    html = html.replace(b'get("ab")', b"get('ab')")
    key = "https://landing.example/settings/landing.example.key.and.js?v=0"
    resources[key] = resources[key].replace(b'"', b"'")
    assert discover_landing(html, "https://landing.example/", "android", lambda url, max_bytes: resources[url]).supported


def test_cumulative_budget_and_callback_order():
    html, resources = synthetic_landing()
    # Valid evidence consumes the same total budget as irrelevant padding.
    entry_key = "https://landing.example/js/index.abcdef.js"
    consumer_key = "https://landing.example/js/222.ddeeff.js"
    resources[entry_key] += b" " * (1024 * 1024 - len(resources[entry_key]))
    resources[consumer_key] += b" " * (1024 * 1024 - len(resources[consumer_key]))
    result = discover_landing(html, "https://landing.example/", "android", lambda url, max_bytes: resources[url])
    assert not result.supported and not result.candidates
    assert result.gaps == ["landing_total_byte_limit"]


def test_unknown_ab_branch_rejected_before_configuration():
    html, resources = synthetic_landing()
    calls = []

    def fetch(url, max_bytes):
        calls.append(url)
        return resources[url]

    result = discover_landing(html, "https://landing.example/?ab=unresolved", "android", fetch)
    assert result.gaps == ["landing_random_hostname_unsupported"] and len(calls) == 1


def test_no_html_entry_ambiguity_or_base_resolution_guessing():
    html, resources = synthetic_landing()
    html = html.replace(b"<html>", b'<html><base href="/other/">')
    result = discover_landing(html, "https://landing.example/", "android", lambda url, max_bytes: resources[url])
    assert not result.supported and result.gaps == ["landing_base_unsupported"]


def test_max_four_mirrors_and_unknown_methods_fail_closed():
    for config in (
        {"CDN1": ",".join(f"https://cdn{i}.example" for i in range(5)), "loadSource": "@CDN/app.apk", "loadMethord": "linkSelf"},
        {"CDN1": "https://cdn.example", "loadSource": "@CDN/app.apk", "loadMethord": "unknownDynamic"},
    ):
        html, resources = synthetic_landing(config)
        result = discover_landing(html, "https://landing.example/", "android", lambda url, max_bytes, resources=resources: resources[url])
        assert not result.supported and not result.candidates
        assert result.gaps[0] in ("landing_mirror_count_limit", "landing_download_mode_unknown")


def test_long_identifiers_and_repeated_matches_fail_quickly():
    start = time.monotonic()
    with pytest.raises(_Unsupported):
        _one(r"\w+\.u=", "x" * (1024 * 1024))
    with pytest.raises(_Unsupported):
        _one(r"x=1;", "x=1;" * (1024 * 256))
    assert time.monotonic() - start < 2.0


def test_callback_receives_hard_remaining_byte_budget():
    html, resources = synthetic_landing()
    budgets = []

    def fetch(url, max_bytes):
        budgets.append(max_bytes)
        assert 0 < max_bytes <= 1024 * 1024
        return resources[url]

    assert discover_landing(html, "https://landing.example/", "android", fetch).supported
    assert len(budgets) == 4
