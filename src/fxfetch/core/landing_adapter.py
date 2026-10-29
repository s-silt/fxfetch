"""Narrow static CryptoJS/webpack landing extraction, without executing JavaScript.

All resources must have explicit source provenance and are fetched by the caller.
Unknown expressions and dynamic package services remain unsupported.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urljoin, urlsplit

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from .discovery import BoundedHTMLParser, Candidate
from .guard import validate_url

MAX_SOURCE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_CONFIG_BYTES = 256 * 1024
MAX_MIRRORS = 4


@dataclass
class LandingResult:
    candidates: list[Candidate] = field(default_factory=list)
    mirror_group: bool = False
    evidence: list[dict[str, object]] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    supported: bool = False


class _Unsupported(ValueError):
    pass


class _Entry(BoundedHTMLParser):
    def __init__(self) -> None:
        super().__init__("landing_html_limit")
        self.scripts: list[str] = []
        self.has_base = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.start_budget(tag, attrs)
        values = dict(attrs)
        if tag == "base":
            self.has_base = True
        if tag == "script" and values.get("src"):
            self.scripts.append(values["src"] or "")

    def handle_endtag(self, tag: str) -> None:
        self.end_budget(tag)

    def handle_data(self, data: str) -> None:
        self.node_budget()


def _one(pattern: str, source: str) -> re.Match[str]:
    identifier = r"(?<![A-Za-z0-9_$])[A-Za-z_$][A-Za-z0-9_$]{0,63}"
    pattern = pattern.replace(r"\w+", identifier)
    matches = re.finditer(pattern, source)
    first = next(matches, None)
    if first is None or next(matches, None) is not None:
        raise _Unsupported("landing_pattern_ambiguous")
    return first


def _origin(url: str) -> tuple[str, str | None, int]:
    parts = urlsplit(url)
    return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)


def _same_origin(reference: str, source: str) -> str:
    url = validate_url(urljoin(source, reference))
    if _origin(url) != _origin(source):
        raise _Unsupported("landing_resource_not_same_origin")
    return url


def _settings_url(entry: str, html: str, source_url: str, chain: str) -> str:
    """Recognize exactly the public hostname/query and platform-template grammar."""
    if chain not in ("android", "iphone"):
        raise _Unsupported("landing_platform_unsupported")
    search = _one(r'const\{search:(\w+)\}=location,(\w+)=new URLSearchParams\(\1\);', entry)
    params_var = re.escape(search[2])
    fields = _one(
        r'let (\w+)=\(' + params_var + r'\.get\("([a-zA-Z0-9_]+)"\)\|\|window\.ANALYSIS_URL\)'
        r'\.replace\(/\^\(www\.\)/,""\);window\.MATOMO_OBJ\.matomoaburl&&\(\1=window\.ANALYSIS_URL\);'
        r'const (\w+)=' + params_var + r'\.get\("([a-zA-Z0-9_]+)"\)\|\|\1,(\w+)=`([^`]+)`;', entry,
    )
    # An AB override chooses a random hostname in the original page; never guess it.
    ab = _one(r'''MATOMO_OBJ\.matomoaburl\s*=\s*MATOMO_OBJ\.urlParma\.get\((["'])([a-zA-Z0-9_]+)\1\)''', html)
    if not re.search(r'window\.ANALYSIS_URL\s*=\s*window\.location\.hostname', html):
        raise _Unsupported("landing_hostname_source_unknown")
    query = parse_qs(urlsplit(source_url).query, keep_blank_values=True)
    if query.get(ab[2], [""])[0]:
        raise _Unsupported("landing_random_hostname_unsupported")
    for key in (fields[2], fields[4]):
        if len(query.get(key, [])) > 1:
            raise _Unsupported("landing_query_ambiguous")
    view = (query.get(fields[2], [""])[0] or urlsplit(source_url).hostname or "")
    view = re.sub(r"^(www.)", "", view, count=1)
    host = query.get(fields[4], [""])[0] or view
    if not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", view) or not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", host):
        raise _Unsupported("landing_hostname_expression_unsupported")
    template = _one(
        r'https://\$\{(\w+)\}/settings/\$\{(\w+)\}\.key\.\$\{\w+\.getters\["([a-zA-Z0-9_/]+)"\]'
        r'\?"([a-z]+)":"([a-z]+)"\}\.js\?v=\$\{parseInt\(1e6\*Math\.random\(\)\)\}', fields[6],
    )
    if template[1] != fields[3] or template[2] != fields[1] or not template[3].endswith("/isIOS"):
        raise _Unsupported("landing_settings_expression_unsupported")
    suffix = template[4] if chain == "iphone" else template[5]
    return _same_origin(f"https://{host}/settings/{view}.key.{suffix}.js?v=0", source_url)


def _decode_config(entry: str, settings: str) -> dict:
    call = _one(r'window\.confView=JSON\.parse\((\w+)\.AES\.decrypt\(window\.confView,(\w+)\)\.toString\(\1\.enc\.Utf8\)\)', entry)
    binding = _one(r'\b' + re.escape(call[2]) + r'="([^"\\]{1,256})"', entry)
    encoded = _one(r'''^\s*window\.confView\s*=\s*(["'])([A-Za-z0-9+/=]+)\1;?\s*$''', settings)
    blob = base64.b64decode(encoded[2], validate=True)
    if len(blob) < 32 or len(blob) > MAX_CONFIG_BYTES or blob[:8] != b"Salted__" or (len(blob) - 16) % 16:
        raise _Unsupported("landing_cipher_format_unknown")
    derived, previous = b"", b""
    while len(derived) < 48:
        previous = hashlib.md5(previous + binding[1].encode("utf-8") + blob[8:16]).digest()
        derived += previous
    decryptor = Cipher(algorithms.AES(derived[:32]), modes.CBC(derived[32:48])).decryptor()
    padded = decryptor.update(blob[16:]) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    plain = unpadder.update(padded) + unpadder.finalize()
    config = json.loads(plain)
    if not isinstance(config, dict):
        raise _Unsupported("landing_config_not_object")
    stack = [(config, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if depth > 16 or count > 4096:
            raise _Unsupported("landing_config_structure_limit")
        children = item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
        stack.extend((child, depth + 1) for child in children)
    if config.get("dynamicKey") or config.get("useDynamicPackage") not in (None, "", False, "false"):
        raise _Unsupported("landing_dynamic_package_unsupported")
    if config.get("loadMethord") != "linkSelf":
        raise _Unsupported("landing_download_mode_unknown")
    return config


def _chunk_paths(entry: str, config: dict) -> list[str]:
    core = _one(
        r'const\{techCore:(\w+)="([A-Za-z0-9_]+)"\}=window\.confView\|\|\{\},\w+=\(\)=>\w+\((\d+)\)\(`\./\$\{\1\}\.vue`\)', entry,
    )
    selected = config.get("techCore", core[2])
    if not isinstance(selected, str) or not re.fullmatch(r"[A-Za-z0-9_]+", selected):
        raise _Unsupported("landing_core_unknown")
    context = _one(re.escape(core[3]) + r':function\([^)]*\)\{var \w+=\{([^}]+)\}', entry)
    dependencies = _one(r'"\./' + re.escape(selected) + r'\.vue":\[([0-9,]+)\]', context[1])
    ids = dependencies[1].split(",")[1:]
    if not 1 <= len(ids) <= 3 or len(set(ids)) != len(ids):
        raise _Unsupported("landing_dependency_limit")
    runtime = _one(r'\w+\.u=function\((\w+)\)\{return"([a-zA-Z0-9_/-]+/)"\+\1\+"\."\+\{([^}]+)\}\[\1\]\+"\.js"', entry)
    public_path = _one(r'\w+\.p="([^"]*)"', entry)[1]
    if public_path not in ("", "/") or ".." in runtime[2]:
        raise _Unsupported("landing_public_path_unknown")
    paths: list[str] = []
    for chunk in ids:
        digest = _one(r'(?<!\d)' + re.escape(chunk) + r':"([a-f0-9]{4,64})"', runtime[3])[1]
        paths.append(public_path + runtime[2] + chunk + "." + digest + ".js")
    return paths


def discover_landing(
    data: bytes, source_url: str, chain: str, fetch_resource: Callable[[str, int], bytes],
) -> LandingResult:
    """Fetch callback must enforce its supplied maximum before reading the body."""
    result = LandingResult()
    total, scripts = 0, 0

    def fetch(reference: str, role: str, parent: str) -> tuple[str, str]:
        nonlocal total, scripts
        url = _same_origin(reference, source_url)
        if role != "configuration":
            scripts += 1
            if scripts > 4:
                raise _Unsupported("landing_script_count_limit")
        remaining = min(MAX_SOURCE_BYTES, MAX_TOTAL_BYTES - total)
        if remaining <= 0:
            raise _Unsupported("landing_total_byte_limit")
        raw = fetch_resource(url, remaining)
        if not isinstance(raw, bytes) or len(raw) > MAX_SOURCE_BYTES:
            raise _Unsupported("landing_source_byte_limit")
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise _Unsupported("landing_total_byte_limit")
        result.evidence.append({"url": url, "parent": parent, "role": role,
                                "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        return raw.decode("utf-8-sig"), url

    try:
        if len(data) > MAX_SOURCE_BYTES:
            raise _Unsupported("landing_html_byte_limit")
        html = data.decode("utf-8-sig")
        parser = _Entry()
        parser.feed(html)
        parser.close()
        if parser.has_base:
            raise _Unsupported("landing_base_unsupported")
        entries = [value for value in parser.scripts if re.fullmatch(
            r"(?:[^?#]*/)?(?:index|app|main|entry)(?:\.[a-f0-9]{4,64})?\.js", value
        )]
        if len(entries) != 1:
            return result
        entry, entry_url = fetch(entries[0], "entry_script", source_url)
        if "window.confView" not in entry or ".AES.decrypt(" not in entry:
            return result
        settings_url = _settings_url(entry, html, source_url, chain)
        settings, _ = fetch(settings_url, "configuration", entry_url)
        config = _decode_config(entry, settings)
        sources = []
        for path in _chunk_paths(entry, config):
            text, _ = fetch(path, "consumer_script", entry_url)
            sources.append(text)
        consumer = "\n".join(sources)
        if not re.search(r'\(this\.loadSource\|\|""\)\.replace\(/@CDN/,this\.cdnChoose\)', consumer):
            raise _Unsupported("landing_download_consumer_unknown")
        if not re.search(r'this\.cdnList=this\.CDN1\.split\(","\)', consumer):
            raise _Unsupported("landing_cdn_consumer_unknown")
        # The same consumer must bind its computed URL to an actual download href.
        if not re.search(r'href:this\.realSoure|href:\w+\.realSoure|href:\w+\.realSource', consumer):
            raise _Unsupported("landing_download_binding_unknown")
        template, cdn_value = config.get("loadSource"), config.get("CDN1")
        if not isinstance(template, str) or not isinstance(cdn_value, str) or template.count("@CDN") != 1 or not template.startswith("@CDN"):
            raise _Unsupported("landing_download_template_unknown")
        cdns = cdn_value.split(",")
        if not 1 <= len(cdns) <= MAX_MIRRORS or len(set(cdns)) != len(cdns):
            raise _Unsupported("landing_mirror_count_limit")
        for cdn in cdns:
            base = validate_url(cdn)
            if urlsplit(base).query or urlsplit(base).fragment:
                raise _Unsupported("landing_cdn_base_unknown")
            url = validate_url(template.replace("@CDN", cdn, 1))
            if not urlsplit(url).path.lower().endswith(".apk"):
                raise _Unsupported("landing_package_type_unknown")
            result.candidates.append(Candidate(url, "direct_apk", source_url))
        if chain != "android":
            raise _Unsupported("landing_platform_unsupported")
        result.evidence.append({"method": "static_cryptojs_openssl_aes256cbc_md5_pkcs7",
                                "fields": ["loadSource", "CDN1"], "mirror_count": len(cdns),
                                "entry_decrypt_offset": entry.find("window.confView=JSON.parse"),
                                "config_assignment_offset": settings.find("window.confView"),
                                "cache_nonce": "deterministic_zero"})
        result.mirror_group, result.supported = True, True
    except (ValueError, UnicodeError, RecursionError) as error:
        result.candidates = []
        result.gaps = [str(error) if isinstance(error, _Unsupported) else "landing_static_decode_failed"]
    return result
