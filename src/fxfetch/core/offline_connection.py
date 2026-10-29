"""Ordinary local connection guidance, without claiming a saved website snapshot."""

from __future__ import annotations

import html
from pathlib import Path
from urllib.parse import urlsplit

from .offline import NEUTRAL_CSS


def write_connection_page(site: Path, url: str) -> None:
    """Write only controlled, inert content; target requests are never performed."""
    host = urlsplit(url).hostname
    if not host:
        raise ValueError("missing connection page hostname")
    escaped_host = html.escape(host, quote=True)
    csp = (
        "default-src 'none'; img-src 'self'; style-src 'self' 'unsafe-inline'; "
        "base-uri 'none'; form-action 'none'; connect-src 'none'; frame-src 'none'"
    )
    document = (
        '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="' + html.escape(csp, quote=True) + '">'
        '<title>' + escaped_host + '</title><link rel="stylesheet" href="assets/style.css">'
        '</head><body><main><h1>' + escaped_host + '</h1><h2>连接网络后继续</h2>'
        '<p>此处是连接说明，未保存网站内容。</p>'
        '<p>请检查网络连接，然后在菜单中选择「重新联网」打开页面。</p>'
        '<p>页面功能和最新内容需要网络连接。</p></main></body></html>'
    )
    (site / "assets").mkdir(parents=True, exist_ok=False)
    (site / "index.html").write_text(document, encoding="utf-8")
    (site / "assets" / "style.css").write_text(
        NEUTRAL_CSS + "main{max-width:40rem;margin:3rem auto;padding:1rem}h1{font-size:1.4rem}",
        encoding="utf-8",
    )
