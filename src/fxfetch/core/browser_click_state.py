"""Bounded read-only click diagnostics with a strict non-content whitelist."""

from __future__ import annotations

import asyncio
import json
import math
import time
from pathlib import Path
from typing import Any, Protocol

from playwright.async_api import Error as PlaywrightError

_OBSERVE = """e => {
    const doc=e.ownerDocument, view=doc.defaultView, rect=e.getBoundingClientRect();
    const hit=doc.elementFromPoint(rect.x+rect.width/2,rect.y+rect.height/2);
    return {
        connected:e.isConnected,visibility:doc.visibilityState,ready_state:doc.readyState,
        rect:{x:rect.x,y:rect.y,width:rect.width,height:rect.height,
              top:rect.top,right:rect.right,bottom:rect.bottom,left:rect.left},
        viewport:{width:view?.innerWidth,height:view?.innerHeight},
        center_hits_element:!!hit && (hit===e || e.contains(hit))
    };
}"""


class ClickStateElement(Protocol):
    async def evaluate(self, expression: str) -> Any: ...


def sanitize_click_state(value: object) -> dict[str, object]:
    """Persist only known enums, booleans and finite geometry, never page strings."""
    data = value if isinstance(value, dict) else {}

    def boolean(name: str) -> bool | None:
        item = data.get(name)
        return item if isinstance(item, bool) else None

    def dimensions(name: str, keys: tuple[str, ...]) -> dict[str, float | None]:
        source = data.get(name)
        source = source if isinstance(source, dict) else {}
        result: dict[str, float | None] = {}
        for key in keys:
            item = source.get(key)
            result[key] = round(float(item), 3) if (
                isinstance(item, (int, float)) and not isinstance(item, bool)
                and -1e9 <= item <= 1e9 and math.isfinite(item)
            ) else None
        return result

    visibility = data.get("visibility")
    ready = data.get("ready_state")
    return {
        "connected": boolean("connected"),
        "visibility": visibility if visibility in ("visible", "hidden", "prerender") else "unknown",
        "ready_state": ready if ready in ("loading", "interactive", "complete") else "unknown",
        "rect": dimensions("rect", ("x", "y", "width", "height", "top", "right", "bottom", "left")),
        "viewport": dimensions("viewport", ("width", "height")),
        "center_hits_element": boolean("center_hits_element"),
    }


async def write_click_state(element: ClickStateElement, directory: Path, *, deadline: float) -> None:
    """Observation failure must never replace the original click failure."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return
    try:
        value = await asyncio.wait_for(element.evaluate(_OBSERVE), timeout=min(0.5, remaining))
        if time.monotonic() >= deadline:
            return
        document = sanitize_click_state(value)
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / "click-state-diagnostic.json").open("x", encoding="utf-8") as stream:
            json.dump(document, stream, separators=(",", ":"), allow_nan=False)
    except (PlaywrightError, TimeoutError, OSError):
        return  # This receipt is best effort; acquisition keeps its original error.
