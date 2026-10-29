import asyncio
import json
import time

import pytest
from playwright.async_api import Error as PlaywrightError

from fxfetch.core.browser_click_state import sanitize_click_state, write_click_state


def test_click_state_filters_content_and_nonfinite_geometry():
    result = sanitize_click_state({
        "connected": True, "visibility": "visible", "ready_state": "complete",
        "rect": {"x": 1.23456, "y": float("nan"), "width": float("inf"),
                 "height": True, "top": "secret", "right": 10**1000},
        "viewport": {"width": 400, "height": 800, "url": "private"},
        "center_hits_element": False, "url": "secret", "text": "private", "html": "private",
    })
    assert result["rect"] == {"x": 1.235, "y": None, "width": None, "height": None,
                              "top": None, "right": None, "bottom": None, "left": None}
    assert result["viewport"] == {"width": 400.0, "height": 800.0}
    assert result["connected"] is True and result["center_hits_element"] is False
    body = json.dumps(result, allow_nan=False)
    assert all(value not in body for value in ("secret", "private", "url", "html"))
    assert sanitize_click_state({"visibility": "secret", "ready_state": "private"})["visibility"] == "unknown"


class Element:
    def __init__(self, *, delay=0, error=False):
        self.delay = delay
        self.error = error
        self.calls = 0
        self.finished = False

    async def evaluate(self, expression):
        self.calls += 1
        assert ".click(" not in expression and "fetch(" not in expression
        try:
            await asyncio.sleep(self.delay)
            if self.error:
                raise PlaywrightError("private page error")
            return {"connected": True, "visibility": "hidden", "ready_state": "complete",
                    "center_hits_element": False, "text": "secret"}
        finally:
            self.finished = True


def test_click_state_writes_only_first_whitelisted_receipt(tmp_path):
    element = Element()
    asyncio.run(write_click_state(element, tmp_path, deadline=time.monotonic() + 2))
    path = tmp_path / "click-state-diagnostic.json"
    before = path.read_text()
    assert json.loads(before)["visibility"] == "hidden"
    assert "secret" not in before
    asyncio.run(write_click_state(element, tmp_path, deadline=time.monotonic() + 2))
    assert path.read_text() == before


@pytest.mark.parametrize("budget", [0.04, 5])
def test_click_state_observation_respects_deadline_and_half_second_cap(tmp_path, budget):
    element = Element(delay=2)
    start = time.monotonic()
    asyncio.run(write_click_state(element, tmp_path, deadline=start + budget))
    assert time.monotonic() - start < min(budget, 0.5) + 0.2
    assert element.finished
    assert not (tmp_path / "click-state-diagnostic.json").exists()


def test_click_state_skips_expired_task_and_ignores_observation_failure(tmp_path):
    element = Element(error=True)
    asyncio.run(write_click_state(element, tmp_path, deadline=time.monotonic() - 1))
    assert element.calls == 0
    asyncio.run(write_click_state(element, tmp_path, deadline=time.monotonic() + 1))
    assert element.calls == 1
    assert not (tmp_path / "click-state-diagnostic.json").exists()


def test_click_state_write_failure_does_not_replace_original_error(tmp_path):
    destination = tmp_path / "not-a-directory"
    destination.write_text("retained")
    asyncio.run(write_click_state(Element(), destination, deadline=time.monotonic() + 1))
    assert destination.read_text() == "retained"
