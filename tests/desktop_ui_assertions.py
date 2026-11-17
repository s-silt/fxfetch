"""Shared geometry checks for the installed-Chrome desktop acceptance scripts."""

from playwright.sync_api import Page

DESKTOP_SIZES = {
    'desktop-1280': {'width': 1280, 'height': 800},
    'desktop-1440': {'width': 1440, 'height': 900},
    'desktop-1920': {'width': 1920, 'height': 1080},
}


def assert_desktop_workspace(page: Page, view: str = 'collect') -> None:
    """Require two visible, aligned columns and a single active workspace."""
    assert page.evaluate('() => document.documentElement.scrollWidth <= innerWidth')
    active, inactive = ('#collect-workspace', '#icon-search-panel') if view == 'collect' else (
        '#icon-search-panel', '#collect-workspace')
    assert page.locator(active).is_visible() and page.locator(inactive).is_hidden()
    assert page.locator('#view-' + view).get_attribute('aria-selected') == 'true'
    other = 'search' if view == 'collect' else 'collect'
    assert page.locator('#view-' + other).get_attribute('aria-selected') == 'false'
    selectors = ('#collect-panel', '#task-panel') if view == 'collect' else (
        '#icon-search-panel .search-input', '#search-result-panel')
    # Read both boxes in one frame: keyboard focus can still be finishing a
    # smooth document scroll, which must not look like misaligned grid rows.
    left, right = page.evaluate('''selectors => selectors.map(selector => {
        const box = document.querySelector(selector).getBoundingClientRect();
        return {x:box.x, y:box.y, width:box.width, height:box.height};
    })''', selectors)
    assert left and right, selectors
    assert abs(left['y'] - right['y']) <= 2, (left, right)
    assert left['x'] + left['width'] + 8 <= right['x'], (left, right)
    assert page.viewport_size is not None
    width = page.viewport_size['width']
    for box in (left, right):
        assert 0 <= box['x'] and box['x'] + box['width'] <= width + 0.5, box
    assert right['width'] >= left['width'], (left, right)


def assert_same_page(page: Page, url: str) -> None:
    assert page.url == url
    assert len(page.context.pages) == 1
