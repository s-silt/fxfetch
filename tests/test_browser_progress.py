from fxfetch.core.browser_progress import BrowserProgress


def test_identical_content_is_not_progress_but_changed_content_and_actions_are():
    clock = [0.0]
    progress = BrowserProgress(lambda: clock[0])
    clock[0] = 1
    progress.content("https://example.test/ping", "digest")
    clock[0] = 5
    progress.content("https://example.test/ping", "digest")
    assert progress.last == 1 and progress.stalled(5, 4)
    progress.content("https://example.test/ping", "changed")
    assert progress.last == 5
    clock[0] = 10
    progress.content("https://example.test/page", "dom", document=True)
    clock[0] = 11
    progress.content("https://example.test/page", "dom", document=True)
    assert progress.last == 10
    progress.action()
    assert progress.last == 11


def test_progress_content_memory_is_bounded():
    progress = BrowserProgress(lambda: 0)
    for index in range(350):
        progress.content("https://example.test/", str(index))
        progress.content("https://example.test/", str(index), document=True)
    assert len(progress.responses) == len(progress.documents) == 300
