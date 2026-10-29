"""Challenge decisions require actual UI evidence, not translated strings or SDKs."""

import pytest

from fxfetch.core.discovery import discover_html


@pytest.mark.parametrize(
    "html",
    [
        '<title>Ordinary application</title><script>const messages={captcha:"验证码",human:"verify you are human"};</script>',
        '<script src="/captcha-sdk.js"></script><div hidden><input name="captcha">Verify you are human</div>',
        '<script src="/captcha-sdk.js"></script><div style="display:none"><input name="captcha">Verify you are human</div>',
        "<article><h1>How CAPTCHA works</h1><p>Verify you are human is a common security prompt.</p></article>",
        '<noscript><form id="challenge-form">Verify you are human<input name="captcha"></form></noscript>',
        '<template><div class="g-recaptcha">Verify you are human</div><button>Verify</button></template>',
        '<form><input type="password"><input name="captcha"><p>请输入验证码</p><button>Login</button></form>',
        '<form><input type="email"><div class="g-recaptcha"></div><p>Verify you are human</p><button>Sign in</button></form>',
        "<html>captcha</html>",
    ],
)
def test_mentions_hidden_widgets_articles_and_login_are_not_blocked(html):
    result = discover_html(html.encode(), "https://synthetic.invalid/")
    assert "challenge_detected" not in result.gaps


@pytest.mark.parametrize(
    "html",
    [
        '<h1>Verify you are human</h1><input name="captcha"><button>Verify</button>',
        '<h1>人机验证</h1><div class="g-recaptcha"></div><button>继续</button>',
        '<title>Just a moment...</title><form id="challenge-form"></form><script src="/cdn-cgi/challenge-platform/check.js"></script>',
        '<p>Checking your browser</p><div id="challenge-stage"></div><script src="/cdn-cgi/challenge-platform/check.js"></script>',
    ],
)
def test_actual_verification_ui_is_blocked(html):
    result = discover_html(html.encode(), "https://synthetic.invalid/")
    assert "challenge_detected" in result.gaps


def test_download_candidate_survives_sdk_dictionary():
    result = discover_html(
        b'<a href="/app.apk" download>Download</a><script>const captcha="Verify you are human";</script>',
        "https://synthetic.invalid/",
    )
    assert result.candidates[0].kind == "direct_apk"
    assert "browser_required" in result.gaps
    assert "challenge_detected" not in result.gaps
