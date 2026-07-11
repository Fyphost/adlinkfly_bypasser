"""End-to-end tests using a local mock adlinkfly server.

These run entirely offline: a small ``http.server`` mimics the adlinkfly
interstitial + ``/links/go`` JSON flow so the resolver can be exercised without
touching the internet.

Run with:  python -m pytest tests/ -q      (if pytest is installed)
    or:    python tests/test_bypasser.py    (plain, no dependencies)
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from adlinkfly_bypasser import AdlinkflyBypasser, ResolutionError

DESTINATION = "https://real-destination.example/final?id=42"

INTERSTITIAL_HTML = """
<!doctype html><html><head>
<script>var time = 5;</script>
</head><body>
<form id="go-link" method="post" action="/links/go">
  <input type="hidden" name="_token" value="tok_abc123">
  <input type="hidden" name="link" value="enc_payload">
  <button type="submit">Get Link</button>
</form>
</body></html>
"""

META_REFRESH_HTML = """
<!doctype html><html><head>
<meta http-equiv="refresh" content="0; url=%s">
</head><body>redirecting...</body></html>
""" % DESTINATION

# A representative Cloudflare "managed challenge" / Turnstile interstitial.
CLOUDFLARE_HTML = """
<!doctype html><html><head><title>Just a moment...</title>
<script src="/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1"></script>
</head><body>
<div class="cf-turnstile"></div>
<script>window._cf_chl_opt={cvId:'3'};</script>
<p>Verify you are human by completing the action below.</p>
<link rel="stylesheet" href="/cf-fonts/inter.css">
</body></html>
"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def _send(self, code, body, content_type="text/html"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/go-link"):
            self._send(200, INTERSTITIAL_HTML)
        elif self.path.startswith("/meta"):
            self._send(200, META_REFRESH_HTML)
        elif self.path.startswith("/cf"):
            # Always a Cloudflare challenge.
            self._send(403, CLOUDFLARE_HTML)
        elif self.path.startswith("/guarded"):
            # Serve the real page only if a cf_clearance cookie is present,
            # otherwise a challenge - mirroring the escape-hatch workflow.
            cookie = self.headers.get("Cookie", "")
            if "cf_clearance=" in cookie:
                self._send(200, INTERSTITIAL_HTML)
            else:
                self._send(403, CLOUDFLARE_HTML)
        else:
            self._send(404, "not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        if self.path == "/links/go" and "_token=tok_abc123" in body:
            self._send(
                200,
                '{"status":"success","url":"%s"}' % DESTINATION,
                content_type="application/json",
            )
        else:
            self._send(400, '{"status":"error"}', content_type="application/json")


class _MockSolver:
    """A stand-in for BrowserSolver: pretends a browser cleared Cloudflare.

    Returns a rendered adlinkfly interstitial plus a cf_clearance cookie, which
    is exactly what a real browser solve would hand back.
    """

    def __init__(self, html, cookies=None, user_agent="Mozilla/5.0 Solved", final_url=None):
        from adlinkfly_bypasser import SolveResult

        self._result = SolveResult(
            html=html,
            cookies=cookies or {"cf_clearance": "browser-solved-token"},
            user_agent=user_agent,
            final_url=final_url,
        )
        self._final_override = final_url
        self.calls = 0

    def solve(self, url):
        self.calls += 1
        # Use an explicit landing URL if given, else reflect the requested URL.
        self._result.final_url = self._final_override or url
        return self._result


# A WordPress destination/blog page (what vplink.in actually redirects to). It
# has a comment form (author/email/url/comment_post_ID) and an OpenGraph
# namespace URL - both classic false-positive traps.
WORDPRESS_LANDING_HTML = """
<!doctype html><html xmlns:og="https://ogp.me/ns#"><head>
<meta property="og:title" content="Some Article">
<link rel="https://api.w.org/" href="https://blogsite.example/wp-json/">
</head><body>
<h1>Online AI and Machine Learning Degree</h1>
<form action="https://blogsite.example/wp-comments-post.php" method="post" id="commentform">
  <input name="author" type="text">
  <input name="email" type="text">
  <input name="url" type="text">
  <textarea name="comment"></textarea>
  <input type="hidden" name="comment_post_ID" value="123">
  <input type="hidden" name="comment_parent" value="0">
  <input name="submit" type="submit" value="Post Comment">
</form>
</body></html>
"""


def _start_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _base(server):
    host, port = server.server_address
    return f"http://{host}:{port}"


def test_links_go_post_flow():
    server = _start_server()
    try:
        bp = AdlinkflyBypasser(wait=0, backend="urllib")
        result = bp.bypass(_base(server) + "/go-link/abc")
        assert result.destination == DESTINATION, result.destination
        assert result.method == "links_go_post", result.method
        print("PASS test_links_go_post_flow ->", result.destination)
    finally:
        server.shutdown()


def test_meta_refresh_flow():
    server = _start_server()
    try:
        bp = AdlinkflyBypasser(wait=0, backend="urllib")
        result = bp.bypass(_base(server) + "/meta/xyz")
        assert result.destination == DESTINATION, result.destination
        assert result.method == "meta_refresh", result.method
        print("PASS test_meta_refresh_flow ->", result.destination)
    finally:
        server.shutdown()


def test_unresolvable_raises():
    server = _start_server()
    try:
        bp = AdlinkflyBypasser(wait=0, backend="urllib")
        try:
            bp.bypass(_base(server) + "/nothing")
        except ResolutionError:
            print("PASS test_unresolvable_raises")
            return
        raise AssertionError("expected ResolutionError")
    finally:
        server.shutdown()


def test_cloudflare_challenge_raises():
    from adlinkfly_bypasser import CloudflareChallengeError

    server = _start_server()
    try:
        bp = AdlinkflyBypasser(wait=0, backend="urllib")
        try:
            bp.bypass(_base(server) + "/cf/abc")
        except CloudflareChallengeError as exc:
            assert exc.reason in ("turnstile", "managed challenge"), exc.reason
            assert "Cloudflare" in str(exc)
            print("PASS test_cloudflare_challenge_raises ->", exc.reason)
            return
        raise AssertionError("expected CloudflareChallengeError")
    finally:
        server.shutdown()


def test_cf_clearance_cookie_escape_hatch():
    server = _start_server()
    try:
        # Without the cookie -> challenge.
        bp_no = AdlinkflyBypasser(wait=0, backend="urllib")
        from adlinkfly_bypasser import CloudflareChallengeError

        try:
            bp_no.bypass(_base(server) + "/guarded/abc")
            raise AssertionError("expected challenge without cookie")
        except CloudflareChallengeError:
            pass

        # With a cf_clearance cookie -> real page resolves.
        bp_yes = AdlinkflyBypasser(
            wait=0, backend="urllib", cookies={"cf_clearance": "solved-token"}
        )
        result = bp_yes.bypass(_base(server) + "/guarded/abc")
        assert result.destination == DESTINATION, result.destination
        print("PASS test_cf_clearance_cookie_escape_hatch ->", result.destination)
    finally:
        server.shutdown()


def test_browser_solver_clears_cloudflare_end_to_end():
    """A (mock) browser solver clears CF, then the normal resolver finishes."""
    server = _start_server()
    try:
        solver = _MockSolver(INTERSTITIAL_HTML)
        bp = AdlinkflyBypasser(wait=0, backend="urllib", solver=solver)
        result = bp.bypass(_base(server) + "/guarded/abc")
        assert result.destination == DESTINATION, result.destination
        assert solver.calls == 1, solver.calls
        print("PASS test_browser_solver_clears_cloudflare_end_to_end ->", result.destination)
    finally:
        server.shutdown()


def test_browser_solver_that_fails_raises():
    """If the solver returns a page that's still a challenge, raise clearly."""
    from adlinkfly_bypasser import CloudflareChallengeError

    server = _start_server()
    try:
        solver = _MockSolver(CLOUDFLARE_HTML)  # never actually clears
        bp = AdlinkflyBypasser(wait=0, backend="urllib", solver=solver)
        try:
            bp.bypass(_base(server) + "/cf/abc")
        except CloudflareChallengeError as exc:
            assert "did not clear" in str(exc) or "challenge" in str(exc).lower()
            print("PASS test_browser_solver_that_fails_raises")
            return
        raise AssertionError("expected CloudflareChallengeError")
    finally:
        server.shutdown()


def test_browser_backend_selection_without_libs():
    """With no browser driver installed, selecting one errors clearly."""
    from adlinkfly_bypasser import BrowserSolver, BrowserSolverError, available_backends

    if available_backends():
        print("SKIP test_browser_backend_selection_without_libs (a driver is installed)")
        return
    try:
        BrowserSolver(backend="auto")
    except BrowserSolverError as exc:
        assert "No browser backend" in str(exc)
        print("PASS test_browser_backend_selection_without_libs")
        return
    raise AssertionError("expected BrowserSolverError")


def test_solver_disabled_by_default():
    server = _start_server()
    try:
        bp = AdlinkflyBypasser(wait=0, backend="urllib")  # solver defaults to "none"
        assert bp._can_solve() is False
        bp2 = AdlinkflyBypasser(wait=0, backend="urllib", solver="browser")
        assert bp2._can_solve() is True
        print("PASS test_solver_disabled_by_default")
    finally:
        server.shutdown()


def test_browser_redirect_to_destination_not_misparsed():
    """Regression: browser clears CF and lands on the destination blog page.

    The resolver must return that landing URL, NOT scrape the WordPress
    comment form / OpenGraph namespace (which previously yielded ogp.me/ns).
    """
    server = _start_server()
    try:
        landing = "https://blogsite.example/studyeducates/ai-degree-2026/"
        solver = _MockSolver(WORDPRESS_LANDING_HTML, final_url=landing)
        bp = AdlinkflyBypasser(wait=0, backend="urllib", solver=solver)
        result = bp.bypass(_base(server) + "/cf/p1B2")
        assert result.destination == landing, result.destination
        assert result.method == "browser_redirect", result.method
        print("PASS test_browser_redirect_to_destination_not_misparsed ->", result.destination)
    finally:
        server.shutdown()


def test_pick_form_rejects_wordpress_comment_form():
    from adlinkfly_bypasser import html_utils
    from adlinkfly_bypasser.bypasser import AdlinkflyBypasser as _BP

    forms = html_utils.parse_forms(WORDPRESS_LANDING_HTML)
    assert forms, "expected to parse the comment form"
    assert _BP._pick_form(forms) is None  # not an adlinkfly go-link form
    # But a genuine go-link form IS picked.
    golink = html_utils.parse_forms(INTERSTITIAL_HTML)
    assert _BP._pick_form(golink) is not None
    print("PASS test_pick_form_rejects_wordpress_comment_form")


def test_extract_url_rejects_junk():
    from adlinkfly_bypasser.bypasser import AdlinkflyBypasser as _BP

    # json_only: an HTML body must not yield a scraped URL.
    assert _BP._extract_url_from_response(WORDPRESS_LANDING_HTML, json_only=True) is None
    # Non-json_only still rejects namespace/schema hosts like ogp.me.
    assert _BP._extract_url_from_response('see https://ogp.me/ns# here') is None
    # A real destination in JSON is accepted.
    assert (
        _BP._extract_url_from_response('{"url":"https://real.example/x"}')
        == "https://real.example/x"
    )
    # A real bare URL in text is accepted.
    assert (
        _BP._extract_url_from_response("go to https://real.example/y now")
        == "https://real.example/y"
    )
    print("PASS test_extract_url_rejects_junk")


def test_find_browser_binary_env(tmp_path=None):
    import os
    import stat
    import tempfile

    from adlinkfly_bypasser import find_browser_binary

    # Create a fake executable and point CHROME_BIN at it.
    d = tempfile.mkdtemp()
    fake = os.path.join(d, "chrome")
    with open(fake, "w") as fh:
        fh.write("#!/bin/sh\n")
    os.chmod(fake, os.stat(fake).st_mode | stat.S_IEXEC)

    old = os.environ.get("CHROME_BIN")
    try:
        os.environ["CHROME_BIN"] = fake
        assert find_browser_binary() == fake
    finally:
        if old is None:
            os.environ.pop("CHROME_BIN", None)
        else:
            os.environ["CHROME_BIN"] = old
    print("PASS test_find_browser_binary_env")


def test_browser_path_threads_to_solver():
    # AdlinkflyBypasser should forward browser_path / xvfb to the solver it
    # builds. We can't build a real BrowserSolver without a driver installed,
    # so just verify the attributes are stored for the factory to use.
    bp = AdlinkflyBypasser(
        solver="browser", browser_path="/tmp/chrome", xvfb=True, headless=True
    )
    assert bp.browser_path == "/tmp/chrome"
    assert bp.xvfb is True
    print("PASS test_browser_path_threads_to_solver")


def test_detect_cloudflare_unit():
    from adlinkfly_bypasser import html_utils

    assert html_utils.detect_cloudflare(CLOUDFLARE_HTML) in (
        "turnstile",
        "managed challenge",
    )
    # A normal adlinkfly page must NOT be flagged as a challenge.
    assert html_utils.detect_cloudflare(INTERSTITIAL_HTML) is None
    # A page that merely loads cf-fonts is not a challenge.
    assert html_utils.detect_cloudflare('<link href="/cf-fonts/x.css">') is None
    # A bare 403 with no body reads as a block.
    assert html_utils.detect_cloudflare("", status_code=403) == "blocked"
    # An explicit block page.
    assert (
        html_utils.detect_cloudflare("<h1>Sorry, you have been blocked</h1>")
        == "blocked"
    )
    print("PASS test_detect_cloudflare_unit")


def test_countdown_autodetect():
    from adlinkfly_bypasser import html_utils

    assert html_utils.find_countdown_seconds(INTERSTITIAL_HTML) == 5
    print("PASS test_countdown_autodetect")


def test_form_parsing():
    from adlinkfly_bypasser import html_utils

    forms = html_utils.parse_forms(INTERSTITIAL_HTML)
    assert len(forms) == 1
    assert forms[0].inputs.get("_token") == "tok_abc123"
    assert forms[0].action == "/links/go"
    print("PASS test_form_parsing")


if __name__ == "__main__":
    test_form_parsing()
    test_countdown_autodetect()
    test_detect_cloudflare_unit()
    test_links_go_post_flow()
    test_meta_refresh_flow()
    test_unresolvable_raises()
    test_cloudflare_challenge_raises()
    test_cf_clearance_cookie_escape_hatch()
    test_solver_disabled_by_default()
    test_pick_form_rejects_wordpress_comment_form()
    test_extract_url_rejects_junk()
    test_browser_redirect_to_destination_not_misparsed()
    test_find_browser_binary_env()
    test_browser_path_threads_to_solver()
    test_browser_backend_selection_without_libs()
    test_browser_solver_clears_cloudflare_end_to_end()
    test_browser_solver_that_fails_raises()
    print("\nAll tests passed.")
