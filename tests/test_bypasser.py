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

    def __init__(self, html, cookies=None, user_agent="Mozilla/5.0 Solved",
                 final_url=None, reached_final=False, ended=""):
        from adlinkfly_bypasser import SolveResult

        self._result = SolveResult(
            html=html,
            cookies=cookies or {"cf_clearance": "browser-solved-token"},
            user_agent=user_agent,
            final_url=final_url,
            reached_final=reached_final,
            ended=ended,
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


def test_is_final_host():
    from adlinkfly_bypasser import html_utils

    assert html_utils.is_final_host("https://www.terabox.com/s/1abc")
    assert html_utils.is_final_host("https://1024terabox.com/s/x")
    assert html_utils.is_final_host("https://drive.google.com/file/d/x")
    assert not html_utils.is_final_host("https://jobskiki.in/some/article/")
    assert not html_utils.is_final_host("https://vplink.in/p1B2")
    print("PASS test_is_final_host")


def test_find_final_link():
    from adlinkfly_bypasser import html_utils

    html = """
    <a href="/local">nope</a>
    <a href="https://ad.example/next">still an ad</a>
    <a class="btn" href="https://teraboxapp.com/s/1XyZ">Download</a>
    """
    assert html_utils.find_final_link(html) == "https://teraboxapp.com/s/1XyZ"
    assert html_utils.find_final_link("<p>no links here</p>") is None
    print("PASS test_find_final_link")


def test_choose_continue():
    from adlinkfly_bypasser import html_utils

    candidates = [
        {"text": "Home", "tag": "a", "handle": 1},
        {"text": "Share on Facebook", "tag": "a", "handle": 2},
        {"text": "Next", "tag": "button", "handle": 3},
        {"text": "Get Link", "tag": "a", "handle": 4},
    ]
    chosen = html_utils.choose_continue(candidates)
    assert chosen is not None and chosen["handle"] == 4, chosen  # "get link" wins
    # Nav/social only -> nothing to click.
    assert html_utils.choose_continue(
        [{"text": "Login", "tag": "a", "handle": 9},
         {"text": "Privacy Policy", "tag": "a", "handle": 10}]
    ) is None
    # Matches on id/class too.
    assert html_utils.choose_continue(
        [{"id": "verify_button", "tag": "button", "handle": 7}]
    )["handle"] == 7
    print("PASS test_choose_continue")


def test_choose_continue_exclude_and_reveal():
    from adlinkfly_bypasser import html_utils

    cands = [
        {"text": "Continue", "tag": "a", "handle": 1},
        {"text": "Get Link", "tag": "a", "handle": 2},
    ]
    chosen = html_utils.choose_continue(cands)
    assert chosen["handle"] == 2 and html_utils.is_reveal_control(chosen)
    # Excluding the get-link falls back to the (non-reveal) Continue.
    sig = html_utils.candidate_signature(chosen)
    fallback = html_utils.choose_continue(cands, exclude={sig})
    assert fallback["handle"] == 1 and not html_utils.is_reveal_control(fallback)
    print("PASS test_choose_continue_exclude_and_reveal")


def test_find_final_link_rejects_thumbnail_and_decodes_entities():
    from adlinkfly_bypasser import html_utils

    # The exact trap from vplink.in: a dm-data thumbnail preview plus the real
    # share link, both with HTML-encoded ampersands.
    html = (
        '<meta property="og:image" '
        'content="https://dm-data.1024tera.com/thumbnail/abc?fid=1&amp;sign=xyz">'
        '<a id="download" href="https://www.terabox.com/s/1AbC?a=1&amp;b=2">Get Link</a>'
    )
    got = html_utils.find_final_link(html)
    assert got == "https://www.terabox.com/s/1AbC?a=1&b=2", got
    # A thumbnail-only page yields no (share) link.
    assert html_utils.find_final_link(
        '<img src="https://dm-data.1024tera.com/thumbnail/abc.jpg?x=1">'
    ) is None
    print("PASS test_find_final_link_rejects_thumbnail_and_decodes_entities")


class _FakeAdapter:
    """Scripted adapter to exercise the walk algorithm without a real browser.

    *pages* is a list of dicts: {url, html, candidates, next}. Clicking the
    control advances self.idx to page['next'].
    """

    def __init__(self, pages):
        self.pages = pages
        self.idx = 0

    def _p(self):
        return self.pages[self.idx]

    def goto(self, url):
        pass

    def current_url(self):
        return self._p()["url"]

    def page_html(self):
        return self._p().get("html", "")

    def get_cookies(self):
        return {"cf_clearance": "tok"}

    def get_user_agent(self):
        return "Mozilla/5.0 Fake"

    def candidates(self):
        return self._p().get("candidates", [])

    def click(self, handle):
        nxt = self._p().get("next")
        if nxt is not None:
            self.idx = nxt

    def wait_idle(self):
        pass

    def switch_latest_tab(self):
        pass

    def quit(self):
        pass


def test_walk_algorithm_with_fake_adapter():
    """The walk should click through ad pages to a final Terabox share link."""
    from adlinkfly_bypasser.browser import BrowserSolver

    pages = [
        {  # ad page 1: only a plain Continue -> navigates to page 2
            "url": "https://ad1.example/a",
            "html": "<html><body>ad 1</body></html>",
            "candidates": [{"text": "Continue", "tag": "a", "handle": "c1"}],
            "next": 1,
        },
        {  # ad page 2: Continue -> navigates to final page
            "url": "https://ad2.example/b",
            "html": "<html><body>ad 2</body></html>",
            "candidates": [{"text": "Continue", "tag": "a", "handle": "c2"}],
            "next": 2,
        },
        {  # final page: the real share link is present in the DOM
            "url": "https://ad2.example/final",
            "html": '<a href="https://www.terabox.com/s/1RealShare">Get Link</a>',
            "candidates": [{"text": "Get Link", "tag": "a", "handle": "g"}],
        },
    ]
    # Build a solver without triggering backend selection (no browser here).
    solver = BrowserSolver.__new__(BrowserSolver)
    solver.verbose = False
    solver.poll = 0.01
    solver.timeout = 1
    solver.settle = 0
    solver.max_hops = 6
    solver.user_agent = None

    result = solver._walk(_FakeAdapter(pages), "", cleared=True)
    assert result.final_url == "https://www.terabox.com/s/1RealShare", result.final_url
    assert result.cookies.get("cf_clearance") == "tok"
    print("PASS test_walk_algorithm_with_fake_adapter ->", result.final_url)


def test_browser_walk_returns_final_terabox_link():
    """Simulate the solver walking ad pages to a Terabox link."""
    server = _start_server()
    try:
        terabox = "https://www.terabox.com/s/1AbCdEfGhIjK"
        # The solver (browser) walked the ad pages and returned the file link.
        solver = _MockSolver("<html><body>ad page</body></html>", final_url=terabox)
        bp = AdlinkflyBypasser(wait=0, backend="urllib", solver=solver)
        result = bp.bypass(_base(server) + "/cf/p1B2")
        assert result.destination == terabox, result.destination
        assert result.method == "browser_walk", result.method
        print("PASS test_browser_walk_returns_final_terabox_link ->", result.destination)
    finally:
        server.shutdown()


def test_wpsafelink_keywords_recognised():
    from adlinkfly_bypasser import html_utils

    # The WPSafelink/Shortxlinks controls seen on softurl.in must be matched.
    assert html_utils.is_reveal_control(
        {"id": "wpsafelinkhuman", "text": "", "tag": "button"}
    )
    assert html_utils.is_reveal_control({"text": "Generate Link", "tag": "button"})
    assert html_utils.is_reveal_control({"text": "Download Link", "tag": "a"})
    # Footer nav is still ignored.
    assert html_utils.choose_continue(
        [{"text": "About Us", "tag": "a", "handle": 1},
         {"text": "DMCA Policy", "tag": "a", "handle": 2},
         {"text": "Terms and Conditions", "tag": "a", "handle": 3}]
    ) is None
    print("PASS test_wpsafelink_keywords_recognised")


class _WpSafelinkFakeAdapter:
    """Models the WPSafelink flow: human-verify -> generate (needs 2 clicks) ->
    download link revealed in-place (no URL change)."""

    URL = "https://safe.example/article"

    def __init__(self):
        self.state = "human"
        self.gen_clicks = 0

    def goto(self, url):
        pass

    def current_url(self):
        return self.URL

    def page_html(self):
        if self.state == "done":
            return '<a id="dl" href="https://terabox.com/s/1WpSafeWin">Download</a>'
        return "<html>ad %s %s</html>" % (self.state, "x" * 1200)

    def get_cookies(self):
        return {"cf_clearance": "tok"}

    def get_user_agent(self):
        return "UA"

    def candidates(self):
        if self.state == "human":
            return [{"text": "", "id": "wpsafelinkhuman", "tag": "button", "handle": "h"}]
        if self.state == "generate":
            return [{"text": "Generate Link", "id": "generate", "tag": "button", "handle": "g"}]
        return [{"text": "Download", "href": "https://terabox.com/s/1WpSafeWin",
                 "tag": "a", "handle": "d"}]

    def click(self, handle):
        if handle == "h":
            self.state = "generate"
        elif handle == "g":
            self.gen_clicks += 1
            if self.gen_clicks >= 2:  # WPSafelink "Generate" needs two clicks
                self.state = "done"

    def wait_idle(self):
        pass

    def switch_latest_tab(self):
        pass

    def quit(self):
        pass


def test_walk_wpsafelink_double_click_generate():
    from adlinkfly_bypasser.browser import BrowserSolver

    solver = BrowserSolver.__new__(BrowserSolver)
    solver.verbose = False
    solver.poll = 0.01
    solver.timeout = 1
    solver.settle = 0
    solver.max_hops = 10
    solver.user_agent = None

    adapter = _WpSafelinkFakeAdapter()
    result = solver._walk(adapter, "", cleared=True)
    assert result.final_url == "https://terabox.com/s/1WpSafeWin", result.final_url
    assert result.reached_final is True
    assert adapter.gen_clicks == 2, adapter.gen_clicks  # clicked Generate twice
    print("PASS test_walk_wpsafelink_double_click_generate ->", result.final_url)


def test_followed_walk_without_final_raises():
    """Follow mode that ends stuck on an ad page must NOT return the ad page."""
    from adlinkfly_bypasser import ResolutionError

    server = _start_server()
    try:
        adpage = "https://bcsakhi.in/educatestudies/best-universities-2026/"
        solver = _MockSolver(
            "<html><body>an ad blog page, no file link</body></html>",
            final_url=adpage,
            ended="stuck",  # walk got stuck / looped
        )
        bp = AdlinkflyBypasser(wait=0, backend="urllib", solver=solver, follow=True)
        try:
            bp.bypass(_base(server) + "/cf/p1B2")
        except ResolutionError as exc:
            assert "ad-page chain" in str(exc) or "file-host" in str(exc)
            print("PASS test_followed_walk_without_final_raises")
            return
        raise AssertionError("expected ResolutionError for a failed ad-walk")
    finally:
        server.shutdown()


def test_browser_fallback_when_http_resolution_fails():
    """A non-Cloudflare page with no adlinkfly form should fall back to the
    browser solver, which walks to the final link."""
    server = _start_server()
    try:
        terabox = "https://1024terabox.com/s/1FallbackWin"
        # /nothing returns a plain 404-ish page (no form) -> HTTP resolve fails.
        solver = _MockSolver("<html>walked</html>", final_url=terabox,
                             reached_final=True, ended="final_link")
        bp = AdlinkflyBypasser(wait=0, backend="urllib", solver=solver)
        result = bp.bypass(_base(server) + "/nothing")
        assert result.destination == terabox, result.destination
        assert result.method == "browser_walk", result.method
        assert solver.calls == 1
        print("PASS test_browser_fallback_when_http_resolution_fails ->", result.destination)
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
    test_is_final_host()
    test_find_final_link()
    test_choose_continue()
    test_choose_continue_exclude_and_reveal()
    test_find_final_link_rejects_thumbnail_and_decodes_entities()
    test_walk_algorithm_with_fake_adapter()
    test_browser_walk_returns_final_terabox_link()
    test_wpsafelink_keywords_recognised()
    test_walk_wpsafelink_double_click_generate()
    test_followed_walk_without_final_raises()
    test_browser_fallback_when_http_resolution_fails()
    test_pick_form_rejects_wordpress_comment_form()
    test_extract_url_rejects_junk()
    test_browser_redirect_to_destination_not_misparsed()
    test_find_browser_binary_env()
    test_browser_path_threads_to_solver()
    test_browser_backend_selection_without_libs()
    test_browser_solver_clears_cloudflare_end_to_end()
    test_browser_solver_that_fails_raises()
    print("\nAll tests passed.")
