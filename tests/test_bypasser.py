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
    test_links_go_post_flow()
    test_meta_refresh_flow()
    test_unresolvable_raises()
    print("\nAll tests passed.")
