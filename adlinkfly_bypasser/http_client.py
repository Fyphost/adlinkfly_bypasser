"""A tiny HTTP session abstraction with graceful backend fallback.

Preference order for the transport backend:

1. ``cloudscraper`` - best at getting past Cloudflare "I'm Under Attack" pages,
   which many shortener sites sit behind.
2. ``requests`` - a solid, cookie-aware session.
3. ``urllib`` (standard library) - always available, so the package works with
   zero third-party dependencies installed.

All backends are exposed through the same small interface: :meth:`Session.get`
and :meth:`Session.post`, each returning a :class:`Response`.
"""

from __future__ import annotations

import gzip
import json as _json
import zlib
from http.cookiejar import CookieJar
from typing import Dict, Optional
from urllib.parse import urlencode
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    Request,
    build_opener,
)
from urllib.error import HTTPError, URLError

from .exceptions import NetworkError

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


class Response:
    """A backend-agnostic HTTP response."""

    def __init__(self, url: str, status_code: int, text: str, headers: Dict[str, str]):
        self.url = url
        self.status_code = status_code
        self.text = text
        self.headers = headers

    def json(self):
        """Parse the body as JSON, raising ``ValueError`` on failure."""
        return _json.loads(self.text)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Response [{self.status_code}] {self.url}>"


class Session:
    """Uniform HTTP session over cloudscraper / requests / urllib."""

    def __init__(
        self,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout: int = 20,
        backend: str = "auto",
        cookies: Optional[Dict[str, str]] = None,
        default_headers: Optional[Dict[str, str]] = None,
    ):
        self.user_agent = user_agent
        self.timeout = timeout
        self.cookies = dict(cookies) if cookies else {}
        self.default_headers = dict(default_headers) if default_headers else {}
        self.backend, self._impl = self._select_backend(backend)
        self._apply_cookies()

    def _apply_cookies(self) -> None:
        """Seed session cookies (e.g. a browser-obtained ``cf_clearance``)."""
        if not self.cookies:
            return
        if self.backend in ("cloudscraper", "requests"):
            try:
                self._impl.cookies.update(self.cookies)
            except Exception:
                pass
        else:  # urllib: injected via a Cookie header on each request
            self.default_headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in self.cookies.items()
            )

    def update_credentials(
        self,
        cookies: Optional[Dict[str, str]] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        """Merge in cookies / a new User-Agent mid-session.

        Used after a browser solver clears a Cloudflare challenge, to adopt the
        ``cf_clearance`` cookie and the exact browser User-Agent so subsequent
        plain-HTTP requests are accepted.
        """
        if user_agent:
            self.user_agent = user_agent
            if self.backend in ("cloudscraper", "requests"):
                try:
                    self._impl.headers.update({"User-Agent": user_agent})
                except Exception:
                    pass
        if cookies:
            self.cookies.update(cookies)
            # Rebuild from the full cookie set so the urllib Cookie header and
            # the requests cookie jar both reflect every cookie we hold.
            self._apply_cookies()

    # -- backend selection -------------------------------------------------
    def _select_backend(self, backend: str):
        if backend in ("auto", "cloudscraper"):
            try:
                import cloudscraper  # type: ignore

                return "cloudscraper", cloudscraper.create_scraper(
                    browser={"custom": self.user_agent}
                )
            except Exception:
                if backend == "cloudscraper":
                    raise NetworkError(
                        "cloudscraper backend requested but not importable. "
                        "Install it with: pip install cloudscraper"
                    )

        if backend in ("auto", "requests"):
            try:
                import requests  # type: ignore

                sess = requests.Session()
                sess.headers.update({"User-Agent": self.user_agent})
                return "requests", sess
            except Exception:
                if backend == "requests":
                    raise NetworkError(
                        "requests backend requested but not importable. "
                        "Install it with: pip install requests"
                    )

        if backend in ("auto", "urllib"):
            opener = build_opener(
                HTTPCookieProcessor(CookieJar()), HTTPRedirectHandler()
            )
            return "urllib", opener

        raise NetworkError(f"Unknown HTTP backend: {backend!r}")

    # -- public API --------------------------------------------------------
    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> Response:
        return self._request("GET", url, headers=headers)

    def post(
        self,
        url: str,
        data: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Response:
        return self._request("POST", url, data=data, headers=headers)

    # -- dispatch ----------------------------------------------------------
    def _request(self, method, url, data=None, headers=None):
        merged = {"User-Agent": self.user_agent}
        if self.default_headers:
            merged.update(self.default_headers)
        if headers:
            merged.update(headers)

        if self.backend in ("cloudscraper", "requests"):
            return self._request_requests_like(method, url, data, merged)
        return self._request_urllib(method, url, data, merged)

    def _request_requests_like(self, method, url, data, headers):
        try:
            if method == "GET":
                r = self._impl.get(url, headers=headers, timeout=self.timeout)
            else:
                r = self._impl.post(
                    url, data=data, headers=headers, timeout=self.timeout
                )
        except Exception as exc:  # requests.RequestException & friends
            raise NetworkError(f"{method} {url} failed: {exc}") from exc
        return Response(
            url=str(r.url),
            status_code=r.status_code,
            text=r.text,
            headers={k.lower(): v for k, v in r.headers.items()},
        )

    def _request_urllib(self, method, url, data, headers):
        body = None
        if data is not None:
            body = urlencode(data).encode("utf-8")
        # A sensible default set of browser-like headers.
        headers.setdefault("Accept", "text/html,application/xhtml+xml,*/*")
        headers.setdefault("Accept-Language", "en-US,en;q=0.9")
        req = Request(url, data=body, headers=headers, method=method)
        try:
            resp = self._impl.open(req, timeout=self.timeout)
            raw = resp.read()
            final_url = resp.geturl()
            status = resp.getcode()
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        except HTTPError as exc:
            # HTTP errors still carry a body we may want (e.g. JSON error).
            raw = exc.read() if hasattr(exc, "read") else b""
            final_url = url
            status = exc.code
            resp_headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        except URLError as exc:
            raise NetworkError(f"{method} {url} failed: {exc.reason}") from exc
        except Exception as exc:  # pragma: no cover - defensive
            raise NetworkError(f"{method} {url} failed: {exc}") from exc

        text = self._decode(raw, resp_headers)
        return Response(final_url, status, text, resp_headers)

    @staticmethod
    def _decode(raw: bytes, headers: Dict[str, str]) -> str:
        encoding = (headers.get("content-encoding") or "").lower()
        try:
            if "gzip" in encoding:
                raw = gzip.decompress(raw)
            elif "deflate" in encoding:
                raw = zlib.decompress(raw)
        except Exception:
            pass  # fall through with the raw bytes
        for enc in ("utf-8", "latin-1"):
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", errors="replace")
