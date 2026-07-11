"""Core adlinkfly bypass logic.

The typical adlinkfly flow this resolver targets:

1. ``GET`` the short URL. The response is an interstitial page containing a
   ``<form>`` (often ``id="go-link"``) with hidden inputs such as ``_token``
   and ``link``, plus a JavaScript countdown timer.
2. The timer runs (the server also enforces a minimum wait via the session).
3. The page ``POST``\\s the hidden inputs to ``<site>/links/go`` with the header
   ``X-Requested-With: XMLHttpRequest``.
4. The endpoint replies with JSON like ``{"status": "success", "url": "..."}``
   containing the real destination.

Some clones chain two interstitials, use a different POST endpoint (taken from
the form ``action``), or fall back to a meta-refresh / JS redirect. This module
handles those variations and iterates until it lands on a link that is no
longer on the shortener's own domain.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urljoin, urlparse

from . import html_utils
from .exceptions import (
    ResolutionError,
    UnsupportedURLError,
)
from .http_client import Session

logger = logging.getLogger("adlinkfly_bypasser")

# Endpoints adlinkfly and its clones use for the final "go" call, in order of
# likelihood. The form action is always tried first when present.
_GO_ENDPOINTS = ("/links/go", "/go", "/api/links/go")

_MAX_STEPS = 5
_DEFAULT_WAIT_CAP = 15  # never auto-wait longer than this many seconds


@dataclass
class BypassResult:
    """Outcome of a bypass attempt."""

    source: str
    destination: str
    steps: int = 0
    method: str = ""
    trail: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        return self.destination


class AdlinkflyBypasser:
    """Resolve the destination behind adlinkfly-style short URLs.

    Parameters
    ----------
    wait:
        Seconds to wait on each interstitial before submitting.
        ``None`` (default) auto-detects the page countdown (capped at
        ``wait_cap``). ``0`` skips waiting entirely (faster, but some sites
        reject a too-early submission).
    wait_cap:
        Upper bound applied to an auto-detected countdown.
    timeout:
        Per-request timeout in seconds.
    user_agent:
        Override the browser User-Agent string.
    backend:
        Force an HTTP backend: ``"auto"`` (default), ``"cloudscraper"``,
        ``"requests"`` or ``"urllib"``.
    verbose:
        Emit progress via the ``adlinkfly_bypasser`` logger at INFO level.
    """

    def __init__(
        self,
        wait: Optional[float] = None,
        wait_cap: int = _DEFAULT_WAIT_CAP,
        timeout: int = 20,
        user_agent: Optional[str] = None,
        backend: str = "auto",
        verbose: bool = False,
    ):
        self.wait = wait
        self.wait_cap = wait_cap
        self.verbose = verbose
        self._session_kwargs = {"timeout": timeout, "backend": backend}
        if user_agent:
            self._session_kwargs["user_agent"] = user_agent
        self.session = Session(**self._session_kwargs)

    # -- public API --------------------------------------------------------
    def bypass(self, url: str) -> BypassResult:
        """Resolve *url* and return a :class:`BypassResult`.

        Raises :class:`UnsupportedURLError`, :class:`ResolutionError`, etc.
        """
        url = self._validate_url(url)
        self._log("Backend: %s", self.session.backend)
        self._log("Resolving: %s", url)

        source = url
        trail: List[str] = [url]
        current = url
        method_used = ""

        for step in range(1, _MAX_STEPS + 1):
            self._log("Step %d: GET %s", step, current)
            resp = self.session.get(current)
            html = resp.text
            page_url = resp.url or current

            resolved, method = self._resolve_page(page_url, html)
            if resolved is None:
                raise ResolutionError(
                    "Could not find a destination link on the page. The site "
                    "may not be adlinkfly-based, may require JavaScript, or may "
                    "be protected by an anti-bot layer. Try installing "
                    "'cloudscraper' (pip install cloudscraper) or pass "
                    "backend='cloudscraper'."
                )

            resolved = urljoin(page_url, resolved)
            trail.append(resolved)
            method_used = method
            self._log("Step %d resolved via %s -> %s", step, method, resolved)

            # If we've left the shortener's domain, we're done.
            if not self._same_registrable_domain(resolved, page_url):
                return BypassResult(
                    source=source,
                    destination=resolved,
                    steps=step,
                    method=method,
                    trail=trail,
                )

            # Still on the shortener (a chained interstitial): keep going.
            current = resolved

        # Ran out of steps but never left the domain -> return best guess.
        return BypassResult(
            source=source,
            destination=trail[-1],
            steps=_MAX_STEPS,
            method=method_used,
            trail=trail,
        )

    # -- page resolution ---------------------------------------------------
    def _resolve_page(self, page_url: str, html: str):
        """Try every strategy to pull a destination out of one page.

        Returns ``(url, method_name)`` or ``(None, "")``.
        """
        if not html:
            return None, ""

        # Strategy 1: the adlinkfly "/links/go" JSON POST (the primary path).
        dest = self._try_go_post(page_url, html)
        if dest:
            return dest, "links_go_post"

        # Strategy 2: any form that POSTs (some skins post to the same page).
        dest = self._try_generic_form_post(page_url, html)
        if dest:
            return dest, "form_post"

        # Strategy 3: meta refresh redirect.
        dest = html_utils.find_meta_refresh(html)
        if dest:
            return dest, "meta_refresh"

        # Strategy 4: JavaScript location assignment.
        dest = html_utils.find_js_redirect(html)
        if dest and self._looks_external(dest, page_url):
            return dest, "js_redirect"

        # Strategy 5: an obvious action anchor (Get Link / Download / ...).
        dest = html_utils.find_action_anchor(html)
        if dest and self._looks_external(dest, page_url):
            return dest, "anchor"

        return None, ""

    def _try_go_post(self, page_url: str, html: str) -> Optional[str]:
        forms = html_utils.parse_forms(html)
        payload_form = self._pick_form(forms)
        if payload_form is None:
            return None

        data = dict(payload_form.inputs)
        parsed = urlparse(page_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Build the ordered list of endpoints to try.
        endpoints: List[str] = []
        if payload_form.action:
            endpoints.append(urljoin(page_url, payload_form.action))
        for ep in _GO_ENDPOINTS:
            full = base + ep
            if full not in endpoints:
                endpoints.append(full)

        self._sleep_for_countdown(html)

        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Referer": page_url,
            "Origin": base,
            "Accept": "application/json, text/javascript, */*; q=0.01",
        }

        for endpoint in endpoints:
            try:
                self._log("POST %s (payload keys: %s)", endpoint, list(data) or "none")
                resp = self.session.post(endpoint, data=data, headers=headers)
            except Exception as exc:  # noqa: BLE001 - try the next endpoint
                self._log("POST %s failed: %s", endpoint, exc)
                continue

            dest = self._extract_url_from_response(resp.text)
            if dest:
                return dest
        return None

    def _try_generic_form_post(self, page_url: str, html: str) -> Optional[str]:
        for form in html_utils.parse_forms(html):
            if form.method_upper != "POST" or not form.action:
                continue
            endpoint = urljoin(page_url, form.action)
            self._sleep_for_countdown(html)
            headers = {
                "X-Requested-With": "XMLHttpRequest",
                "Referer": page_url,
            }
            try:
                resp = self.session.post(endpoint, data=dict(form.inputs), headers=headers)
            except Exception:  # noqa: BLE001
                continue
            dest = self._extract_url_from_response(resp.text)
            if dest and self._looks_external(dest, page_url):
                return dest
        return None

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _pick_form(forms):
        """Choose the form most likely to be the adlinkfly 'go' form."""
        if not forms:
            return None

        def score(form):
            s = 0
            keys = {k.lower() for k in form.inputs}
            if "_token" in keys:
                s += 5
            if "link" in keys or "url" in keys:
                s += 2
            if form.id and any(t in form.id.lower() for t in ("go", "link", "landing")):
                s += 3
            if form.action and "go" in form.action.lower():
                s += 2
            if form.method_upper == "POST":
                s += 1
            s += min(len(form.inputs), 3)  # forms with hidden fields are likelier
            return s

        best = max(forms, key=score)
        # Require at least one input, otherwise it's not a useful payload form.
        return best if best.inputs else None

    @staticmethod
    def _extract_url_from_response(text: str) -> Optional[str]:
        """Pull a destination URL out of a (usually JSON) response body."""
        if not text:
            return None
        text = text.strip()

        # JSON path.
        try:
            import json

            data = json.loads(text)
            if isinstance(data, dict):
                for key in ("url", "link", "redirect", "location", "destination"):
                    val = data.get(key)
                    if isinstance(val, str) and val.startswith(("http://", "https://")):
                        return val
                # Nested {"data": {"url": ...}} shapes.
                nested = data.get("data")
                if isinstance(nested, dict):
                    for key in ("url", "link"):
                        val = nested.get(key)
                        if isinstance(val, str) and val.startswith("http"):
                            return val
        except (ValueError, TypeError):
            pass

        # Fallback: a bare URL somewhere in the body.
        import re

        m = re.search(r'https?://[^\s"\'<>\\]+', text)
        if m:
            return m.group(0)
        return None

    def _sleep_for_countdown(self, html: str) -> None:
        if self.wait is not None:
            seconds = max(0.0, float(self.wait))
        else:
            detected = html_utils.find_countdown_seconds(html)
            seconds = float(detected) if detected else 0.0
            if seconds > self.wait_cap:
                seconds = float(self.wait_cap)
        if seconds > 0:
            self._log("Waiting %.1fs for interstitial countdown", seconds)
            time.sleep(seconds)

    @staticmethod
    def _validate_url(url: str) -> str:
        if not isinstance(url, str):
            raise UnsupportedURLError("URL must be a string.")
        url = url.strip()
        if not url:
            raise UnsupportedURLError("URL is empty.")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlparse(url)
        if not parsed.netloc:
            raise UnsupportedURLError(f"Not a valid URL: {url!r}")
        return url

    @staticmethod
    def _registrable_domain(netloc: str) -> str:
        host = netloc.split("@")[-1].split(":")[0].lower()
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        # Naive eTLD+1; good enough to tell "same site" from "left the site".
        return ".".join(parts[-2:])

    def _same_registrable_domain(self, a: str, b: str) -> bool:
        da = self._registrable_domain(urlparse(a).netloc)
        db = self._registrable_domain(urlparse(b).netloc)
        return bool(da) and da == db

    def _looks_external(self, candidate: str, page_url: str) -> bool:
        candidate = urljoin(page_url, candidate)
        if not candidate.startswith(("http://", "https://")):
            return False
        return not self._same_registrable_domain(candidate, page_url)

    def _log(self, msg, *args) -> None:
        if self.verbose:
            logger.info(msg, *args)


def bypass(
    url: str,
    wait: Optional[float] = None,
    backend: str = "auto",
    verbose: bool = False,
    **kwargs,
) -> str:
    """Convenience wrapper: resolve *url* and return the destination string.

    For structured output (steps, method, trail) use
    :class:`AdlinkflyBypasser` directly.
    """
    bp = AdlinkflyBypasser(wait=wait, backend=backend, verbose=verbose, **kwargs)
    return bp.bypass(url).destination
