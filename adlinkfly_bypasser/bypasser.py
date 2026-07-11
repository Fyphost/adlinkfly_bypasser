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
    CloudflareChallengeError,
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
    cookies:
        Optional cookies to seed the session with. The primary use is to pass
        a ``cf_clearance`` cookie obtained from a real browser after solving a
        Cloudflare challenge - together with the *same* ``user_agent`` the
        browser used - to get past Cloudflare-protected shorteners.
    headers:
        Optional default headers applied to every request.
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
        cookies: Optional[dict] = None,
        headers: Optional[dict] = None,
        solver: object = "none",
        headless: bool = True,
        verbose: bool = False,
    ):
        self.wait = wait
        self.wait_cap = wait_cap
        self.verbose = verbose
        self.user_agent = user_agent
        self.headless = headless
        # solver: "none" | "browser" | "auto" | a browser backend name | an
        # object exposing .solve(url) -> SolveResult (for custom/test solvers).
        self.solver_spec = solver
        self._solver = None
        self._session_kwargs = {"timeout": timeout, "backend": backend}
        if user_agent:
            self._session_kwargs["user_agent"] = user_agent
        if cookies:
            self._session_kwargs["cookies"] = cookies
        if headers:
            self._session_kwargs["default_headers"] = headers
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
        pending_html: Optional[str] = None
        pending_url: Optional[str] = None

        for step in range(1, _MAX_STEPS + 1):
            if pending_html is not None:
                # Page already rendered by the browser solver; don't re-fetch.
                html, page_url = pending_html, pending_url or current
                status: Optional[int] = 200
                pending_html = pending_url = None
            else:
                self._log("Step %d: GET %s", step, current)
                resp = self.session.get(current)
                html = resp.text
                page_url = resp.url or current
                status = resp.status_code

            # Anti-bot handling: try the browser solver if enabled, otherwise
            # raise a precise error instead of a misleading "no destination".
            if html_utils.detect_cloudflare(html, status):
                if self._can_solve():
                    html, page_url = self._solve_cloudflare(current, page_url)
                self._raise_if_cloudflare(html, status)

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

    # -- browser solver ----------------------------------------------------
    def _can_solve(self) -> bool:
        return self.solver_spec not in (None, "none", "off", False)

    def _get_solver(self):
        if self._solver is not None:
            return self._solver
        spec = self.solver_spec
        if hasattr(spec, "solve"):  # a pre-built / custom / mock solver
            self._solver = spec
            return self._solver

        from .browser import BrowserSolver  # lazy: browser deps are optional

        backend = "auto" if spec in ("browser", "auto", True) else str(spec)
        self._solver = BrowserSolver(
            backend=backend,
            headless=self.headless,
            user_agent=self.user_agent,
            verbose=self.verbose,
        )
        return self._solver

    def _solve_cloudflare(self, request_url: str, page_url: str):
        """Use the browser solver to clear Cloudflare, then adopt its cookies.

        Returns ``(html, page_url)`` for the resolver to continue with. On
        failure, raises :class:`CloudflareChallengeError`.
        """
        self._log("Invoking browser solver for %s", request_url)
        solver = self._get_solver()
        try:
            result = solver.solve(request_url)
        except CloudflareChallengeError:
            raise
        except Exception as exc:  # noqa: BLE001 - surface as a CF error
            raise CloudflareChallengeError(
                f"Browser solver failed to clear Cloudflare: {exc}",
                reason="challenge",
            ) from exc

        # Adopt the browser's cf_clearance cookie + User-Agent so the remaining
        # plain-HTTP steps (e.g. the /links/go POST) are accepted.
        self.session.update_credentials(
            cookies=getattr(result, "cookies", None),
            user_agent=getattr(result, "user_agent", None),
        )
        html = getattr(result, "html", "") or ""
        final_url = getattr(result, "final_url", None) or page_url
        self._log("Browser solver returned %d bytes (url=%s)", len(html), final_url)
        return html, final_url

    # -- anti-bot detection ------------------------------------------------
    def _raise_if_cloudflare(self, html: str, status_code: Optional[int]) -> None:
        reason = html_utils.detect_cloudflare(html, status_code)
        if not reason:
            return

        self._log("Cloudflare protection detected: %s", reason)
        using_cf = self.session.backend == "cloudscraper"
        solver_tried = self._can_solve()

        if reason == "blocked":
            raise CloudflareChallengeError(
                "Cloudflare blocked the request (firewall / IP block). The "
                "server returned a Cloudflare block page instead of the "
                "shortener page, so the destination could not be resolved. "
                "This is not solvable by waiting; try a different network/IP, "
                "or supply a valid 'cf_clearance' cookie and matching "
                "user_agent from a browser session.",
                reason=reason,
            )

        if solver_tried:
            hint = (
                "The browser solver ran but the challenge did not clear. "
                "Retry with a visible browser (headless=False / --headful), "
                "increase the solver timeout, or solve it manually once and "
                "pass the resulting 'cf_clearance' cookie + matching user_agent."
            )
        elif not using_cf:
            hint = (
                "Use the browser solver to clear it automatically "
                "(solver='browser' / --solver browser, after e.g. "
                "pip install DrissionPage), or try backend='cloudscraper'."
            )
        else:
            hint = (
                "cloudscraper could not clear this challenge (it does not solve "
                "Turnstile / interactive managed challenges). Use the browser "
                "solver (solver='browser' / --solver browser, e.g. "
                "pip install DrissionPage), or solve it once in a real browser "
                "and pass the resulting 'cf_clearance' cookie plus the SAME "
                "user_agent (cookies={'cf_clearance': '...'}, user_agent='...')."
            )
        raise CloudflareChallengeError(
            f"Cloudflare {reason} detected. The server returned a Cloudflare "
            "challenge page instead of an adlinkfly page, so the destination "
            f"URL could not be resolved. {hint}",
            reason=reason,
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
