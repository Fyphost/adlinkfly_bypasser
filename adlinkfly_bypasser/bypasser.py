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
import re
import time
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urljoin, urlparse

from . import html_utils
from .exceptions import (
    AdlinkflyBypassError,
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

# Hosts that show up in HTML boilerplate (XML namespaces, schemas, fonts, CDNs,
# anti-bot widgets) and are never a real shortener destination. Used to reject
# false-positive URL matches such as the OpenGraph namespace "ogp.me/ns".
_JUNK_URL_HOSTS = (
    "ogp.me",
    "w3.org",
    "www.w3.org",
    "schema.org",
    "purl.org",
    "gmpg.org",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "ajax.googleapis.com",
    "cdnjs.cloudflare.com",
    "challenges.cloudflare.com",
    "www.google.com",
    "google.com",
    "gravatar.com",
    "secure.gravatar.com",
    "api.w.org",
)

# Substrings that mark a form as NOT the adlinkfly "go-link" form (e.g. the
# WordPress comment form on a destination blog page).
_NON_GOLINK_FORM_MARKERS = (
    "wp-comments-post",
    "comment_post_id",
    "comment_parent",
    "wp-login",
    "loginform",
    "searchform",
    "/search",
)

# Markers that identify an adlinkfly interstitial page.
_INTERSTITIAL_MARKERS = ("go-link", "/links/go", 'name="_token"', "name='_token'")


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
        browser_path: Optional[str] = None,
        xvfb: bool = False,
        follow: bool = True,
        max_hops: int = 25,
        verbose: bool = False,
    ):
        self.wait = wait
        self.wait_cap = wait_cap
        self.verbose = verbose
        self.user_agent = user_agent
        self.headless = headless
        self.browser_path = browser_path
        self.xvfb = xvfb
        self.follow = follow
        self.max_hops = max_hops
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
        browser_tried: set = set()

        for step in range(1, _MAX_STEPS + 1):
            self._log("Step %d: GET %s", step, current)
            resp = self.session.get(current)
            html = resp.text
            page_url = resp.url or current
            status = resp.status_code

            # 1) Cloudflare / anti-bot: hand off to the browser solver.
            if html_utils.detect_cloudflare(html, status):
                if self._can_solve():
                    browser_tried.add(current)
                    result = self._solve_via_browser(current)
                    outcome = self._result_from_solve(result, source, trail, step)
                    if outcome is not None:
                        return outcome
                    # non-follow: continue HTTP resolution on the rendered page
                    html = getattr(result, "html", "") or html
                    page_url = getattr(result, "final_url", None) or page_url
                else:
                    self._raise_if_cloudflare(html, status)

            resolved, method = self._resolve_page(page_url, html)

            # 2) No destination via HTTP: if a browser solver is available, let
            # it drive the page (handles JS-only / multi-page sites with no
            # Cloudflare, e.g. blog content-lockers that need real clicks).
            if resolved is None and self._can_solve() and current not in browser_tried:
                self._log("HTTP resolution failed; trying browser solver")
                browser_tried.add(current)
                result = self._solve_via_browser(current)
                outcome = self._result_from_solve(result, source, trail, step)
                if outcome is not None:
                    return outcome
                html = getattr(result, "html", "") or html
                page_url = getattr(result, "final_url", None) or page_url
                resolved, method = self._resolve_page(page_url, html)

            if resolved is None:
                raise ResolutionError(
                    "Could not find a destination link on the page. The site "
                    "may not be adlinkfly-based, may require JavaScript, or may "
                    "be protected by an anti-bot layer. Try the browser solver "
                    "(--solver browser, e.g. pip install DrissionPage) or "
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
            follow=self.follow,
            max_hops=self.max_hops,
            user_agent=self.user_agent,
            browser_path=self.browser_path,
            xvfb=self.xvfb,
            verbose=self.verbose,
        )
        return self._solver

    def _solve_via_browser(self, request_url: str):
        """Run the browser solver (clear Cloudflare + walk ad pages), adopt its
        cookies/User-Agent, and return the :class:`SolveResult`."""
        self._log("Invoking browser solver for %s", request_url)
        solver = self._get_solver()
        try:
            result = solver.solve(request_url)
        except AdlinkflyBypassError:
            raise  # BrowserSolverError / CloudflareChallengeError - keep as-is
        except Exception as exc:  # noqa: BLE001 - surface as a CF error
            raise CloudflareChallengeError(
                f"Browser solver failed: {exc}", reason="challenge"
            ) from exc

        self.session.update_credentials(
            cookies=getattr(result, "cookies", None),
            user_agent=getattr(result, "user_agent", None),
        )
        self._log(
            "Browser solver returned %d bytes (reached_final=%s, ended=%s, url=%s)",
            len(getattr(result, "html", "") or ""),
            getattr(result, "reached_final", False),
            getattr(result, "ended", ""),
            getattr(result, "final_url", None),
        )
        return result

    # Walk outcomes that represent a "clean" stop (vs. stuck/loop/max_hops).
    _CLEAN_ENDINGS = ("no_controls", "not_followed", "")

    def _result_from_solve(self, result, source, trail, step):
        """Turn a browser :class:`SolveResult` into a :class:`BypassResult` to
        return, or ``None`` to signal "continue HTTP resolution on the rendered
        page". Raises the appropriate error when the browser attempt failed.
        """
        final = getattr(result, "final_url", None)
        reached = getattr(result, "reached_final", False)
        ended = getattr(result, "ended", "")
        html = getattr(result, "html", "") or ""

        # 1) Reached a real file-host / cloud-drive link -> done.
        if final and (reached or html_utils.is_final_link(final)):
            trail.append(final)
            return BypassResult(source, final, step, "browser_walk", trail)

        # 2) Still stuck on a Cloudflare page -> precise CF error.
        if html_utils.detect_cloudflare(html):
            self._raise_if_cloudflare(html, None)

        # 3) The rendered page is an adlinkfly interstitial -> let the HTTP
        #    resolver finish it (now armed with the browser's cookies).
        if self._looks_like_interstitial(html):
            return None

        # 4) Off-domain, non-interstitial landing. Only accept this as the
        #    destination when NOT following an ad-walk (e.g. a Cloudflare-only
        #    solve that landed straight on the target), and never accept an
        #    error/404 page. In follow mode an off-domain blog/ad page is just
        #    another ad hop, not the destination - so we fall through to (5).
        if (
            final
            and not self.follow
            and self._left_domain(source, final)
            and not self._is_error_or_notfound(html)
        ):
            trail.append(final)
            return BypassResult(source, final, step, "browser_redirect", trail)

        # 5) A followed ad-walk that got stuck / looped / hit max hops.
        if self.follow:
            if ended == "blocked_or_stale":
                raise ResolutionError(
                    "The site returned an error/stub page (e.g. a 'Reload Page' "
                    "screen) instead of the ad flow. The link may be expired, or "
                    f"the site is rate-limiting/blocking this IP. Last page: {final or '?'}. "
                    "Wait a while and retry, try a different network/IP, or run "
                    "with --headful to see what the page shows."
                )
            raise ResolutionError(
                "Walked the ad-page chain but could not reach a final "
                f"file-host link (ended: {ended or 'unknown'}). Last page: "
                f"{final or '?'}. The site's ad flow may need --headful, a "
                "higher --max-hops, or manual interaction."
            )
        return None  # non-follow: let HTTP resolution try the rendered page

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
        if dest and not self._is_social(dest, page_url):
            return dest, "meta_refresh"

        # Strategy 4: JavaScript location assignment.
        dest = html_utils.find_js_redirect(html)
        if dest and self._looks_external(dest, page_url) and not self._is_social(dest, page_url):
            return dest, "js_redirect"

        # Strategy 5: an obvious action anchor (Get Link / Download / ...).
        dest = html_utils.find_action_anchor(html)
        if dest and self._looks_external(dest, page_url) and not self._is_social(dest, page_url):
            return dest, "anchor"

        return None, ""

    def _is_social(self, candidate: str, page_url: str) -> bool:
        """True if the candidate is a social/community 'join us' decoy link."""
        return html_utils.is_social_url(urljoin(page_url, candidate))

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

            dest = self._extract_url_from_response(resp.text, json_only=True)
            if dest:
                return dest
        return None

    def _try_generic_form_post(self, page_url: str, html: str) -> Optional[str]:
        for form in html_utils.parse_forms(html):
            if form.method_upper != "POST" or not form.action:
                continue
            # Never submit obviously-unrelated forms (comment/login/search),
            # which would cause side effects and yield junk.
            action = (form.action or "").lower()
            keys = " ".join(k.lower() for k in form.inputs)
            if any(m in action + " " + keys for m in _NON_GOLINK_FORM_MARKERS):
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
            dest = self._extract_url_from_response(resp.text, json_only=True)
            if dest and self._looks_external(dest, page_url) and not self._is_social(dest, page_url):
                return dest
        return None

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _is_golink_form(form) -> bool:
        """True only if the form has a real adlinkfly 'go-link' signal.

        This deliberately rejects unrelated forms (WordPress comment/search/
        login) that happen to share generic field names like ``url``/``email``.
        """
        keys = {k.lower() for k in form.inputs}
        action = (form.action or "").lower()
        fid = (form.id or "").lower()

        # Hard reject known non-adlinkfly forms.
        haystack = action + " " + " ".join(keys)
        if any(marker in haystack for marker in _NON_GOLINK_FORM_MARKERS):
            return False

        # Strong adlinkfly signals - at least one is required.
        return (
            "_token" in keys
            or "links/go" in action
            or action.endswith("/go")
            or any(t in fid for t in ("go-link", "go_link", "golink", "landing", "shortlink"))
        )

    @classmethod
    def _pick_form(cls, forms):
        """Choose the form most likely to be the adlinkfly 'go' form.

        Returns ``None`` unless a form with a genuine go-link signal exists, so
        we never POST an unrelated form (which previously scraped junk URLs).
        """
        candidates = [f for f in forms if f.inputs and cls._is_golink_form(f)]
        if not candidates:
            return None

        def score(form):
            s = 0
            keys = {k.lower() for k in form.inputs}
            if "_token" in keys:
                s += 5
            if "link" in keys or "url" in keys:
                s += 2
            if form.id and any(
                t in form.id.lower() for t in ("go", "link", "landing")
            ):
                s += 3
            if form.action and "go" in form.action.lower():
                s += 2
            if form.method_upper == "POST":
                s += 1
            s += min(len(form.inputs), 3)
            return s

        return max(candidates, key=score)

    @classmethod
    def _extract_url_from_response(cls, text: str, json_only: bool = False) -> Optional[str]:
        """Pull a destination URL out of a response body.

        With ``json_only`` (used for the ``/links/go`` POST, which returns
        JSON), only a JSON ``url``-style field is accepted - this prevents
        scraping a stray URL out of an HTML page that a mis-fired POST returned
        (e.g. the OpenGraph namespace ``https://ogp.me/ns``).
        """
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
                    if isinstance(val, str) and cls._is_real_destination(val):
                        return val
                nested = data.get("data")
                if isinstance(nested, dict):
                    for key in ("url", "link"):
                        val = nested.get(key)
                        if isinstance(val, str) and cls._is_real_destination(val):
                            return val
        except (ValueError, TypeError):
            pass

        if json_only:
            return None

        # Fallback: a bare URL somewhere in the body (only when not json_only).
        import re

        for m in re.finditer(r'https?://[^\s"\'<>\\)]+', text):
            candidate = m.group(0).rstrip(".,;")
            if cls._is_real_destination(candidate):
                return candidate
        return None

    @staticmethod
    def _is_real_destination(url: str) -> bool:
        """Reject non-http, namespace/schema/CDN, and anti-bot boilerplate URLs."""
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            return False
        host = urlparse(url).netloc.split("@")[-1].split(":")[0].lower()
        if not host:
            return False
        return host not in _JUNK_URL_HOSTS

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

    def _left_domain(self, source: str, current: str) -> bool:
        """True if *current* is on a different registrable domain than *source*."""
        return not self._same_registrable_domain(source, current)

    @staticmethod
    def _looks_like_interstitial(html: str) -> bool:
        """True if the page looks like an adlinkfly interstitial (not a plain
        destination page)."""
        if not html:
            return False
        low = html.lower()
        return any(marker.lower() in low for marker in _INTERSTITIAL_MARKERS)

    @staticmethod
    def _is_error_or_notfound(html: str) -> bool:
        """True if the page is a 404 / error / block page (never a destination)."""
        if not html:
            return True
        low = html.lower()
        markers = (
            "page not found",
            "page can't be found",
            "page can\u2019t be found",
            "nothing was found at this location",
            "404 not found",
            "error 404",
            "not found",
            "you have been blocked",
            "access denied",
            "too many requests",
        )
        # Prefer the <title> when available (avoids matching article prose).
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        title = (m.group(1).lower() if m else "")
        if any(k in title for k in ("not found", "404", "error", "blocked", "denied")):
            return True
        return any(k in low for k in markers[:6])

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
