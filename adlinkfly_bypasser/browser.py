"""Optional real-browser solver for Cloudflare-protected & multi-page shorteners.

Two jobs this module handles that a plain HTTP client cannot:

1. **Cloudflare** managed challenges / Turnstile - cleared by rendering the page
   in a real Chromium browser and waiting for the challenge to pass.
2. **Multi-page "blog" content-lockers** - many adlinkfly links don't point
   straight at the destination; they bounce you through 2-4 ad/blog pages, each
   with a countdown and a "Continue / Get Link" button, before finally revealing
   a file-host link (e.g. Terabox). The solver can *walk* that chain: on each
   page it waits out the countdown, clicks the continue control, and repeats
   until it reaches a real file-host link.

The browser's cookies (incl. ``cf_clearance``) and User-Agent are returned so
the rest of the adlinkfly HTTP flow can reuse them if needed.

Supported drivers, auto-selected in this order (first installed wins):

1. ``DrissionPage``   - CDP-based, most reliable against Cloudflare.
2. ``seleniumbase``   - UC (undetected) mode with CAPTCHA-click helpers.
3. ``undetected_chromedriver``
4. ``playwright``     - last resort.

Install one, e.g.::

    pip install DrissionPage

None are imported unless a solver is actually used, so the base package stays
dependency-free.
"""

from __future__ import annotations

import glob
import importlib.util
import logging
import os
import re
import shutil
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import html_utils
from .exceptions import AdlinkflyBypassError

logger = logging.getLogger("adlinkfly_bypasser.browser")

# Auto-selection order.
_BACKENDS = ("drissionpage", "seleniumbase", "undetected", "playwright")

# Clickable-candidate selectors. The base is standard and always valid; the
# extended one also grabs the non-standard controls that safelink/blog-locker
# plugins use - <div>/<span> styled as buttons (onclick / role=button) and
# elements whose id/class hints at the advance/get-link/download/verify action.
# They are queried separately so that if the extended (case-insensitive
# attribute) selector isn't supported, we still get anchors/buttons.
_CANDIDATE_CSS_BASE = "a, button, input[type=submit], input[type=button]"
_CANDIDATE_CSS_EXTRA = (
    "[onclick], [role=button], "
    "[id*=wpsafe i], [class*=wpsafe i], [id*=safelink i], [class*=safelink i], "
    "[id*=generate i], [class*=generate i], "
    "[id*=getlink i], [id*=get-link i], [class*=get-link i], [class*=getlink i], "
    "[id*=download i], [class*=download i], "
    "[id*=continue i], [class*=continue i], "
    "[id*=human i], [class*=human i], "
    "[id*=btn i], [class*=btn i], [class*=button i]"
)
_CANDIDATE_SELECTORS = (_CANDIDATE_CSS_BASE, _CANDIDATE_CSS_EXTRA)

# Executable names looked up on PATH.
_CHROME_ON_PATH = (
    "google-chrome-stable",
    "google-chrome",
    "chromium",
    "chromium-browser",
    "chrome",
    "brave-browser",
)

# Absolute paths / globs to probe for a Chromium-family binary, including
# browsers downloaded by Playwright.
_CHROME_PATH_GLOBS = (
    "/usr/bin/google-chrome-stable",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/snap/bin/chromium",
    "/opt/google/chrome/chrome",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "~/.cache/ms-playwright/chromium-*/chrome-linux/chrome",
    "~/.cache/ms-playwright/chromium-*/chrome-mac/Chromium.app/Contents/MacOS/Chromium",
    "~/.cache/ms-playwright/chromium_headless_shell-*/chrome-linux/headless_shell",
    "~/.cache/ms-playwright/chromium_headless_shell-*/chrome-linux*/headless_shell",
)


def find_browser_binary() -> Optional[str]:
    """Best-effort search for an installed Chromium-family browser binary.

    Checks ``$CHROME_BIN`` / ``$CHROME_PATH``, then PATH, then common install
    locations (including Playwright's downloaded browsers). Returns the path or
    ``None``.
    """
    for env in ("CHROME_BIN", "CHROME_PATH", "CHROMIUM_PATH"):
        val = os.environ.get(env)
        if val and os.path.exists(val):
            return val

    for name in _CHROME_ON_PATH:
        found = shutil.which(name)
        if found:
            return found

    candidates: List[str] = []
    for pattern in _CHROME_PATH_GLOBS:
        expanded = os.path.expanduser(pattern)
        if any(ch in expanded for ch in "*?["):
            candidates.extend(sorted(glob.glob(expanded), reverse=True))
        elif os.path.exists(expanded):
            candidates.append(expanded)
    for path in candidates:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    return None


# Map backend name -> importable module used to detect availability.
_BACKEND_MODULE = {
    "drissionpage": "DrissionPage",
    "seleniumbase": "seleniumbase",
    "undetected": "undetected_chromedriver",
    "playwright": "playwright",
}


class BrowserSolverError(AdlinkflyBypassError):
    """Raised when no browser backend is available or a solve attempt fails."""


@dataclass
class SolveResult:
    """What a browser solve produced once the flow was walked / CF cleared."""

    html: str
    cookies: Dict[str, str] = field(default_factory=dict)
    user_agent: Optional[str] = None
    final_url: Optional[str] = None
    cleared: bool = True
    # True only when final_url is a recognised file-host / cloud-drive link
    # (as opposed to where the walk happened to stop, e.g. an ad page).
    reached_final: bool = False
    # Short reason the walk ended: "final_link", "no_controls", "max_hops",
    # "stuck", "loop", "not_followed".
    ended: str = ""


def available_backends():
    """Return the list of browser backends currently importable."""
    found = []
    for name, module in _BACKEND_MODULE.items():
        try:
            if importlib.util.find_spec(module) is not None:
                found.append(name)
        except (ImportError, ValueError):
            continue
    return found


def _safe(fn, default=""):
    """Call *fn* and return its value, swallowing any error (returns default)."""
    try:
        v = fn()
        return v if v is not None else default
    except Exception:  # noqa: BLE001
        return default


# ==========================================================================
# Per-driver adapters: a tiny uniform interface over each browser library.
# ==========================================================================
class _DrissionAdapter:
    name = "drissionpage"

    def __init__(self, solver: "BrowserSolver"):
        from DrissionPage import ChromiumOptions, ChromiumPage  # type: ignore

        co = ChromiumOptions()
        if solver.browser_path:
            try:
                co.set_browser_path(solver.browser_path)
            except Exception:  # noqa: BLE001
                pass
        if solver.headless:
            co.headless()
        if solver.user_agent:
            try:
                co.set_user_agent(solver.user_agent)
            except Exception:  # noqa: BLE001
                pass
        for arg in ("--no-sandbox", "--disable-dev-shm-usage"):
            try:
                co.set_argument(arg)
            except Exception:  # noqa: BLE001
                pass
        self._page = ChromiumPage(co)
        self._main_id = _safe(lambda: self._page.tab_id, default=None)

    def goto(self, url):
        self._page.get(url)

    def current_url(self):
        return _safe(lambda: self._page.url)

    def page_html(self):
        return _safe(lambda: self._page.html)

    def get_cookies(self):
        ck = _safe(lambda: self._page.cookies(as_dict=True), default=None)
        if isinstance(ck, dict):
            return {str(k): str(v) for k, v in ck.items()}
        return {}

    def get_user_agent(self):
        ua = _safe(lambda: self._page.user_agent, default=None)
        if ua:
            return ua
        return _safe(lambda: self._page.run_js("return navigator.userAgent"), default=None)

    def candidates(self):
        out = []
        seen = set()
        for selector in _CANDIDATE_SELECTORS:
            els = _safe(lambda: self._page.eles("css:" + selector), default=[]) or []
            for el in els:
                try:
                    if id(el) in seen:
                        continue
                    seen.add(id(el))
                    if _safe(lambda: el.states.is_displayed, default=True) is False:
                        continue
                    out.append({
                        "text": _safe(lambda: el.text),
                        "value": _safe(lambda: el.attr("value")),
                        "id": _safe(lambda: el.attr("id")),
                        "cls": _safe(lambda: el.attr("class")),
                        "href": _safe(lambda: el.attr("href")),
                        "aria": _safe(lambda: el.attr("aria-label")),
                        "tag": _safe(lambda: el.tag),
                        "handle": el,
                    })
                except Exception:  # noqa: BLE001
                    continue
        return out

    def click(self, handle):
        try:
            handle.click()
        except Exception:  # noqa: BLE001
            handle.click(by_js=True)

    def wait_idle(self):
        _safe(lambda: self._page.wait.doc_loaded(timeout=15))

    def handle_new_tabs(self):
        """If a click opened new tabs: switch to one holding the final link,
        otherwise close the pop-ups (ads) and stay on the main tab."""
        ids = _safe(lambda: list(self._page.tab_ids), default=[]) or []
        if len(ids) <= 1:
            return
        for tid in ids:
            url = _safe(lambda t=tid: self._page.get_tab(t).url, default="")
            if html_utils.is_final_link(url):
                tab = _safe(lambda t=tid: self._page.get_tab(t), default=None)
                if tab is not None:
                    self._page = tab
                    self._main_id = tid
                break
        self.close_popups()

    def close_popups(self):
        ids = _safe(lambda: list(self._page.tab_ids), default=[]) or []
        if len(ids) <= 1:
            return
        main = self._main_id if self._main_id in ids else ids[-1]
        for tid in ids:
            if tid != main:
                _safe(lambda t=tid: self._page.get_tab(t).close())
        tab = _safe(lambda: self._page.get_tab(main), default=None)
        if tab is not None:
            self._page = tab
        _safe(lambda: self._page.set.activate())

    def click_image_ad(self):
        for sel in ("css:.entry-content a img", "css:article a img",
                    "css:.post-content a img", "css:a img", "css:img"):
            el = _safe(lambda s=sel: self._page.ele(s, timeout=1), default=None)
            if el:
                try:
                    el.click()
                    return True
                except Exception:  # noqa: BLE001
                    _safe(lambda: el.click(by_js=True))
                    return True
        return False

    def back(self):
        _safe(lambda: self._page.back())

    def reload(self):
        _safe(lambda: self._page.refresh())

    def quit(self):
        _safe(lambda: self._page.quit())


class _SeleniumAdapter:
    """Shared adapter for undetected-chromedriver and SeleniumBase UC mode."""

    def __init__(self, solver: "BrowserSolver", driver):
        from selenium.webdriver.common.by import By  # type: ignore

        self._solver = solver
        self._driver = driver
        self._By = By
        self._main = _safe(lambda: driver.current_window_handle, default=None)

    def goto(self, url):
        d = self._driver
        opened = False
        if hasattr(d, "uc_open_with_reconnect"):
            try:
                d.uc_open_with_reconnect(url, reconnect_time=4)
                opened = True
            except Exception:  # noqa: BLE001
                opened = False
        if not opened:
            d.get(url)
        if hasattr(d, "uc_gui_click_captcha"):
            try:
                d.uc_gui_click_captcha()
            except Exception:  # noqa: BLE001
                pass

    def current_url(self):
        return _safe(lambda: self._driver.current_url)

    def page_html(self):
        return _safe(lambda: self._driver.page_source)

    def get_cookies(self):
        cks = _safe(lambda: self._driver.get_cookies(), default=[]) or []
        return {c["name"]: c.get("value", "") for c in cks if "name" in c}

    def get_user_agent(self):
        return _safe(
            lambda: self._driver.execute_script("return navigator.userAgent"),
            default=None,
        )

    def candidates(self):
        out = []
        seen = set()
        for selector in _CANDIDATE_SELECTORS:
            els = _safe(
                lambda: self._driver.find_elements(self._By.CSS_SELECTOR, selector),
                default=[],
            ) or []
            for el in els:
                if id(el) in seen:
                    continue
                seen.add(id(el))
                try:
                    if not el.is_displayed():
                        continue
                except Exception:  # noqa: BLE001
                    pass
                out.append({
                    "text": _safe(lambda: el.text),
                    "value": _safe(lambda: el.get_attribute("value")),
                    "id": _safe(lambda: el.get_attribute("id")),
                    "cls": _safe(lambda: el.get_attribute("class")),
                    "href": _safe(lambda: el.get_attribute("href")),
                    "aria": _safe(lambda: el.get_attribute("aria-label")),
                    "tag": _safe(lambda: el.tag_name),
                    "handle": el,
                })
        return out

    def click(self, handle):
        try:
            handle.click()
        except Exception:  # noqa: BLE001
            self._driver.execute_script("arguments[0].click();", handle)

    def wait_idle(self):
        time.sleep(1.0)

    def handle_new_tabs(self):
        handles = _safe(lambda: self._driver.window_handles, default=[]) or []
        if len(handles) <= 1:
            return
        for h in handles:
            _safe(lambda hh=h: self._driver.switch_to.window(hh))
            if html_utils.is_final_link(self.current_url()):
                self._main = h
                break
        self.close_popups()

    def close_popups(self):
        handles = _safe(lambda: self._driver.window_handles, default=[]) or []
        if len(handles) <= 1:
            return
        main = self._main if self._main in handles else handles[0]
        for h in handles:
            if h != main:
                _safe(lambda hh=h: (self._driver.switch_to.window(hh),
                                    self._driver.close()))
        _safe(lambda: self._driver.switch_to.window(main))

    def click_image_ad(self):
        for sel in (".entry-content a img", "article a img",
                    ".post-content a img", "a img", "img"):
            els = _safe(
                lambda s=sel: self._driver.find_elements(self._By.CSS_SELECTOR, s),
                default=[],
            ) or []
            for el in els:
                try:
                    if el.is_displayed():
                        el.click()
                        return True
                except Exception:  # noqa: BLE001
                    _safe(lambda e=el: self._driver.execute_script(
                        "arguments[0].click();", e))
                    return True
        return False

    def back(self):
        _safe(lambda: self._driver.back())

    def reload(self):
        _safe(lambda: self._driver.refresh())

    def quit(self):
        _safe(lambda: self._driver.quit())


class _PlaywrightAdapter:
    name = "playwright"

    def __init__(self, solver: "BrowserSolver"):
        from playwright.sync_api import sync_playwright  # type: ignore

        self._pw = sync_playwright().start()
        launch = {"headless": solver.headless}
        if solver.browser_path:
            launch["executable_path"] = solver.browser_path
        self._browser = self._pw.chromium.launch(**launch)
        ctx = {}
        if solver.user_agent:
            ctx["user_agent"] = solver.user_agent
        self._context = self._browser.new_context(**ctx)
        self._page = self._context.new_page()

    def goto(self, url):
        self._page.goto(url, wait_until="domcontentloaded")

    def current_url(self):
        return _safe(lambda: self._page.url)

    def page_html(self):
        return _safe(lambda: self._page.content())

    def get_cookies(self):
        cks = _safe(lambda: self._context.cookies(), default=[]) or []
        return {c["name"]: c["value"] for c in cks if "name" in c}

    def get_user_agent(self):
        return _safe(lambda: self._page.evaluate("navigator.userAgent"), default=None)

    def candidates(self):
        out = []
        seen = set()
        for selector in _CANDIDATE_SELECTORS:
            els = _safe(lambda: self._page.query_selector_all(selector), default=[]) or []
            for el in els:
                if id(el) in seen:
                    continue
                seen.add(id(el))
                try:
                    if not el.is_visible():
                        continue
                except Exception:  # noqa: BLE001
                    pass
                out.append({
                    "text": _safe(lambda: el.inner_text()),
                    "value": _safe(lambda: el.get_attribute("value")),
                    "id": _safe(lambda: el.get_attribute("id")),
                    "cls": _safe(lambda: el.get_attribute("class")),
                    "href": _safe(lambda: el.get_attribute("href")),
                    "aria": _safe(lambda: el.get_attribute("aria-label")),
                    "tag": "",
                    "handle": el,
                })
        return out

    def click(self, handle):
        handle.click(timeout=5000)

    def wait_idle(self):
        _safe(lambda: self._page.wait_for_load_state("domcontentloaded", timeout=15000))

    def handle_new_tabs(self):
        pages = _safe(lambda: self._context.pages, default=[]) or []
        if len(pages) <= 1:
            return
        for p in pages:
            if html_utils.is_final_link(_safe(lambda pp=p: pp.url, default="")):
                self._page = p
                break
        self.close_popups()

    def close_popups(self):
        pages = _safe(lambda: self._context.pages, default=[]) or []
        if len(pages) <= 1:
            return
        keep = self._page if self._page in pages else pages[0]
        for p in pages:
            if p is not keep:
                _safe(lambda pp=p: pp.close())
        self._page = keep

    def click_image_ad(self):
        for sel in (".entry-content a img", "article a img",
                    ".post-content a img", "a img", "img"):
            el = _safe(lambda s=sel: self._page.query_selector(s), default=None)
            if el:
                _safe(lambda: el.click(timeout=4000))
                return True
        return False

    def back(self):
        _safe(lambda: self._page.go_back())

    def reload(self):
        _safe(lambda: self._page.reload())

    def quit(self):
        _safe(lambda: self._browser.close())
        _safe(lambda: self._pw.stop())


class BrowserSolver:
    """Drive a real browser to clear Cloudflare and walk multi-page ad flows.

    Parameters
    ----------
    backend:
        ``"auto"`` (default) picks the first installed driver, or force one of
        ``"drissionpage"``, ``"seleniumbase"``, ``"undetected"``, ``"playwright"``.
    headless:
        Run without a visible window. Headless is more likely to be detected by
        Cloudflare; if solving fails, retry headed (``headless=False``) or with
        ``xvfb=True``.
    follow:
        Walk multi-page ad/blog interstitials (click "Continue / Get Link"
        through each page) until a final file-host link is reached. Default
        ``True``. Set ``False`` to only clear Cloudflare and return the first
        page.
    max_hops:
        Maximum number of ad pages to click through.
    timeout:
        Max seconds to wait per phase (challenge clear, countdown, navigation).
    poll:
        Seconds between polls.
    settle:
        Extra seconds to wait after a challenge clears before capturing.
    user_agent, browser_path, xvfb:
        See the module docs / README. ``browser_path`` is auto-detected if
        omitted; ``xvfb`` runs headed under a virtual display on servers.
    verbose:
        Log progress at INFO level (very useful for debugging a specific site).
    """

    def __init__(
        self,
        backend: str = "auto",
        headless: bool = True,
        follow: bool = True,
        max_hops: int = 25,
        time_budget: int = 150,
        timeout: int = 60,
        poll: float = 2.0,
        settle: float = 3.0,
        user_agent: Optional[str] = None,
        browser_path: Optional[str] = None,
        xvfb: bool = False,
        verbose: bool = False,
    ):
        self.headless = headless
        self.follow = follow
        self.max_hops = max_hops
        self.time_budget = time_budget
        self.timeout = timeout
        self.poll = poll
        self.settle = settle
        self.user_agent = user_agent
        self.xvfb = xvfb
        self.verbose = verbose
        self.backend = self._select(backend)
        self.browser_path = browser_path or find_browser_binary()
        if self.browser_path:
            self._log("Using browser binary: %s", self.browser_path)
        else:
            self._log("No browser binary auto-detected; driver default will apply")

    def _select(self, backend: str) -> str:
        found = available_backends()
        if backend == "auto":
            for name in _BACKENDS:
                if name in found:
                    return name
            raise BrowserSolverError(
                "No browser backend is installed. Install one of: "
                "DrissionPage, seleniumbase, undetected-chromedriver, or "
                "playwright. For example:  pip install DrissionPage"
            )
        if backend not in _BACKEND_MODULE:
            raise BrowserSolverError(f"Unknown browser backend: {backend!r}")
        if backend not in found:
            module = _BACKEND_MODULE[backend]
            raise BrowserSolverError(
                f"Browser backend {backend!r} requested but its package "
                f"({module!r}) is not importable. Install it first."
            )
        return backend

    def _log(self, msg, *args):
        if self.verbose:
            logger.info(msg, *args)

    # -- public API --------------------------------------------------------
    def solve(self, url: str) -> SolveResult:
        """Load *url*, clear Cloudflare, optionally walk ad pages, and return
        the rendered page + cookies + the final URL reached."""
        self._log("Browser solver (%s) opening %s", self.backend, url)
        display = None
        if self.xvfb and self.backend != "seleniumbase":
            display = self._start_virtual_display()
        adapter = None
        try:
            adapter = self._build_adapter()
            adapter.goto(url)
            html, cleared = self._wait_cleared_adapter(adapter)
            if not self.follow:
                final = html_utils.find_final_link(html)
                return self._capture(
                    adapter, html, final=final, cleared=cleared,
                    reached=bool(final), ended="not_followed",
                )
            return self._walk(adapter, html, cleared)
        finally:
            if adapter is not None:
                adapter.quit()
            if display is not None:
                try:
                    display.stop()
                except Exception:  # noqa: BLE001
                    pass

    # -- adapter construction ---------------------------------------------
    def _build_adapter(self):
        if self.backend == "drissionpage":
            return _DrissionAdapter(self)
        if self.backend == "playwright":
            return _PlaywrightAdapter(self)
        if self.backend == "seleniumbase":
            from seleniumbase import Driver  # type: ignore

            kwargs = {"uc": True, "headless": self.headless, "agent": self.user_agent}
            if self.xvfb:
                kwargs["xvfb"] = True
                kwargs["headless"] = False
            if self.browser_path:
                kwargs["binary_location"] = self.browser_path
            return _SeleniumAdapter(self, Driver(**kwargs))
        if self.backend == "undetected":
            import undetected_chromedriver as uc  # type: ignore

            options = uc.ChromeOptions()
            if self.headless:
                options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            if self.user_agent:
                options.add_argument(f"--user-agent={self.user_agent}")
            uc_kwargs = {"options": options}
            if self.browser_path:
                uc_kwargs["browser_executable_path"] = self.browser_path
            return _SeleniumAdapter(self, uc.Chrome(**uc_kwargs))
        raise BrowserSolverError(f"Unsupported backend: {self.backend}")

    # -- Cloudflare wait ---------------------------------------------------
    def _wait_cleared_adapter(self, adapter):
        deadline = time.time() + self.timeout
        html = ""
        while time.time() < deadline:
            html = adapter.page_html() or ""
            if html and html_utils.detect_cloudflare(html) is None:
                self._log("Cloudflare cleared / not present")
                if self.settle:
                    time.sleep(self.settle)
                return adapter.page_html() or html, True
            time.sleep(self.poll)
        self._log("Timed out waiting for Cloudflare to clear")
        return html, html_utils.detect_cloudflare(html) is None

    # -- multi-page walk ---------------------------------------------------
    # Some plugins (e.g. WPSafelink) require clicking the *same* control more
    # than once (a "Generate link" button often needs two clicks). Allow a
    # control to be clicked up to this many times per page before excluding it.
    _MAX_CLICKS_PER_CONTROL = 3

    def _walk(self, adapter, html, cleared):
        click_counts = {}  # signature -> times clicked ON THIS PAGE
        visited = []  # ordered URLs seen (for loop detection)
        gated = set()  # URLs whose "click an image" gate we've already handled
        stuck = 0
        reloads = 0
        last_url = None
        hop_timeout = min(self.timeout, 12)
        deadline = time.time() + getattr(self, "time_budget", 150)
        ended = "max_hops"

        for hop in range(1, self.max_hops + 1):
            if time.time() > deadline:
                ended = "timeout"
                self._log("Walk time budget exceeded; stopping")
                break
            cur = adapter.current_url()
            self._log("Ad-page hop %d: %s", hop, cur)
            if self.verbose:
                self._log("  controls: %s", self._labels(adapter))

            # Already on the final file link?
            if html_utils.is_final_link(cur):
                self._log("Reached final file-host in the address bar")
                return self._capture(adapter, adapter.page_html(), final=cur,
                                     cleared=cleared, reached=True, ended="final_link")

            # New page => fresh click counts (a "Continue" on a different page
            # is legitimately different even if it shares a label).
            if cur != last_url:
                click_counts = {}
                last_url = cur
            looping = cur in visited
            visited.append(cur)

            # Fast path: if a Terabox/Drive link is already embedded in the
            # page, surface it immediately (no need to wait/click further).
            early = self._find_final(adapter.page_html() or "")
            if early:
                self._log("Found embedded final link: %s", early)
                return self._capture(adapter, adapter.page_html(), final=early,
                                     cleared=cleared, reached=True, ended="final_link")

            # Error/stub page ("Reload Page", browser net error, empty body):
            # the site likely rate-limited us or the link is stale. Reload and
            # retry a couple of times before giving up.
            if reloads < 2 and self._is_error_page(adapter):
                reloads += 1
                self._log("Page looks like an error/reload stub; reloading (%d/2)", reloads)
                self._log_stub_page(adapter)
                adapter.reload()
                time.sleep(3)
                self._wait_cleared_adapter(adapter)
                continue

            # NOTE: we deliberately do NOT wait out the page countdown. These
            # "Continue / Verify / Click to Verify / Get Link" buttons work when
            # clicked immediately; waiting the 8-15s timers just burns the time
            # budget. Click instantly and move on.

            # "Click an image, wait, come back" ad gate: note it, but do NOT
            # auto-click arbitrary page images - that navigates to random
            # ad/404 pages and derails the flow. We rely on the real advance
            # control ("Continue"/"Get Link") instead; a true image-view gate
            # needs --headful manual assist.
            if cur not in gated and html_utils.is_image_gate(adapter.page_html() or ""):
                gated.add(cur)
                self._log("Image-gate instruction present (not auto-clicking; may need --headful)")

            # Is this the LAST ad page? (It references a file-host, e.g. a
            # Terabox preview thumbnail.) If so, wait harder for the real
            # share link / reveal button rather than clicking a looping
            # "Continue".
            on_final_page = html_utils.references_final_host(adapter.page_html() or "")
            scan_secs = hop_timeout if on_final_page else self.settle
            final = self._scan_final(adapter, seconds=scan_secs)
            if final:
                self._log("Found final file-host link in page: %s", final)
                return self._capture(adapter, adapter.page_html(), final=final,
                                     cleared=cleared, reached=True, ended="final_link")

            # Prefer a real reveal/get-link control; on the final page, refuse
            # to click a plain "Continue" (it just loops through more ads).
            # Exclude controls we've already clicked the max number of times.
            exhausted = {
                sig for sig, c in click_counts.items()
                if c >= self._MAX_CLICKS_PER_CONTROL
            }
            cand = self._wait_for_continue(
                adapter, exclude=exhausted, timeout=hop_timeout,
                reveal_only=on_final_page,
            )
            if cand is None:
                ended = "blocked_or_stale" if self._is_error_page(adapter) else "no_controls"
                self._log("No usable continue/get-link control. Controls: %s", self._labels(adapter))
                self._log_page_markers(adapter)
                self._log_stub_page(adapter)
                break

            sig = html_utils.candidate_signature(cand)
            click_counts[sig] = click_counts.get(sig, 0) + 1
            label = str(cand.get("text") or cand.get("value") or cand.get("id") or "").strip()[:60]
            reveal = html_utils.is_reveal_control(cand)
            before_url = cur
            before_len = len(adapter.page_html() or "")
            self._log("Clicking %s control: %r (x%d)", "get-link" if reveal else "continue",
                      label or "<unnamed>", click_counts[sig])
            try:
                adapter.click(cand["handle"])
            except Exception as exc:  # noqa: BLE001
                self._log("Click failed: %s", exc)
                continue
            adapter.wait_idle()
            adapter.handle_new_tabs()

            final, progressed = self._wait_progress(adapter, before_url, before_len, hop_timeout)
            if final:
                self._log("Found final file-host link after click: %s", final)
                return self._capture(adapter, adapter.page_html(), final=final,
                                     cleared=cleared, reached=True, ended="final_link")
            if progressed and adapter.current_url() not in visited:
                stuck = 0
            else:
                stuck += 1
                if looping:
                    self._log("Revisited a page (ad loop) at hop %d", hop)
                self._log("No forward progress after click (stuck=%d)", stuck)
                # Give JS / countdowns a moment - the same control may need
                # another click (e.g. WPSafelink "Generate" wants two clicks).
                time.sleep(min(3, hop_timeout))
                if stuck >= 5:
                    ended = "loop" if looping else "stuck"
                    self._log("Giving up walk (%s). Controls: %s", ended, self._labels(adapter))
                    break

        # Walk ended without a file-host link.
        page_html = adapter.page_html() or ""
        cur = adapter.current_url()
        final = self._find_final(page_html)
        reached = bool(final)
        if not final and html_utils.is_final_link(cur):
            final, reached = cur, True
        return self._capture(adapter, page_html, final=final, cleared=cleared,
                             reached=reached, ended="final_link" if reached else ended)

    def _satisfy_image_gate(self, adapter) -> bool:
        """Handle the "click an ad image, wait, come back" gate: click an image
        (opening an ad), close the pop-up/return to the page, then wait so the
        real Get Link/Download control activates."""
        self._log("Image gate detected - clicking an ad image and returning")
        before = adapter.current_url()
        if not adapter.click_image_ad():
            self._log("No ad image found to click for the gate")
            return False
        time.sleep(2)
        adapter.close_popups()
        # If the main tab itself navigated to the ad, go back.
        if adapter.current_url() and adapter.current_url() != before:
            adapter.back()
            adapter.wait_idle()
        self._wait_countdown(adapter)
        time.sleep(3)
        return True

    def _wait_countdown(self, adapter) -> None:
        html = adapter.page_html() or ""
        secs = html_utils.find_countdown_seconds(html) or 0
        # Many safelink pages show a "please wait" with a timer we can't parse;
        # fall back to a sensible default so the real button has time to appear.
        if not secs and re.search(r"please\s*wait", html, re.IGNORECASE):
            secs = 8
        secs = min(secs, 25)
        if secs > 0:
            self._log("Waiting %ds for page countdown", secs)
            time.sleep(secs + 1)

    def _wait_for_continue(self, adapter, exclude=None, timeout=None, reveal_only=False):
        """Return the best advance control (Continue / Verify / Click to Verify
        / Get Link) as soon as one is present - clicked *instantly*, no
        countdown grace. ``choose_continue`` already prefers a reveal/get-link
        button over a plain "Continue". With *reveal_only* (the final ad page),
        a plain "Continue" is ignored so we don't loop back through more ads.
        """
        deadline = time.time() + (timeout or self.timeout)
        while time.time() < deadline:
            cand = html_utils.choose_continue(adapter.candidates(), exclude=exclude)
            if cand is not None and (not reveal_only or html_utils.is_reveal_control(cand)):
                return cand
            time.sleep(self.poll)
        return None

    @staticmethod
    def _find_final(html):
        """Prefer a validated share link; fall back to any embedded file-host
        URL (incl. previews) so a referenced Terabox/Drive link is still
        surfaced on hostile 'ad maze' pages."""
        return html_utils.find_final_link(html) or html_utils.find_any_final_link(html)

    def _scan_final(self, adapter, seconds):
        deadline = time.time() + seconds
        while time.time() < deadline:
            final = self._find_final(adapter.page_html() or "")
            if final:
                return final
            if html_utils.is_final_link(adapter.current_url()):
                return adapter.current_url()
            time.sleep(self.poll)
        return None

    def _wait_progress(self, adapter, before_url, before_len, timeout):
        """Wait for navigation / final link / Cloudflare-clear after a click.

        Returns ``(final_url_or_None, progressed_bool)``.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            cur = adapter.current_url()
            if html_utils.is_final_link(cur):
                return cur, True
            page_html = adapter.page_html() or ""
            final = self._find_final(page_html)
            if final:
                return final, True
            if cur and cur != before_url:
                if html_utils.detect_cloudflare(page_html):
                    self._wait_cleared_adapter(adapter)
                return None, True
            time.sleep(self.poll)
        # No navigation; treat a big DOM change as (weak) progress.
        page_html = adapter.page_html() or ""
        changed = abs(len(page_html) - before_len) > 400
        return None, changed

    _ERROR_PAGE_MARKERS = (
        "reload page", "try again", "isn't working", "took too long",
        "err_", "this site can", "refused to connect", "no internet",
        "aw, snap", "rate limit", "too many requests", "429", "access denied",
    )

    def _is_error_page(self, adapter) -> bool:
        html = adapter.page_html() or ""
        if len(html) >= 15000:
            return False
        low = html.lower()
        return any(m in low for m in self._ERROR_PAGE_MARKERS)

    def _labels(self, adapter):
        out = []
        for c in adapter.candidates()[:30]:
            lbl = str(c.get("text") or c.get("value") or c.get("id")
                      or c.get("cls") or "").strip()
            if lbl:
                out.append(lbl[:34])
        return out

    def _log_stub_page(self, adapter):
        """Log the title + a text snippet of a small/stub page, to reveal what
        an 'error/Reload Page' block actually is (anti-bot, custom, etc.)."""
        if not self.verbose:
            return
        html = adapter.page_html() or ""
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        title = (m.group(1).strip()[:150] if m else "")
        text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html,
                      flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()[:400]
        self._log("Stub page title=%r", title)
        self._log("Stub page text=%r", text)

    def _log_page_markers(self, adapter):
        """Diagnostic: which link-flow markers / countdown are on the page.

        Helps identify an unknown safelink button when the walk gets stuck.
        """
        if not self.verbose:
            return
        low = (adapter.page_html() or "").lower()
        markers = [
            m for m in (
                "wpsafe", "safelink", "please wait", "get link", "getlink",
                "get-link", "download", "generate", "recaptcha", "turnstile",
                "g-recaptcha", "countdown", "timer", "click here",
            )
            if m in low
        ]
        self._log(
            "Page markers: %s | countdown=%s | html=%d bytes",
            markers,
            html_utils.find_countdown_seconds(adapter.page_html() or ""),
            len(low),
        )

    # -- capture / display -------------------------------------------------
    def _capture(self, adapter, html, final=None, cleared=True, reached=False, ended="") -> SolveResult:
        return SolveResult(
            html=html or "",
            cookies=adapter.get_cookies(),
            user_agent=adapter.get_user_agent() or self.user_agent,
            final_url=final or adapter.current_url(),
            cleared=cleared,
            reached_final=reached,
            ended=ended,
        )

    def _start_virtual_display(self):
        try:
            from pyvirtualdisplay import Display  # type: ignore
        except Exception:  # noqa: BLE001
            raise BrowserSolverError(
                "xvfb requested but 'pyvirtualdisplay' is not installed. "
                "Install it and the Xvfb system package, e.g.:  "
                "pip install pyvirtualdisplay  &&  apt-get install -y xvfb"
            )
        self._log("Starting virtual display (Xvfb)")
        display = Display(visible=False, size=(1920, 1080))
        display.start()
        self.headless = False  # under Xvfb we run headed
        return display
