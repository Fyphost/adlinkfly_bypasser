"""Optional real-browser solver for Cloudflare-protected shorteners.

Cloudflare **managed challenges** and **Turnstile** cannot be cleared by a
pure HTTP client (requests / cloudscraper) - they require a JavaScript engine
and browser fingerprint. This module drives a real Chromium browser to load the
page, waits for Cloudflare to clear, and returns the rendered HTML, the cookies
it set (crucially ``cf_clearance``) and the browser's User-Agent. Those are then
reused by the normal HTTP pipeline so the rest of the adlinkfly flow (the
``/links/go`` POST) works over plain HTTP.

Supported drivers, in auto-selection order (first installed one wins):

1. ``DrissionPage`` - CDP-based, currently the most reliable against Cloudflare.
2. ``seleniumbase`` - UC (undetected) mode with CAPTCHA-click helpers.
3. ``undetected_chromedriver`` - patched Selenium Chromedriver.
4. ``playwright`` - last resort (vanilla Playwright is often detected).

Install one, e.g.::

    pip install DrissionPage
    # or
    pip install seleniumbase
    # or
    pip install undetected-chromedriver selenium
    # or
    pip install playwright && playwright install chromium

None of these are imported unless a solver is actually used, so the base
package stays dependency-free.
"""

from __future__ import annotations

import glob
import importlib.util
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import html_utils
from .exceptions import AdlinkflyBypassError

logger = logging.getLogger("adlinkfly_bypasser.browser")

# Auto-selection order.
_BACKENDS = ("drissionpage", "seleniumbase", "undetected", "playwright")

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
    # Playwright-managed full Chromium (headed-capable).
    "~/.cache/ms-playwright/chromium-*/chrome-linux/chrome",
    "~/.cache/ms-playwright/chromium-*/chrome-mac/Chromium.app/Contents/MacOS/Chromium",
    # Playwright headless-shell (headless only) - last resort.
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
    """What a browser solve produced once Cloudflare was (hopefully) cleared."""

    html: str
    cookies: Dict[str, str] = field(default_factory=dict)
    user_agent: Optional[str] = None
    final_url: Optional[str] = None
    cleared: bool = True


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


class BrowserSolver:
    """Drive a real browser to clear a Cloudflare challenge.

    Parameters
    ----------
    backend:
        ``"auto"`` (default) picks the first installed driver, or force one of
        ``"drissionpage"``, ``"seleniumbase"``, ``"undetected"``, ``"playwright"``.
    headless:
        Run without a visible window. Note: headless is more likely to be
        detected by Cloudflare; if solving fails, retry with ``headless=False``.
    timeout:
        Max seconds to wait for the challenge to clear.
    poll:
        Seconds between challenge-cleared checks.
    settle:
        Extra seconds to wait after the challenge clears (lets cookies/redirects
        settle) before capturing the page.
    user_agent:
        Optional User-Agent override for the browser.
    browser_path:
        Path to a Chrome/Chromium binary. If omitted, common locations (and
        Playwright's downloaded browsers) are auto-detected.
    xvfb:
        On a display-less Linux server, run the browser under a virtual
        display (Xvfb) so it can run *headed* - which clears Cloudflare far
        more reliably than headless. Requires ``pyvirtualdisplay`` + the
        ``Xvfb`` system package (SeleniumBase has native support).
    verbose:
        Log progress at INFO level.
    """

    def __init__(
        self,
        backend: str = "auto",
        headless: bool = True,
        timeout: int = 60,
        poll: float = 2.0,
        settle: float = 3.0,
        user_agent: Optional[str] = None,
        browser_path: Optional[str] = None,
        xvfb: bool = False,
        verbose: bool = False,
    ):
        self.headless = headless
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
        """Load *url* in a browser and return the cleared page + credentials."""
        self._log("Browser solver (%s) opening %s", self.backend, url)
        # SeleniumBase manages Xvfb itself; for the others we start one here.
        display = None
        if self.xvfb and self.backend != "seleniumbase":
            display = self._start_virtual_display()
        try:
            return getattr(self, f"_solve_{self.backend}")(url)
        finally:
            if display is not None:
                try:
                    display.stop()
                except Exception:  # noqa: BLE001
                    pass

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
        # Running under Xvfb means we can (and should) run headed.
        self.headless = False
        return display

    # -- shared wait loop --------------------------------------------------
    def _wait_cleared(self, get_html):
        """Poll ``get_html()`` until Cloudflare is gone or timeout elapses.

        Returns ``(html, cleared)``.
        """
        deadline = time.time() + self.timeout
        html = ""
        while time.time() < deadline:
            try:
                html = get_html() or ""
            except Exception:  # noqa: BLE001 - page may be mid-navigation
                html = ""
            if html and html_utils.detect_cloudflare(html) is None:
                self._log("Cloudflare cleared")
                if self.settle:
                    time.sleep(self.settle)
                try:
                    html = get_html() or html
                except Exception:  # noqa: BLE001
                    pass
                return html, True
            time.sleep(self.poll)
        self._log("Timed out waiting for Cloudflare to clear")
        return html, html_utils.detect_cloudflare(html) is None

    # -- DrissionPage ------------------------------------------------------
    def _solve_drissionpage(self, url: str) -> SolveResult:
        from DrissionPage import ChromiumOptions, ChromiumPage  # type: ignore

        co = ChromiumOptions()
        if self.browser_path:
            try:
                co.set_browser_path(self.browser_path)
            except Exception:  # noqa: BLE001
                pass
        if self.headless:
            co.headless()
        if self.user_agent:
            co.set_user_agent(self.user_agent)
        for arg in ("--no-sandbox", "--disable-dev-shm-usage"):
            try:
                co.set_argument(arg)
            except Exception:  # noqa: BLE001
                pass

        page = ChromiumPage(co)
        try:
            page.get(url)
            html, cleared = self._wait_cleared(lambda: page.html)
            cookies = self._cookies_drission(page)
            ua = self.user_agent
            try:
                ua = page.user_agent  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                try:
                    ua = page.run_js("return navigator.userAgent")
                except Exception:  # noqa: BLE001
                    pass
            final = getattr(page, "url", url)
            return SolveResult(html, cookies, ua, final, cleared)
        finally:
            try:
                page.quit()
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def _cookies_drission(page) -> Dict[str, str]:
        try:
            ck = page.cookies(as_dict=True)
            if isinstance(ck, dict):
                return {str(k): str(v) for k, v in ck.items()}
        except Exception:  # noqa: BLE001
            pass
        out: Dict[str, str] = {}
        try:
            for c in page.cookies():
                if isinstance(c, dict) and "name" in c:
                    out[c["name"]] = c.get("value", "")
        except Exception:  # noqa: BLE001
            pass
        return out

    # -- SeleniumBase (UC mode) -------------------------------------------
    def _solve_seleniumbase(self, url: str) -> SolveResult:
        from seleniumbase import Driver  # type: ignore

        driver_kwargs = {"uc": True, "headless": self.headless, "agent": self.user_agent}
        if self.xvfb:
            driver_kwargs["xvfb"] = True
            driver_kwargs["headless"] = False  # headed under Xvfb
        if self.browser_path:
            driver_kwargs["binary_location"] = self.browser_path
        driver = Driver(**driver_kwargs)
        try:
            # uc_open_with_reconnect helps get past the initial challenge.
            try:
                driver.uc_open_with_reconnect(url, reconnect_time=4)
            except Exception:  # noqa: BLE001
                driver.get(url)
            # Best-effort Turnstile checkbox click.
            for attempt in ("uc_gui_click_captcha", "uc_gui_handle_captcha"):
                try:
                    getattr(driver, attempt)()
                    break
                except Exception:  # noqa: BLE001
                    continue
            html, cleared = self._wait_cleared(lambda: driver.get_page_source())
            cookies = {
                c["name"]: c.get("value", "") for c in driver.get_cookies()
            }
            ua = driver.execute_script("return navigator.userAgent")
            final = driver.get_current_url()
            return SolveResult(html, cookies, ua, final, cleared)
        finally:
            try:
                driver.quit()
            except Exception:  # noqa: BLE001
                pass

    # -- undetected-chromedriver ------------------------------------------
    def _solve_undetected(self, url: str) -> SolveResult:
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
        driver = uc.Chrome(**uc_kwargs)
        try:
            driver.get(url)
            html, cleared = self._wait_cleared(lambda: driver.page_source)
            cookies = {
                c["name"]: c.get("value", "") for c in driver.get_cookies()
            }
            ua = driver.execute_script("return navigator.userAgent")
            final = driver.current_url
            return SolveResult(html, cookies, ua, final, cleared)
        finally:
            try:
                driver.quit()
            except Exception:  # noqa: BLE001
                pass

    # -- Playwright (last resort) -----------------------------------------
    def _solve_playwright(self, url: str) -> SolveResult:
        from playwright.sync_api import sync_playwright  # type: ignore

        with sync_playwright() as p:
            launch_kwargs = {"headless": self.headless}
            if self.browser_path:
                launch_kwargs["executable_path"] = self.browser_path
            browser = p.chromium.launch(**launch_kwargs)
            ctx_kwargs = {}
            if self.user_agent:
                ctx_kwargs["user_agent"] = self.user_agent
            context = browser.new_context(**ctx_kwargs)
            page = context.new_page()
            try:
                page.goto(url, wait_until="domcontentloaded")
                html, cleared = self._wait_cleared(lambda: page.content())
                cookies = {c["name"]: c["value"] for c in context.cookies()}
                try:
                    ua = page.evaluate("navigator.userAgent")
                except Exception:  # noqa: BLE001
                    ua = self.user_agent
                final = page.url
                return SolveResult(html, cookies, ua, final, cleared)
            finally:
                try:
                    browser.close()
                except Exception:  # noqa: BLE001
                    pass
