"""HTML parsing helpers built on the standard-library ``html.parser``.

These extract the bits an adlinkfly bypass needs - forms with their hidden
inputs, meta-refresh redirects, and JavaScript ``location`` assignments -
without requiring BeautifulSoup. If BeautifulSoup is installed it is *not*
required here; the stdlib parser is sufficient and keeps the package
dependency-free.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional


@dataclass
class Form:
    """A parsed HTML ``<form>``."""

    action: Optional[str] = None
    method: str = "get"
    id: Optional[str] = None
    inputs: Dict[str, str] = field(default_factory=dict)

    @property
    def method_upper(self) -> str:
        return (self.method or "get").upper()


class _FormParser(HTMLParser):
    """Collect all forms and their input/name-value pairs."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: List[Form] = []
        self._current: Optional[Form] = None

    def handle_starttag(self, tag, attrs):
        attrs_d = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._current = Form(
                action=attrs_d.get("action"),
                method=attrs_d.get("method", "get"),
                id=attrs_d.get("id"),
            )
        elif tag in ("input", "textarea", "button") and self._current is not None:
            name = attrs_d.get("name")
            if name:
                self._current.inputs[name] = attrs_d.get("value", "")
        # Some templates place inputs before the <form> or omit the closing
        # tag; capturing on start keeps us resilient.

    def handle_endtag(self, tag):
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None

    def close(self):
        super().close()
        # Flush a form that never received a closing tag.
        if self._current is not None:
            self.forms.append(self._current)
            self._current = None


def parse_forms(html: str) -> List[Form]:
    """Return every ``<form>`` found in *html*."""
    parser = _FormParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        # Malformed markup: return whatever we managed to collect.
        pass
    return parser.forms


_META_REFRESH_RE = re.compile(
    r"""<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["'][^"']*url=([^"'>\s]+)""",
    re.IGNORECASE,
)

_JS_LOCATION_RE = re.compile(
    r"""(?:window\.)?location(?:\.href)?\s*(?:=|\.replace\(|\.assign\()\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

# Common ways adlinkfly-style pages embed the final link in markup.
_ANCHOR_RE = re.compile(
    r"""<a[^>]+(?:id|class)=["'][^"']*(?:btn|get[-_]?link|download|continue|generate)[^"']*["'][^>]*href=["']([^"']+)["']""",
    re.IGNORECASE,
)


def find_meta_refresh(html: str) -> Optional[str]:
    m = _META_REFRESH_RE.search(html)
    return m.group(1).strip() if m else None


def find_js_redirect(html: str) -> Optional[str]:
    for m in _JS_LOCATION_RE.finditer(html):
        candidate = m.group(1).strip()
        if candidate and candidate not in ("#", "/"):
            return candidate
    return None


def find_action_anchor(html: str) -> Optional[str]:
    m = _ANCHOR_RE.search(html)
    return m.group(1).strip() if m else None


# Timers are usually rendered from a JS integer; grab the largest plausible one.
_TIMER_RES = [
    re.compile(r"var\s+(?:time|seconds|timer|counter|count)\s*=\s*(\d+)", re.IGNORECASE),
    re.compile(r"data-(?:timer|wait|seconds)=[\"'](\d+)[\"']", re.IGNORECASE),
    re.compile(r"(?:setTimeout|countdown)[^;{]*?(\d{1,3})\s*\*\s*1000", re.IGNORECASE),
]


def find_countdown_seconds(html: str) -> Optional[int]:
    """Best-effort extraction of the interstitial countdown, in seconds."""
    best: Optional[int] = None
    for regex in _TIMER_RES:
        for m in regex.finditer(html):
            try:
                value = int(m.group(1))
            except (ValueError, IndexError):
                continue
            # Ignore absurd values (milliseconds, years, random ids, ...).
            if 0 < value <= 120:
                best = value if best is None else max(best, value)
    return best


# -- Cloudflare protection detection --------------------------------------

# Markers that strongly indicate an interactive Cloudflare challenge (JS / IUAM
# / managed challenge / Turnstile) rather than the real destination page.
_CF_CHALLENGE_MARKERS = (
    "/cdn-cgi/challenge-platform",
    "window._cf_chl_opt",
    "cf_chl_opt",
    "cf-browser-verification",
    "cf-challenge-running",
    "challenges.cloudflare.com/turnstile",
    "cf-turnstile",
    "__cf_chl_",
    "turnstile",
)

# Human-readable phrases seen on Cloudflare interstitials.
_CF_CHALLENGE_PHRASES = (
    "just a moment",
    "verify you are human",
    "checking your browser before accessing",
    "enable javascript and cookies to continue",
    "needs to review the security of your connection",
)

# Markers/phrases that indicate an outright Cloudflare *block* (not solvable by
# waiting - usually IP/firewall based).
_CF_BLOCK_PHRASES = (
    "sorry, you have been blocked",
    "attention required",
    "you have been blocked",
    "error 1020",  # access denied (firewall rule)
    "access denied",
)


def detect_cloudflare(html: str, status_code: Optional[int] = None) -> Optional[str]:
    """Detect a Cloudflare protection page.

    Returns a short reason string describing what was found
    (``"managed challenge"``, ``"turnstile"``, ``"javascript challenge"``,
    ``"blocked"``), or ``None`` if the page does not look like a Cloudflare
    interstitial.

    The heuristic deliberately avoids false positives: many normal pages load
    Cloudflare *assets* (e.g. ``/cf-fonts/``, ``cdnjs``) without being a
    challenge, so those alone are not treated as a challenge.
    """
    if not html:
        # A bare 403 with no body is very likely a Cloudflare block.
        if status_code == 403:
            return "blocked"
        return None

    low = html.lower()

    # A real destination page (adlinkfly interstitial) has a form/inputs; if we
    # can already see the go-link markers, it's not a challenge.
    if ("go-link" in low) or ("/links/go" in low) or ('name="_token"' in low):
        return None

    is_challenge = any(marker.lower() in low for marker in _CF_CHALLENGE_MARKERS)
    has_phrase = any(phrase in low for phrase in _CF_CHALLENGE_PHRASES)
    is_block = any(phrase in low for phrase in _CF_BLOCK_PHRASES)

    if is_block and not is_challenge:
        return "blocked"

    if is_challenge or (has_phrase and "cloudflare" in low):
        if "turnstile" in low:
            return "turnstile"
        if "cf_chl_opt" in low or "_cf_chl_opt" in low or "__cf_chl_" in low:
            return "managed challenge"
        if "cf-browser-verification" in low or "checking your browser" in low:
            return "javascript challenge"
        return "managed challenge"

    return None



# -- Final file-host detection --------------------------------------------

# Substrings identifying a real file-host / cloud-drive destination. These are
# where adlinkfly "blog" content-lockers eventually send you (Terabox & family,
# plus the usual cloud drives / file hosts). Matching one means we've reached
# the end of the ad-page chain.
FINAL_HOST_SUBSTRINGS = (
    # Terabox and its many mirror domains
    "terabox",
    "1024tera",
    "teraboxapp",
    "teraboxlink",
    "terafileshare",
    "terasharelink",
    "freeterabox",
    "teraboxdrive",
    "nephobox",
    "4funbox",
    "mirrobox",
    "momerybox",
    "tibibox",
    "gibibox",
    # Common cloud drives / file hosts
    "mega.nz",
    "mega.co.nz",
    "mediafire.com",
    "drive.google.com",
    "docs.google.com",
    "dropbox.com",
    "gofile.io",
    "pixeldrain.com",
    "krakenfiles.com",
    "send.cm",
    "sfile.mobi",
    "anonfiles",
    "1fichier.com",
    "workers.dev",
)

_URL_RE = re.compile(r'https?://[^\s"\'<>\\)]+', re.IGNORECASE)


def _host_of(url: str) -> str:
    """Return the lowercased host of *url* (no scheme/port/path)."""
    m = re.match(r"https?://([^/:?#]+)", url, re.IGNORECASE)
    return m.group(1).lower() if m else ""


def is_final_host(url: str) -> bool:
    """True if *url*'s host looks like a final file-host / cloud drive."""
    if not url:
        return False
    host = _host_of(url)
    if not host:
        return False
    return any(sub in host for sub in FINAL_HOST_SUBSTRINGS)


def find_final_link(html: str) -> Optional[str]:
    """Find the first URL in *html* that points at a final file-host.

    Scans hrefs and any bare URLs in the markup. Returns the matching URL or
    ``None``. This lets the walker stop as soon as a Terabox/drive link is
    present in the DOM, even before the last "get link" click.
    """
    if not html:
        return None
    for m in _URL_RE.finditer(html):
        candidate = m.group(0).rstrip(".,;\"')")
        if is_final_host(candidate):
            return candidate
    return None


# -- "Continue / Get Link" button selection --------------------------------

# Text/attribute keywords, in *priority order* (earlier = preferred), that
# identify the button advancing to the next ad page or revealing the link.
CONTINUE_KEYWORDS = (
    "get link",
    "getlink",
    "get your link",
    "get download link",
    "download link",
    "generate link",
    "generatelink",
    "click here to continue",
    "continue to link",
    "continue",
    "verify",
    "i am human",
    "im human",
    "proceed",
    "go to link",
    "gotolink",
    "get-link",
    "click here",
    "unlock",
    "skip",
    "next",
)

# Words that mark an element as navigation/social/unrelated - never click it.
_CONTINUE_NEGATIVE = (
    "facebook",
    "twitter",
    "telegram",
    "whatsapp",
    "instagram",
    "youtube",
    "share",
    "comment",
    "login",
    "log in",
    "sign in",
    "signup",
    "sign up",
    "subscribe",
    "home",
    "privacy",
    "policy",
    "terms",
    "contact",
    "about",
    "disclaimer",
    "menu",
    "search",
    "advertis",
    "cookie",
)


def choose_continue(candidates):
    """Pick the best "continue / get link" control from parsed candidates.

    *candidates* is a list of dicts with any of the keys ``text``, ``value``,
    ``id``, ``cls`` (class), ``href``, ``tag`` and ``handle`` (an opaque
    driver-specific reference). Returns the chosen candidate dict, or ``None``.

    Selection is pure/testable: it scores each candidate's combined text by the
    highest-priority :data:`CONTINUE_KEYWORDS` it contains, rejects obvious
    navigation/social controls, and slightly prefers anchors/buttons.
    """
    best = None
    best_rank = len(CONTINUE_KEYWORDS)  # lower rank = higher priority
    best_tiebreak = -1

    for cand in candidates or []:
        blob = " ".join(
            str(cand.get(k, "") or "")
            for k in ("text", "value", "id", "cls", "aria")
        ).lower().strip()
        href = str(cand.get("href", "") or "")
        if not blob and not href:
            continue
        if any(neg in blob for neg in _CONTINUE_NEGATIVE):
            continue

        for rank, kw in enumerate(CONTINUE_KEYWORDS):
            if kw in blob:
                tag = str(cand.get("tag", "")).lower()
                tiebreak = 2 if tag in ("a", "button") else 1
                if rank < best_rank or (rank == best_rank and tiebreak > best_tiebreak):
                    best, best_rank, best_tiebreak = cand, rank, tiebreak
                break
    return best
