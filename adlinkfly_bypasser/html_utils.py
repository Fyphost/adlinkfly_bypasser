"""HTML parsing helpers built on the standard-library ``html.parser``.

These extract the bits an adlinkfly bypass needs - forms with their hidden
inputs, meta-refresh redirects, and JavaScript ``location`` assignments -
without requiring BeautifulSoup. If BeautifulSoup is installed it is *not*
required here; the stdlib parser is sufficient and keeps the package
dependency-free.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from html import unescape as _html_unescape
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


def references_final_host(html: str) -> bool:
    """True if the page mentions a final file-host *anywhere* (incl. thumbnail
    previews / og:image). A useful signal that we've reached the last ad page,
    where the real share link is about to be revealed."""
    if not html:
        return False
    low = _html_unescape(html).lower()
    return any(sub in low for sub in FINAL_HOST_SUBSTRINGS)


# URL fragments that mark a match as an *asset* (thumbnail / preview / static),
# not the shareable file link. e.g. Terabox previews live on dm-data.*.
_ASSET_URL_MARKERS = (
    "/thumbnail",
    "/thumb/",
    "sharethumbnail",
    "dm-data.",
    "data.1024tera",
    "/preview",
    "/icon",
    "/avatar",
)
_ASSET_URL_EXTS = (
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".gif",
    ".svg",
    ".ico",
    ".bmp",
    ".avif",
    ".css",
    ".js",
    ".mp4",
    ".woff",
    ".woff2",
    ".ttf",
)
# Path/query fragments that mark a URL as a genuine *share* link (preferred).
_SHARE_URL_MARKERS = ("/s/", "/sharing/", "surl=", "/web/share", "/wap/share")


def _is_asset_url(url: str) -> bool:
    """True if *url* is a static asset / thumbnail rather than a share link."""
    low = url.lower()
    path = low.split("?", 1)[0].split("#", 1)[0]
    if any(path.endswith(ext) for ext in _ASSET_URL_EXTS):
        return True
    return any(marker in low for marker in _ASSET_URL_MARKERS)


# Terabox-family hosts and the markers that make a Terabox URL a real *share*
# link (as opposed to the homepage or a preview asset).
_TERABOX_SUBSTRINGS = (
    "terabox", "1024tera", "teraboxapp", "teraboxlink", "terafileshare",
    "terasharelink", "freeterabox", "teraboxdrive", "nephobox", "4funbox",
    "mirrobox", "momerybox", "tibibox", "gibibox",
)
_TERABOX_SHARE_MARKERS = ("/s/", "surl=", "/sharing")
# Google Drive/Docs URLs are only real files when they carry a file/folder id;
# the bare viewer app (drive.google.com/viewer…) is not a destination.
_GOOGLE_ID_MARKERS = (
    "/file/d/", "/folders/", "/document/d/", "/spreadsheets/d/",
    "/presentation/d/", "/forms/d/", "open?id=", "/uc?", "id=",
)


def _valid_final_url(url: str) -> bool:
    """Host-specific validation that a file-host URL is a *real* destination
    (not a homepage, viewer app, or embedded widget)."""
    low = url.lower()
    host = _host_of(low)
    if "google.com" in host or "google." in host:
        if "/viewer" in low:  # drive.google.com/viewer(ng) app - not a file
            return False
        return any(m in low for m in _GOOGLE_ID_MARKERS)
    if any(t in host for t in _TERABOX_SUBSTRINGS):
        return any(m in low for m in _TERABOX_SHARE_MARKERS)
    return True


def is_final_link(url: str) -> bool:
    """True if *url* is a genuine final destination link (file-host, valid,
    and not a thumbnail/preview/viewer asset)."""
    if not url or not is_final_host(url) or _is_asset_url(url):
        return False
    return _valid_final_url(url)


def find_final_link(html: str) -> Optional[str]:
    """Find the best URL in *html* that points at a real final destination.

    - HTML entities are decoded (so ``&amp;`` becomes ``&``).
    - Thumbnail / preview / static-asset URLs are rejected (a Terabox preview
      image on ``dm-data.1024tera.com`` is not the shareable link).
    - Host-specific validation rejects non-file URLs such as the Google Drive
      viewer app (``drive.google.com/viewer/main``) or a bare Terabox homepage.
    - A genuine *share* link (``/s/``, ``/sharing/``, ``surl=`` …) is preferred.

    Returns the chosen URL or ``None``.
    """
    if not html:
        return None
    text = _html_unescape(html)
    matches: List[str] = []
    for m in _URL_RE.finditer(text):
        candidate = m.group(0).rstrip(".,;\"')")
        if not is_final_link(candidate):
            continue
        if candidate not in matches:
            matches.append(candidate)
    if not matches:
        return None
    for url in matches:  # prefer canonical share links
        if any(marker in url.lower() for marker in _SHARE_URL_MARKERS):
            return url
    return matches[0]


# -- "Continue / Get Link" button selection --------------------------------

# Text/attribute keywords, in *priority order* (earlier = preferred), that
# identify the button advancing to the next ad page or revealing the link.
CONTINUE_KEYWORDS = (
    # --- human verification FIRST: on safelink flows this must be clicked
    #     before the "generate" button becomes functional. ---
    "human verification",
    "verify you are human",
    "i am human",
    "im human",
    "wpsafelinkhuman",
    "human",
    "verification",
    "verify",
    # --- then link reveal / generate / download (the actual link controls) ---
    "get link",
    "getlink",
    "get-link",
    "get your link",
    "get download link",
    "download link",
    "download now",
    "your link is ready",
    "generate link",
    "generatelink",
    "create link",
    "generate",
    "continue to link",
    "click here to continue",
    # --- generic advance (lower priority; after the "reveal" boundary) ---
    "continue",
    "proceed",
    "go to link",
    "gotolink",
    "click here",
    "unlock",
    "download",
    "skip ad",
    "skip this ad",
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
    "skip to content",
    "skip to main",
    "skip navigation",
    "scroll",
    "read more",
    "related",
    "recent post",
    "leave a comment",
    "reply",
    "back to top",
    "toggle",
    # instruction labels (not the button): "click image & wait & come back..."
    "click image",
    "click on any",
    "click any image",
    "come back this page",
    "then back",
    "then come back",
    "wait & come",
    "learn more",
)


# Rank boundary: keywords before "continue" are "reveal" buttons (the actual
# get-link / download control), which the walker should prefer and treat as
# terminal-ish. Computed once.
_REVEAL_RANK_CUTOFF = CONTINUE_KEYWORDS.index("continue")


def _normalize(text: str) -> str:
    """Lowercase + NFKC-normalize so 'stylish' unicode button text (e.g.
    mathematical-bold '𝗚𝗲𝘁 𝗟𝗶𝗻𝗸') matches plain keywords."""
    return unicodedata.normalize("NFKC", str(text or "")).lower().strip()


def candidate_signature(cand) -> str:
    """A stable identity for a control, used to avoid clicking it twice."""
    return "|".join(
        str(cand.get(k, "") or "") for k in ("text", "id", "href", "value")
    ).strip().lower()[:200]


# href path fragments that mark a link as WordPress navigation/archive (author
# byline, category/tag/date archives, feeds, login) - never the advance button.
_BAD_HREF_MARKERS = (
    "/author/",
    "/category/",
    "/tag/",
    "/page/",
    "/feed",
    "/wp-login",
    "/wp-admin",
    "/cdn-cgi/",
    "/privacy",
    "/disclaimer",
    "/dmca",
    "/contact",
    "/about",
    "/terms",
)


def continue_rank(cand) -> Optional[int]:
    """Priority rank of a control (lower = better), or ``None`` if it's not a
    continue/get-link control (or is navigation/social/archive)."""
    href = str(cand.get("href", "") or "").lower()
    if href and any(marker in href for marker in _BAD_HREF_MARKERS):
        return None  # WordPress author/category/etc. link - not an advance button
    blob = _normalize(
        " ".join(str(cand.get(k, "") or "") for k in ("text", "value", "id", "cls", "aria"))
    )
    if not blob and not href:
        return None
    if any(neg in blob for neg in _CONTINUE_NEGATIVE):
        return None
    for rank, kw in enumerate(CONTINUE_KEYWORDS):
        if kw in blob:
            return rank
    return None


# Phrases (after NFKC-normalisation) that mark the "click an ad image, wait,
# then come back to get the link" anti-bot gate used by these blog lockers.
_IMAGE_GATE_PHRASES = (
    "click image",
    "click on any",
    "click any image",
    "click on image",
    "click the image",
    "come back this page",
    "back this page to get",
    "wait & come back",
    "wait and come back",
    "then come back",
    "click & wait",
    "click and wait",
)


def is_image_gate(html: str) -> bool:
    """Detect the "click an image / wait / come back to get link" ad gate."""
    if not html:
        return False
    norm = _normalize(html)
    return any(phrase in norm for phrase in _IMAGE_GATE_PHRASES)


def is_reveal_control(cand) -> bool:
    """True if the control looks like the actual get-link/download button."""
    rank = continue_rank(cand)
    return rank is not None and rank < _REVEAL_RANK_CUTOFF


def choose_continue(candidates, exclude=None):
    """Pick the best "continue / get link" control from parsed candidates.

    *candidates* is a list of dicts with any of the keys ``text``, ``value``,
    ``id``, ``cls`` (class), ``href``, ``tag`` and ``handle`` (an opaque
    driver-specific reference). *exclude* is an optional set of
    :func:`candidate_signature` values to skip (controls already clicked).
    Returns the chosen candidate dict, or ``None``.
    """
    exclude = exclude or set()
    best = None
    best_rank = len(CONTINUE_KEYWORDS)  # lower rank = higher priority
    best_tiebreak = -1

    for cand in candidates or []:
        if candidate_signature(cand) in exclude:
            continue
        rank = continue_rank(cand)
        if rank is None:
            continue
        tag = str(cand.get("tag", "")).lower()
        tiebreak = 2 if tag in ("a", "button") else 1
        if rank < best_rank or (rank == best_rank and tiebreak > best_tiebreak):
            best, best_rank, best_tiebreak = cand, rank, tiebreak
    return best
