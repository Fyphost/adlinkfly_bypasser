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
