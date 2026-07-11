"""adlinkfly_bypasser - Resolve the destination behind adlinkfly-based short URLs.

Adlinkfly is a popular PHP URL-shortener script. Many "make money by
shortening links" sites are adlinkfly (or clones such as GPLinks, DropLink,
ShrinkMe, Shortingly, ShareUs, etc.). They wrap a destination URL behind one
or more interstitial pages with ads and a countdown timer, then reveal the
real link through a JSON endpoint (usually ``/links/go``).

This package automates that flow and returns the final destination URL.

Basic usage::

    from adlinkfly_bypasser import bypass

    final_url = bypass("https://example-shortener.com/abc123")
    print(final_url)

Advanced usage::

    from adlinkfly_bypasser import AdlinkflyBypasser

    bp = AdlinkflyBypasser(wait=None, verbose=True)
    result = bp.bypass("https://example-shortener.com/abc123")
    print(result.destination)
"""

from .browser import (
    BrowserSolver,
    BrowserSolverError,
    SolveResult,
    available_backends,
    find_browser_binary,
)
from .bypasser import AdlinkflyBypasser, BypassResult, bypass
from .exceptions import (
    AdlinkflyBypassError,
    CloudflareChallengeError,
    NetworkError,
    ParseError,
    ResolutionError,
    UnsupportedURLError,
)

__all__ = [
    "AdlinkflyBypasser",
    "BypassResult",
    "bypass",
    "BrowserSolver",
    "SolveResult",
    "BrowserSolverError",
    "available_backends",
    "find_browser_binary",
    "AdlinkflyBypassError",
    "CloudflareChallengeError",
    "NetworkError",
    "ParseError",
    "ResolutionError",
    "UnsupportedURLError",
]

__version__ = "1.10.0"
