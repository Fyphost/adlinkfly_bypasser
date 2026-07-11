"""Command-line interface for adlinkfly_bypasser.

Examples
--------
Resolve a single link::

    adlinkfly-bypass https://example-shortener.com/abc123

Resolve several, using cloudscraper and skipping the countdown::

    adlinkfly-bypass -b cloudscraper --no-wait url1 url2 url3

Read links from stdin (one per line)::

    cat links.txt | adlinkfly-bypass -
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import List

from . import __version__
from .bypasser import AdlinkflyBypasser
from .exceptions import AdlinkflyBypassError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adlinkfly-bypass",
        description="Resolve the destination behind adlinkfly-based short URLs.",
    )
    parser.add_argument(
        "urls",
        nargs="+",
        metavar="URL",
        help="One or more short URLs to resolve. Use '-' to read from stdin.",
    )
    parser.add_argument(
        "-b",
        "--backend",
        choices=("auto", "cloudscraper", "requests", "urllib"),
        default="auto",
        help="HTTP backend to use (default: auto).",
    )
    wait_group = parser.add_mutually_exclusive_group()
    wait_group.add_argument(
        "-w",
        "--wait",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Fixed seconds to wait on each interstitial (default: auto-detect).",
    )
    wait_group.add_argument(
        "--no-wait",
        action="store_true",
        help="Skip the interstitial countdown entirely (fastest).",
    )
    parser.add_argument(
        "-s",
        "--solver",
        default="none",
        metavar="SOLVER",
        help="Cloudflare solver: 'none' (default), 'browser'/'auto' (use the "
        "first installed browser driver), or a specific driver name "
        "(drissionpage|seleniumbase|undetected|playwright). Requires the "
        "corresponding package, e.g. pip install DrissionPage.",
    )
    parser.add_argument(
        "--headful",
        action="store_true",
        help="Run the browser solver with a visible window (more likely to "
        "clear Cloudflare than headless).",
    )
    parser.add_argument(
        "--browser-path",
        default=None,
        metavar="PATH",
        help="Path to a Chrome/Chromium binary for the browser solver. "
        "Auto-detected if omitted (checks PATH, common locations, and "
        "Playwright's downloaded browsers).",
    )
    parser.add_argument(
        "--xvfb",
        action="store_true",
        help="Run the browser solver headed under a virtual display (Xvfb) - "
        "best for display-less Linux servers. Needs pyvirtualdisplay + the "
        "Xvfb system package (SeleniumBase handles it natively).",
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=20, help="Per-request timeout in seconds."
    )
    parser.add_argument(
        "-u", "--user-agent", default=None, help="Override the User-Agent string."
    )
    parser.add_argument(
        "-c",
        "--cookie",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Add a cookie (repeatable). Use this to pass a browser-obtained "
        "'cf_clearance' cookie to get past Cloudflare; also pass the same "
        "--user-agent the browser used.",
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="NAME:VALUE",
        help="Add a default request header (repeatable).",
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit JSON results instead of plain URLs."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show progress on stderr."
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def _parse_pairs(items: List[str], sep: str, label: str) -> dict:
    """Parse repeated ``NAME<sep>VALUE`` CLI args into a dict."""
    out: dict = {}
    for item in items:
        if sep not in item:
            raise SystemExit(f"Invalid {label} (expected NAME{sep}VALUE): {item!r}")
        name, value = item.split(sep, 1)
        out[name.strip()] = value.strip()
    return out


def _collect_urls(raw: List[str]) -> List[str]:
    urls: List[str] = []
    for item in raw:
        if item == "-":
            urls.extend(line.strip() for line in sys.stdin if line.strip())
        else:
            urls.append(item)
    return urls


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)

    if args.verbose:
        logging.basicConfig(
            level=logging.INFO, format="[%(levelname)s] %(message)s", stream=sys.stderr
        )

    wait = 0.0 if args.no_wait else args.wait
    cookies = _parse_pairs(args.cookie, sep="=", label="cookie")
    headers = _parse_pairs(args.header, sep=":", label="header")
    bypasser = AdlinkflyBypasser(
        wait=wait,
        timeout=args.timeout,
        user_agent=args.user_agent,
        backend=args.backend,
        cookies=cookies or None,
        headers=headers or None,
        solver=args.solver,
        headless=not args.headful,
        browser_path=args.browser_path,
        xvfb=args.xvfb,
        verbose=args.verbose,
    )

    urls = _collect_urls(args.urls)
    exit_code = 0
    results = []

    for url in urls:
        try:
            result = bypasser.bypass(url)
            results.append(
                {
                    "source": result.source,
                    "destination": result.destination,
                    "method": result.method,
                    "steps": result.steps,
                    "ok": True,
                }
            )
            if not args.json:
                if len(urls) > 1:
                    print(f"{url} -> {result.destination}")
                else:
                    print(result.destination)
        except AdlinkflyBypassError as exc:
            exit_code = 1
            results.append(
                {"source": url, "error": str(exc), "ok": False}
            )
            if not args.json:
                print(f"[error] {url}: {exc}", file=sys.stderr)

    if args.json:
        import json

        print(json.dumps(results, indent=2))

    return exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
