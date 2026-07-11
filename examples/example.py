"""Minimal usage examples for adlinkfly_bypasser.

Run:  python examples/example.py <short_url>
"""

import sys

from adlinkfly_bypasser import AdlinkflyBypasser, bypass
from adlinkfly_bypasser.exceptions import AdlinkflyBypassError


def main():
    if len(sys.argv) < 2:
        print("Usage: python examples/example.py <short_url>")
        return 1

    url = sys.argv[1]

    # 1) One-liner
    try:
        print("Destination:", bypass(url, verbose=True))
    except AdlinkflyBypassError as exc:
        print("Failed (simple):", exc)

    # 2) Structured result
    bp = AdlinkflyBypasser(wait=None, backend="auto", verbose=True)
    try:
        result = bp.bypass(url)
        print("\n--- details ---")
        print("source     :", result.source)
        print("destination:", result.destination)
        print("method     :", result.method)
        print("steps      :", result.steps)
        print("trail      :", " -> ".join(result.trail))
    except AdlinkflyBypassError as exc:
        print("Failed (detailed):", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
