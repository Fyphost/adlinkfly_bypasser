# adlinkfly_bypasser

Resolve the real destination hidden behind **adlinkfly**-based short URLs, in Python.

Adlinkfly is a widely-used PHP URL-shortener script. Sites built on it (and its
many clones — GPLinks, DropLink, ShrinkMe, Shortingly, ShareUs, and friends)
wrap a destination link behind one or more interstitial pages with ads and a
countdown timer, then reveal the real link through a JSON endpoint (usually
`/links/go`). This library automates that flow and hands you the final URL.

- **Zero required dependencies** — works on the Python standard library alone.
- **Optional turbo mode** — install `cloudscraper` / `requests` for better
  handling of Cloudflare-protected sites.
- **Library + CLI** — call it from code or the terminal.
- **Resilient** — tries the `/links/go` JSON POST first, then generic form
  POSTs, meta-refresh, JS redirects, and action anchors; follows chained
  interstitials until it leaves the shortener's domain.

## How it works

A typical adlinkfly interstitial does this in the browser:

1. `GET` the short URL → an HTML page with a hidden `<form>` (often
   `id="go-link"`) containing fields like `_token` and `link`, plus a countdown.
2. Wait for the countdown.
3. `POST` those hidden fields to `https://<site>/links/go` with the header
   `X-Requested-With: XMLHttpRequest`.
4. Receive JSON such as `{"status": "success", "url": "https://real-destination"}`.

`adlinkfly_bypasser` reproduces exactly these steps, with fallbacks for clones
that deviate from the standard skin.

## Installation

```bash
# From source
git clone https://github.com/Fyphost/adlinkfly_bypasser.git
cd adlinkfly_bypasser
pip install .

# Recommended extras for real-world (Cloudflare-protected) sites
pip install ".[enhanced]"
```

The core package imports and runs with no third-party packages at all.

## Usage — library

```python
from adlinkfly_bypasser import bypass

# Simplest form: returns the destination URL as a string
print(bypass("https://example-shortener.com/abc123"))

# More control and structured output
from adlinkfly_bypasser import AdlinkflyBypasser

bp = AdlinkflyBypasser(
    wait=None,            # None = auto-detect countdown; 0 = skip; N = fixed seconds
    backend="auto",       # "auto" | "cloudscraper" | "requests" | "urllib"
    verbose=True,
)
result = bp.bypass("https://example-shortener.com/abc123")
print(result.destination)  # the resolved URL
print(result.method)       # how it was resolved (e.g. "links_go_post")
print(result.steps)        # number of interstitials traversed
print(result.trail)        # full redirect trail
```

### Handling errors

```python
from adlinkfly_bypasser import bypass, ResolutionError, NetworkError

try:
    print(bypass("https://example-shortener.com/abc123"))
except ResolutionError as e:
    print("Could not resolve:", e)
except NetworkError as e:
    print("Network problem:", e)
```

## Usage — CLI

```bash
# Single URL (prints just the destination)
adlinkfly-bypass https://example-shortener.com/abc123

# Multiple URLs (prints "source -> destination" per line)
adlinkfly-bypass url1 url2 url3

# Use cloudscraper and skip the countdown
adlinkfly-bypass -b cloudscraper --no-wait https://example-shortener.com/abc123

# JSON output
adlinkfly-bypass --json https://example-shortener.com/abc123

# Read links from stdin, one per line
cat links.txt | adlinkfly-bypass -
```

Key flags: `-b/--backend`, `-w/--wait SECONDS`, `--no-wait`, `-t/--timeout`,
`-u/--user-agent`, `--json`, `-v/--verbose`.

## Options reference

| Option        | Default | Meaning                                                             |
|---------------|---------|---------------------------------------------------------------------|
| `wait`        | `None`  | `None` auto-detects the countdown (capped); `0` skips; `N` waits N s |
| `backend`     | `auto`  | Force `cloudscraper`, `requests`, or `urllib`                       |
| `timeout`     | `20`    | Per-request timeout (seconds)                                       |
| `user_agent`  | Chrome  | Override the browser User-Agent                                    |

## Notes & limitations

- Sites that require a real JavaScript engine, solving a CAPTCHA, or an
  interactive challenge cannot be resolved by a pure HTTP client. For heavy
  Cloudflare protection, install the `enhanced` extras.
- Shortener sites change their markup often; the fallback strategies aim to
  keep things working, but a specific site may still need tweaks.
- Respect each site's Terms of Service and applicable law. This tool is provided
  for interoperability, research, and personal convenience. You are responsible
  for how you use it.

## License

MIT
