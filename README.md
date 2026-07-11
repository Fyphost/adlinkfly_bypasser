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
`-u/--user-agent`, `-c/--cookie NAME=VALUE`, `-H/--header NAME:VALUE`,
`--json`, `-v/--verbose`.

## Cloudflare-protected shorteners

Some shorteners (e.g. sites fronted by a Cloudflare **managed challenge** or
**Turnstile**) never serve the adlinkfly page to a plain HTTP client — they
return a challenge/"Just a moment" page first. `adlinkfly_bypasser` detects
this and raises a precise `CloudflareChallengeError` instead of a vague
"could not find a destination" message:

```
Cloudflare turnstile detected. The server returned a Cloudflare challenge
page instead of an adlinkfly page, so the destination URL could not be
resolved. ...
```

`cloudscraper` can clear the older JavaScript ("I'm Under Attack") challenge,
but it does **not** solve interactive Turnstile / managed challenges. You have
two ways to get past those:

### Option A — automatic browser solver (recommended)

Install a real-browser driver and let the tool clear the challenge for you. It
drives Chromium, waits for Cloudflare to pass, grabs the `cf_clearance` cookie +
User-Agent, and then finishes the adlinkfly flow over plain HTTP automatically.

```bash
pip install DrissionPage          # recommended driver (also: seleniumbase,
                                  # undetected-chromedriver, playwright)
```

```bash
# CLI
adlinkfly-bypass --solver browser https://some-cf-protected-shortener/abc123

# If headless gets detected, use a visible window:
adlinkfly-bypass --solver browser --headful https://some-cf-protected-shortener/abc123
```

```python
from adlinkfly_bypasser import AdlinkflyBypasser

bp = AdlinkflyBypasser(solver="browser", headless=False, verbose=True)
print(bp.bypass("https://some-cf-protected-shortener/abc123").destination)
```

Supported drivers (auto-detected; force one with `--solver drissionpage|seleniumbase|undetected|playwright`):

| Driver | Install | Notes |
|--------|---------|-------|
| DrissionPage | `pip install DrissionPage` | CDP-based, most reliable vs Cloudflare |
| SeleniumBase (UC) | `pip install seleniumbase` | UC mode + CAPTCHA-click helpers |
| undetected-chromedriver | `pip install undetected-chromedriver selenium` | patched Chromedriver |
| Playwright | `pip install playwright && playwright install chromium` | last resort |

Requires a Chrome/Chromium install on the machine. Headless is easier to detect —
if a site won't clear, run `--headful`.

#### Browser binary

The solver auto-detects a Chrome/Chromium binary (checks `$CHROME_BIN`, `PATH`,
common install locations, and Playwright's downloaded browsers). If it can't
find one you'll see an error like *"Cannot find the browser executable path"* —
fix it by installing a browser or pointing at one explicitly:

```bash
# Debian/Ubuntu
apt-get install -y chromium            # or: google-chrome-stable
# Fedora/RHEL
dnf install -y chromium

# ...or point the tool at any Chromium binary:
adlinkfly-bypass --solver browser --browser-path /usr/bin/chromium https://.../abc123
export CHROME_BIN=/usr/bin/chromium    # alternatively, via env var
```

#### Headless servers (no display) — use Xvfb

On a server with no display, a **headed** browser under a virtual display beats
Cloudflare far more reliably than headless. Use `--xvfb`:

```bash
pip install pyvirtualdisplay
apt-get install -y xvfb                 # system package
adlinkfly-bypass --solver browser --xvfb https://.../abc123
```

SeleniumBase has native Xvfb support; for the other drivers the tool starts the
virtual display via `pyvirtualdisplay`. Tip: SeleniumBase UC mode + `--xvfb` is
one of the most reliable combinations on servers:

```bash
pip install seleniumbase
adlinkfly-bypass --solver seleniumbase --xvfb https://.../abc123
```

#### Multi-page "blog" ad flows (walking to the final file link)

Many adlinkfly links don't point straight at the destination — they bounce you
through 2–4 ad/blog pages, each with a countdown and a **"Continue / Get Link"**
button, before finally revealing a file-host link (e.g. **Terabox**, Google
Drive, MediaFire). The browser solver **walks that chain automatically**: on
each page it clears any Cloudflare, waits for the "continue" control to become
clickable, clicks it, and repeats until it reaches a recognised file-host link.

This is on by default when using the browser solver:

```bash
adlinkfly-bypass --solver browser --xvfb -v https://vplink.in/p1B2
# -> https://www.terabox.com/s/....   (the real destination)
```

Controls:

- `--no-follow` — stop after clearing Cloudflare on the first page (don't walk).
- `--max-hops N` — cap how many ad pages to click through (default 6).
- Recognised final hosts include the Terabox family (terabox, 1024terabox,
  teraboxapp, terafileshare, nephobox, 4funbox, …) plus Google Drive, MediaFire,
  Mega, Dropbox, GoFile, Pixeldrain and more.
- The tool returns the canonical **share** link (e.g. `terabox.com/s/…`). It
  skips thumbnail/preview/static-asset URLs (such as `dm-data.1024tera.com/thumbnail/…`)
  and decodes HTML entities, so you get a clean, usable link.

Run with `-v` to see each hop (URL, the button it clicked, and where it landed).
If a specific site uses an unusual button label, tell me the verbose log and the
keyword list can be extended.

On the **last** ad page (detected because it references a file host, e.g. a
Terabox preview), the walker refuses to click a plain "Continue" (which just
loops through more ads) and instead waits for the real *Get Link* control /
share link to appear. If the walk gets stuck, loops, or hits `--max-hops`
without reaching a file-host link, the tool raises a clear error **instead of
returning an ad page** as if it were the destination.

### Sites without Cloudflare that still need a browser

Some shorteners are JavaScript-only or multi-page but have no Cloudflare. When
plain-HTTP resolution finds no link and `--solver` is set, the tool
automatically falls back to the browser solver (and walks the flow) for those
sites too — you don't need Cloudflare to be present.

The walker understands common plugin flows, including **WPSafelink /
Shortxlinks** (Human-Verification → Generate Link → Download Link). It clicks
the human-verification control, handles buttons that need **more than one
click**, normalizes stylish-unicode button text (e.g. `𝗚𝗲𝘁 𝗟𝗶𝗻𝗸`), skips
WordPress nav/author/instruction links, and closes ad pop-up tabs (while
following a new tab if it holds the real link).

### "Click an image, wait, come back" ad gates

Some lockers gate the link behind *"click an image, wait, then come back to get
the link"*. The solver detects this and makes a best-effort attempt (click an ad
image, close the pop-up, wait out the timer, then take the revealed link). These
gates are deliberately anti-automation, so success isn't guaranteed — if it
can't get through, run **`--headful`** (a visible browser, no `--xvfb`) and
complete that single image-click by hand; the tool will carry on from there.

### Option B — manual cookie escape hatch

Solve the challenge once in a real browser, copy the `cf_clearance` cookie *and
the exact User-Agent* your browser used, and hand both to the bypasser.

```python
from adlinkfly_bypasser import AdlinkflyBypasser

bp = AdlinkflyBypasser(
    backend="cloudscraper",
    user_agent="Mozilla/5.0 ...",          # MUST match the browser that solved it
    cookies={"cf_clearance": "<value-from-browser>"},
)
print(bp.bypass("https://some-cf-protected-shortener/abc123").destination)
```

```bash
adlinkfly-bypass -b cloudscraper \
  -u "Mozilla/5.0 ..." \
  -c "cf_clearance=<value-from-browser>" \
  https://some-cf-protected-shortener/abc123
```

> `cf_clearance` is bound to your IP **and** User-Agent, and it expires. If it
> stops working, solve the challenge again and refresh the cookie. Fully
> automating Turnstile requires a real browser engine (e.g. Playwright /
> undetected-chromedriver), which is out of scope for this HTTP-based tool.

Catch it specifically if you want to branch on it:

```python
from adlinkfly_bypasser import bypass, CloudflareChallengeError

try:
    print(bypass("https://some-cf-protected-shortener/abc123"))
except CloudflareChallengeError as e:
    print("Blocked by Cloudflare:", e.reason)   # e.g. "turnstile", "blocked"
```

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
  Cloudflare protection, install the `enhanced` extras and/or use the
  `cf_clearance` cookie escape hatch described above.
- Shortener sites change their markup often; the fallback strategies aim to
  keep things working, but a specific site may still need tweaks.
- Respect each site's Terms of Service and applicable law. This tool is provided
  for interoperability, research, and personal convenience. You are responsible
  for how you use it.

## License

MIT
