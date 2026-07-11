"""Exception hierarchy for adlinkfly_bypasser."""


class AdlinkflyBypassError(Exception):
    """Base class for every error raised by this package."""


class NetworkError(AdlinkflyBypassError):
    """Raised when an HTTP request fails at the transport level."""


class ParseError(AdlinkflyBypassError):
    """Raised when a page cannot be parsed as expected."""


class UnsupportedURLError(AdlinkflyBypassError):
    """Raised when the given input is not a usable http(s) URL."""


class ResolutionError(AdlinkflyBypassError):
    """Raised when the destination link could not be resolved.

    This typically means the site is not an adlinkfly-style shortener, has
    changed its flow, requires JavaScript we cannot execute, or is protected
    by an anti-bot layer (e.g. Cloudflare) that the current HTTP backend
    cannot get past.
    """


class CloudflareChallengeError(ResolutionError):
    """Raised when the server returns a Cloudflare protection page.

    The HTTP client received a Cloudflare challenge / "Just a moment" /
    Turnstile / block page instead of the actual adlinkfly interstitial, so
    the destination could not be resolved. This is distinct from a plain
    parsing failure: the target page was never delivered.

    Attributes
    ----------
    reason:
        A short human-readable description of what was detected (e.g.
        ``"managed challenge"``, ``"turnstile"``, ``"blocked"``).
    """

    def __init__(self, message: str, reason: str = "challenge"):
        super().__init__(message)
        self.reason = reason
