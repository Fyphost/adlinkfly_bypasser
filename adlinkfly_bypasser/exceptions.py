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
