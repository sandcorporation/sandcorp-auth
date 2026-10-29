"""Rules shared by every way a client gets registered (CIMD, DCR, admin)."""

from typing import Final
from urllib.parse import SplitResult, urlsplit

ALLOWED_GRANT_TYPES: Final = ("authorization_code", "refresh_token")
# `urlsplit().hostname` strips the brackets of an IPv6 literal: `[::1]` comes back as `::1`.
LOOPBACK_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "::1"})


def valid_redirect_uri(uri: object) -> bool:
    """https with a host, or http on localhost/127.0.0.1/[::1] (any port). No fragment."""
    if not isinstance(uri, str) or not uri:
        return False
    try:
        parts = urlsplit(uri)
        parts.port  # noqa: B018  # raises ValueError on a malformed port
    except ValueError:
        return False
    if parts.fragment or not parts.hostname:
        return False
    if parts.scheme == "https":
        return True
    return parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS


def redirect_uri_matches(requested: str, registered: str) -> bool:
    """Whether a `redirect_uri` sent to /authorize matches one the client registered.

    Exact string match, except when both are loopback http (RFC 8252 §7.3): native apps pick
    a free port per login, so the port is ignored there and scheme, host, path and query must
    still be identical. `localhost`, `127.0.0.1` and `[::1]` are different hosts, compared as
    written. The token endpoint is stricter: it wants the exact URI of the authorize request,
    which the authorization code keeps (authlib compares them)."""
    if requested == registered:
        return True
    want, got = _loopback_parts(registered), _loopback_parts(requested)
    if want is None or got is None:
        return False
    return (_host_as_written(got), got.path, got.query) == (
        _host_as_written(want),
        want.path,
        want.query,
    )


def _loopback_parts(uri: str) -> SplitResult | None:
    """The parts of a loopback http URI (lowercase scheme, no user info, no fragment — not
    even an empty `#`), else None."""
    if not uri.startswith("http://") or "#" in uri:
        return None
    try:
        parts = urlsplit(uri)
        parts.port  # noqa: B018  # raises ValueError on a malformed port
    except ValueError:
        return None
    if "@" in parts.netloc:
        return None
    if _host_as_written(parts) not in {"localhost", "127.0.0.1", "[::1]"}:
        return None
    return parts


def _host_as_written(parts: SplitResult) -> str:
    """The netloc without its port, case and brackets kept (`hostname` would lowercase)."""
    if parts.port is None:
        return parts.netloc
    return parts.netloc.rsplit(":", 1)[0]
