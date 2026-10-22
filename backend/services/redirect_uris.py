"""Rules shared by every way a client gets registered (CIMD, DCR, admin)."""

from typing import Final
from urllib.parse import urlsplit

ALLOWED_GRANT_TYPES: Final = ("authorization_code", "refresh_token")
LOOPBACK_HOSTS: Final = frozenset({"localhost", "127.0.0.1"})


def valid_redirect_uri(uri: object) -> bool:
    """https with a host, or http on localhost/127.0.0.1 (any port). No fragment."""
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
