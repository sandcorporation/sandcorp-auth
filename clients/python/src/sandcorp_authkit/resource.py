"""Protected-resource metadata (RFC 9728) and `WWW-Authenticate` values for a resource server.

The shapes are sandcorp-auth `docs/resource-server-token-validation.md` §5–§6. Plain values in,
plain values out — the web framework writes them into the response.
"""

from collections.abc import Sequence
from typing import Literal, NotRequired, TypedDict
from urllib.parse import SplitResult, urlsplit

WELL_KNOWN = "/.well-known/oauth-protected-resource"


class ProtectedResourceMetadata(TypedDict):
    resource: str
    authorization_servers: list[str]
    scopes_supported: list[str]
    bearer_methods_supported: list[str]
    resource_name: NotRequired[str]


def protected_resource_metadata(
    resource: str,
    authorization_server: str,
    scopes_supported: Sequence[str],
    *,
    resource_name: str | None = None,
) -> ProtectedResourceMetadata:
    """The JSON body served at `metadata_path(resource)` (and, by the existing sites, also at
    the bare well-known path). Tokens travel in the `Authorization` header only (§3 B1)."""
    if isinstance(scopes_supported, str):
        raise TypeError("scopes_supported is a sequence of scope names, not one string")
    body: ProtectedResourceMetadata = {
        "resource": resource,
        "authorization_servers": [authorization_server],
        "scopes_supported": list(scopes_supported),
        "bearer_methods_supported": ["header"],
    }
    if resource_name is not None:
        body["resource_name"] = resource_name
    return body


def metadata_path(resource: str) -> str:
    """RFC 9728 §3.1: the well-known path for `resource`. With a path component it goes after
    the well-known segment (`https://x/mcp` -> `/.well-known/oauth-protected-resource/mcp`);
    without one (or only `/`) it is the bare well-known path. A trailing `/` after the host is
    dropped. Resource identifiers with a query or fragment are refused (§1.2)."""
    parts = _resource_parts(resource)
    return WELL_KNOWN + ("" if parts.path == "/" else parts.path)


def metadata_url(resource: str) -> str:
    """The absolute URL of `metadata_path(resource)` on the resource's own origin — the value
    for `www_authenticate(resource_metadata_url=...)`."""
    parts = _resource_parts(resource)
    return f"{parts.scheme}://{parts.netloc}{metadata_path(resource)}"


def _resource_parts(resource: str) -> SplitResult:
    parts = urlsplit(resource)
    if parts.scheme not in ("https", "http") or not parts.netloc:
        raise ValueError("resource must be an absolute http(s) URL")
    if parts.query or parts.fragment or "?" in resource or "#" in resource:
        raise ValueError("resource must not have a query or fragment (RFC 9728 §1.2)")
    return parts


def www_authenticate(
    resource_metadata_url: str,
    *,
    error: Literal["invalid_token", "insufficient_scope"] | None = None,
    scope: str | None = None,
) -> str:
    """The `WWW-Authenticate` value (§5), byte for byte:

    - no token (401): `Bearer resource_metadata="<url>"`
    - bad token (401): `Bearer resource_metadata="<url>", error="invalid_token"`
    - missing scope (403): `Bearer error="insufficient_scope", scope="<scope>"`
    """
    if error == "insufficient_scope":
        if not scope:
            raise ValueError("insufficient_scope needs the required scope")
        return f'Bearer error="insufficient_scope", scope="{_quotable(scope)}"'
    if scope is not None:
        raise ValueError("scope goes only with insufficient_scope")
    value = f'Bearer resource_metadata="{_quotable(resource_metadata_url)}"'
    if error == "invalid_token":
        value += ', error="invalid_token"'
    return value


def _quotable(value: str) -> str:
    """Values go inside a quoted-string; refuse anything that could break out of it or out of
    the header line rather than escaping it (these come from configuration, not from users)."""
    if any(ch in value for ch in '"\\') or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError("value cannot go in a WWW-Authenticate quoted-string")
    return value
