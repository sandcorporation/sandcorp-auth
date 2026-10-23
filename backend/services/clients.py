"""Finding a client by `client_id`: a stored client, or a Client ID Metadata Document (CIMD).

CIMD (draft-ietf-oauth-client-id-metadata-document): when `client_id` is an https URL with a
path, the JSON document at that URL describes the client. We fetch it through the HTTP adapter
(SSRF rules below), validate it, and keep it as a `Client` row (`registered_via=cimd`) that
serves as the cache until `metadata_expires_at`. Any failure means "no such client" (the caller
answers `invalid_client`) and leaves a `client.cimd_rejected` audit event with the reason.
"""

import ipaddress
import json
import re
from collections.abc import Mapping
from datetime import timedelta
from typing import Final
from urllib.parse import urlsplit

from django.db import IntegrityError, transaction

from adapters.clock import get_clock
from adapters.http import FetchError, get_http_client
from oauth.models import Client
from services import audit
from services.redirect_uris import valid_redirect_uri

MAX_DOCUMENT_BYTES: Final = 64 * 1024
FETCH_TIMEOUT_SECONDS: Final = 5.0
DEFAULT_CACHE_SECONDS: Final = 3600
MAX_CACHE_SECONDS: Final = 24 * 3600

_MAX_AGE = re.compile(r"(?:^|,)\s*max-age\s*=\s*\"?(\d+)\"?\s*(?:,|$)", re.IGNORECASE)


class CimdRejected(Exception):
    """The metadata document cannot be used; `str(error)` is the reason for the audit log."""


def find_client(client_id: str) -> Client | None:
    """The active client with this `client_id`, fetching (or refreshing) its CIMD if needed."""
    if not client_id.isascii():
        # `client_id` is an ascii_bin column: no client can have this id, and a metadata
        # document URL must be ASCII (non-ASCII characters percent-encoded).
        if looks_like_cimd_url(client_id):
            _record_rejected(client_id, "client_id is not ASCII")
        return None
    client = Client.objects.filter(client_id=client_id).first()
    if client is not None and not client.active:
        return None
    if client is not None and client.registered_via != Client.Via.CIMD:
        return client
    if client is None and not looks_like_cimd_url(client_id):
        return None
    now = get_clock().now()
    if client is not None and client.metadata_expires_at and now < client.metadata_expires_at:
        return client
    try:
        return _fetch_and_store(client_id, client)
    except CimdRejected as error:
        _record_rejected(client_id, str(error))
        return None


def _record_rejected(client_id: str, reason: str) -> None:
    audit.record(audit.CLIENT_CIMD_REJECTED, client_id=client_id[:200], detail={"reason": reason})


def looks_like_cimd_url(client_id: str) -> bool:
    """https with a path: the shape that makes a `client_id` a metadata document URL."""
    parts = urlsplit(client_id)
    return parts.scheme == "https" and bool(parts.netloc) and parts.path not in ("", "/")


def _check_url(url: str) -> str:
    """Validate the URL and its host's addresses (SSRF); return the address to connect to.
    The fetch is pinned to this address so the name is resolved only once (no DNS rebinding
    between check and connect)."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as error:
        raise CimdRejected("malformed URL") from error
    if parts.scheme != "https":
        raise CimdRejected("not https")
    if parts.path in ("", "/"):
        raise CimdRejected("URL has no path")
    if parts.username is not None or parts.password is not None:
        raise CimdRejected("URL carries credentials")
    if parts.fragment:
        raise CimdRejected("URL has a fragment")
    if port not in (None, 443):
        raise CimdRejected("port other than 443")
    host = parts.hostname
    if not host:
        raise CimdRejected("URL has no host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise CimdRejected("host is an IP literal")
    try:
        addresses = get_http_client().resolve(host)
    except FetchError as error:
        raise CimdRejected("host does not resolve") from error
    if not addresses:
        raise CimdRejected("host does not resolve")
    for address in addresses:
        if not _public_address(address):
            raise CimdRejected("host resolves to a non-public address")
    return addresses[0]


def _public_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def _cache_seconds(headers: Mapping[str, str]) -> int:
    match = _MAX_AGE.search(headers.get("cache-control", ""))
    if match is None:
        return DEFAULT_CACHE_SECONDS
    return min(int(match.group(1)), MAX_CACHE_SECONDS)


def _fetch_and_store(url: str, client: Client | None) -> Client:
    address = _check_url(url)
    try:
        fetched = get_http_client().fetch_json(
            url, address=address, max_bytes=MAX_DOCUMENT_BYTES, timeout=FETCH_TIMEOUT_SECONDS
        )
    except FetchError as error:
        raise CimdRejected("fetch failed") from error
    if fetched.status != 200:
        raise CimdRejected(f"HTTP status {fetched.status}")
    content_type = fetched.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/json" and not content_type.endswith("+json"):
        raise CimdRejected("content type is not JSON")
    if len(fetched.body) > MAX_DOCUMENT_BYTES:
        raise CimdRejected("document too large")
    try:
        document: object = json.loads(fetched.body)
    except (ValueError, UnicodeDecodeError) as error:
        raise CimdRejected("not valid JSON") from error
    name, redirect_uris = _validate_document(url, document)

    now = get_clock().now()
    expires_at = now + timedelta(seconds=_cache_seconds(fetched.headers))
    if client is None:
        client = Client(client_id=url, registered_via=Client.Via.CIMD, created_at=now)
    client.name = name
    client.redirect_uris = redirect_uris
    client.kind = Client.Kind.PUBLIC
    client.metadata_document = document
    client.metadata_fetched_at = now
    client.metadata_expires_at = expires_at
    try:
        with transaction.atomic():
            client.save()
    except IntegrityError:  # another request cached the same document first
        return Client.objects.get(client_id=url)
    return client


def _validate_document(url: str, document: object) -> tuple[str, list[str]]:
    if not isinstance(document, dict):
        raise CimdRejected("document is not a JSON object")
    if document.get("client_id") != url:
        raise CimdRejected("client_id does not match the document URL")
    name = document.get("client_name")
    if not isinstance(name, str) or not name.strip():
        raise CimdRejected("client_name missing")
    redirect_uris = document.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        raise CimdRejected("redirect_uris missing")
    if not all(valid_redirect_uri(uri) for uri in redirect_uris):
        raise CimdRejected("invalid redirect_uri")
    if document.get("token_endpoint_auth_method", "none") != "none":
        raise CimdRejected("token_endpoint_auth_method other than none")
    return name.strip()[:200], [str(uri) for uri in redirect_uris]
