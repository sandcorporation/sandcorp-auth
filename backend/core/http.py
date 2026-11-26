"""Small helpers that read the HTTP request (services never see the request itself)."""

from ipaddress import ip_address

from django.conf import settings
from django.http import HttpRequest


def client_ip(request: HttpRequest) -> str:
    """The caller's address. With `TRUST_X_FORWARDED_FOR = N` trusted proxies in front, each
    appending to `X-Forwarded-For`, the N-th entry from the right (what the outermost trusted
    proxy saw). Too few entries, an entry that is not an address, or N = 0: `REMOTE_ADDR`."""
    remote = str(request.META.get("REMOTE_ADDR", ""))[:45]
    hops = int(settings.TRUST_X_FORWARDED_FOR)
    if hops <= 0:
        return remote
    forwarded = str(request.META.get("HTTP_X_FORWARDED_FOR", ""))
    entries = [entry.strip() for entry in forwarded.split(",") if entry.strip()]
    if len(entries) < hops:
        return remote
    candidate = entries[-hops].removeprefix("[").removesuffix("]")
    try:
        return str(ip_address(candidate))
    except ValueError:
        return remote
