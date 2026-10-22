"""Small helpers that read the HTTP request (services never see the request itself)."""

from django.conf import settings
from django.http import HttpRequest


def client_ip(request: HttpRequest) -> str:
    """The caller's address. Behind NPMplus (`TRUST_X_FORWARDED_FOR`) the first
    `X-Forwarded-For` entry; otherwise `REMOTE_ADDR`."""
    if settings.TRUST_X_FORWARDED_FOR:
        forwarded = str(request.META.get("HTTP_X_FORWARDED_FOR", ""))
        first = forwarded.split(",")[0].strip()
        if first:
            return first[:45]
    return str(request.META.get("REMOTE_ADDR", ""))[:45]
