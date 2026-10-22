import json
from urllib.parse import urlencode, urlsplit

from authlib.oauth2 import OAuth2Error
from django.contrib.auth.models import User
from django.db import transaction
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from adapters.clock import get_clock
from core.http import client_ip
from oauth.grants import SandcorpAuthorizationCodeGrant, live_consent
from oauth.models import Client, Consent
from oauth.server import SandcorpRevocationEndpoint, authorization_server_metadata, server
from services import audit, throttle
from services.consents import revoke_consent
from services.signing import published_jwks


@require_GET
def jwks(request: HttpRequest) -> JsonResponse:
    response = JsonResponse(published_jwks())
    response["Cache-Control"] = "public, max-age=600"
    return response


@require_GET
def authorization_server_metadata_view(request: HttpRequest) -> JsonResponse:
    response = JsonResponse(authorization_server_metadata())
    response["Cache-Control"] = "public, max-age=3600"
    return response


@csrf_exempt
@require_POST
def register(request: HttpRequest) -> HttpResponse:
    """Dynamic Client Registration (RFC 7591). Every request counts toward the per-IP limit."""
    ip = client_ip(request)
    blocked = throttle.check("register", f"ip:{ip}")
    if not blocked.allowed:
        limited = JsonResponse({"error": "too_many_requests"}, status=429)
        limited["Retry-After"] = str(blocked.retry_after)
        return limited
    throttle.hit("register", f"ip:{ip}")
    response: HttpResponse = server.create_endpoint_response("client_registration", request)
    if response.status_code == 201:
        client_id = str(json.loads(response.content)["client_id"])
        audit.record(audit.CLIENT_REGISTERED, client_id=client_id, ip=ip, detail={"via": "dcr"})
    response["Cache-Control"] = "no-store"
    return response


@csrf_exempt
@require_POST
def token(request: HttpRequest) -> HttpResponse:
    """The token endpoint (RFC 6749 3.2): authlib runs the grant (`authorization_code`,
    `refresh_token`). Every request counts toward the per-IP limit. Neither tokens nor errors
    may be cached."""
    limited = _token_limit(request)
    if limited is not None:
        return limited
    response: HttpResponse = server.create_token_response(request)
    return _no_store(response)


@csrf_exempt
@require_POST
def revoke(request: HttpRequest) -> HttpResponse:
    """Token revocation (RFC 7009), limited together with the token endpoint per IP."""
    limited = _token_limit(request)
    if limited is not None:
        return limited
    response: HttpResponse = server.create_endpoint_response(
        SandcorpRevocationEndpoint.ENDPOINT_NAME, request
    )
    return _no_store(response)


def _token_limit(request: HttpRequest) -> HttpResponse | None:
    """Count the request toward the per-IP `token` limit; the 429 response if it is over."""
    ip = client_ip(request)
    blocked = throttle.check("token", f"ip:{ip}")
    if not blocked.allowed:
        limited = JsonResponse({"error": "too_many_requests"}, status=429)
        limited["Retry-After"] = str(blocked.retry_after)
        return _no_store(limited)
    throttle.hit("token", f"ip:{ip}")
    return None


@require_http_methods(["GET", "POST"])
def authorize(request: HttpRequest) -> HttpResponse:
    """The authorization endpoint (RFC 6749 4.1 with PKCE S256 and RFC 8707 `resource`).

    GET validates the request and either issues a code at once (a live consent already covers
    the scopes) or shows the consent screen. POST is the owner's answer from that screen
    (`decision=allow|deny`), validated again from the same query string.
    """
    user = request.user
    if not isinstance(user, User) or not user.is_authenticated:
        return redirect("/login?" + urlencode({"next": request.get_full_path()}))
    try:
        grant: SandcorpAuthorizationCodeGrant = server.get_consent_grant(request, end_user=user)
    except OAuth2Error as error:
        return _authorization_error(request, error)
    client: Client = grant.request.client
    consent = live_consent(user, client, grant.resource)
    ip = client_ip(request)
    if request.method == "GET":
        if consent is not None and consent.covers(grant.scopes):
            return _issue_code(request, grant, user, ip)
        return _consent_screen(request, grant, consent)

    detail = {"resource": grant.resource.url, "scope": " ".join(grant.scopes)}
    if request.POST.get("decision") != "allow":
        audit.record(
            audit.CONSENT_DENIED,
            actor=user.username,
            client_id=client.client_id,
            ip=ip,
            detail=detail,
        )
        return _no_store(server.create_authorization_response(request, grant=grant))
    if consent is None or not consent.covers(grant.scopes):
        _grant_consent(user, grant, consent, ip)
        audit.record(
            audit.CONSENT_GRANTED,
            actor=user.username,
            client_id=client.client_id,
            ip=ip,
            detail=detail,
        )
    return _issue_code(request, grant, user, ip)


def _grant_consent(
    user: User, grant: SandcorpAuthorizationCodeGrant, previous: Consent | None, ip: str
) -> Consent:
    """Replace `previous` (if any) with a live consent for its scopes plus the requested ones.
    `previous` is revoked like any consent, refresh token families included: the client is
    getting a code under the new consent right now, so it loses nothing it cannot replace."""
    now = get_clock().now()
    scopes = set(grant.scopes)
    with transaction.atomic():
        if previous is not None:
            scopes |= set(previous.scopes)
            revoke_consent(previous, reason="consent_replaced", actor=user.username, ip=ip)
        return Consent.objects.create(
            user=user,
            client=grant.request.client,
            resource=grant.resource,
            scopes=sorted(scopes),
            granted_at=now,
        )


def _issue_code(
    request: HttpRequest, grant: SandcorpAuthorizationCodeGrant, user: User, ip: str
) -> HttpResponse:
    response: HttpResponse = server.create_authorization_response(
        request, grant_user=user, grant=grant
    )
    issued = grant.issued
    if issued is not None:
        audit.record(
            audit.AUTHORIZATION_CODE_ISSUED,
            actor=user.username,
            client_id=issued.client.client_id,
            ip=ip,
            detail={"resource": issued.resource.url, "scope": issued.scope},
        )
    return _no_store(response)


def _consent_screen(
    request: HttpRequest, grant: SandcorpAuthorizationCodeGrant, consent: Consent | None
) -> HttpResponse:
    client: Client = grant.request.client
    granted = set(consent.scopes) if consent is not None else set()
    descriptions = dict(
        grant.resource.scopes.filter(name__in=grant.scopes).values_list("name", "description")
    )
    scopes = [
        {"name": name, "description": descriptions[name], "granted": name in granted}
        for name in grant.scopes
    ]
    context = {
        "client_name": client.name,
        "client_id": client.client_id if client.registered_via == Client.Via.CIMD else "",
        "resource": grant.resource,
        "scopes": scopes,
        "redirect_host": urlsplit(grant.redirect_uri).netloc,
        "action": request.get_full_path(),
    }
    return _no_store(render(request, "oauth/consent.html", context))


def _authorization_error(request: HttpRequest, error: OAuth2Error) -> HttpResponse:
    """RFC 6749 4.1.2.1: back to the client with `error=` once the client and redirect URI are
    known to be good; otherwise an error page here, never a redirect."""
    if error.redirect_uri:
        oauth_request = server.create_oauth2_request(request)
        return _no_store(server.handle_error_response(oauth_request, error))
    context = {"error": error.error, "description": error.description or ""}
    return _no_store(render(request, "oauth/authorize_error.html", context, status=400))


def _no_store(response: HttpResponse) -> HttpResponse:
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    return response
