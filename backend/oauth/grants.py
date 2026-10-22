"""The authorization code grant (+ PKCE S256) with RFC 8707 `resource`, which authlib lacks.

`SandcorpAuthorizationCodeGrant` is registered on `oauth.server.server`. Authorization request
validation is authlib's (client, redirect URI, response type, PKCE) followed by ours: exactly
one `resource` that is a registered resource URL, and a non-empty `scope` made only of that
resource's scope names. Codes are stored as SHA-256 hashes, bound to the consent that allowed
them, and are good once for `AUTHORIZATION_CODE_LIFETIME`.

At the token endpoint the code is claimed atomically (`used_at`), a `resource` sent there must
equal the code's, and the access token's `aud` is the code's resource. A used code that comes
back revokes the refresh token family its consent opened (`oauth.tokens.report_code_reuse`).
"""

import hashlib

from authlib.oauth2 import OAuth2Error, OAuth2Request
from authlib.oauth2.rfc6749 import InvalidGrantError, InvalidRequestError, InvalidScopeError
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant
from authlib.oauth2.rfc7636 import CodeChallenge
from django.contrib.auth.models import User
from django.db import transaction

from adapters.clock import get_clock
from core.http import client_ip
from oauth.models import AuthorizationCode, Client, Consent, Resource
from oauth.tokens import TokenResponse, report_code_reuse
from services.signing import random_token

type Headers = list[tuple[str, str]]


class InvalidTargetError(OAuth2Error):  # type: ignore[misc]  # authlib has no type stubs
    """RFC 8707 2: the `resource` is missing, repeated, or not a resource of this server."""

    error = "invalid_target"


class S256CodeChallenge(CodeChallenge):  # type: ignore[misc]  # authlib has no type stubs
    """PKCE with S256 only, on every authorization request. authlib's `CodeChallenge` lets a
    request without `code_challenge` through (it only demands a verifier at the token endpoint)
    and accepts `plain`; OAuth 2.1 wants neither."""

    SUPPORTED_CODE_CHALLENGE_METHOD = ["S256"]

    def validate_code_challenge(self, grant: AuthorizationCodeGrant, redirect_uri: str) -> None:
        data = grant.request.payload.data
        if not data.get("code_challenge"):
            raise InvalidRequestError("Missing 'code_challenge'")
        if data.get("code_challenge_method") != "S256":
            raise InvalidRequestError("'code_challenge_method' must be S256")
        super().validate_code_challenge(grant, redirect_uri)


def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def requested_resource(request: OAuth2Request) -> Resource:
    values: list[str] = request.payload.datalist.get("resource", [])
    if len(values) != 1:
        raise InvalidTargetError("Exactly one 'resource' is required.")
    resource = Resource.objects.filter(url=values[0]).first()
    if resource is None:
        raise InvalidTargetError("Unknown 'resource'.")
    return resource


def requested_scopes(request: OAuth2Request, resource: Resource) -> list[str]:
    """The requested scope names (sorted, distinct); all must belong to `resource`."""
    names = sorted(set(str(request.payload.scope or "").split()))
    if not names:
        raise InvalidScopeError("'scope' is required.")
    known = set(resource.scopes.filter(name__in=names).values_list("name", flat=True))
    if known != set(names):
        raise InvalidScopeError(f"Scopes not in {resource.url}: {sorted(set(names) - known)}")
    return names


def live_consent(user: User, client: Client, resource: Resource) -> Consent | None:
    return Consent.objects.filter(
        user=user, client=client, resource=resource, revoked_at__isnull=True
    ).first()


def request_ip(request: OAuth2Request) -> str:
    return client_ip(request._request)  # authlib's Django request keeps the HttpRequest here


def find_used_authorization_code(code: str, client: Client) -> AuthorizationCode | None:
    return (
        AuthorizationCode.objects.select_related("user", "client", "resource", "consent")
        .filter(code_hash=hash_code(code), client=client, used_at__isnull=False)
        .first()
    )


def find_authorization_code(code: str, client: Client) -> AuthorizationCode | None:
    """The unused, unexpired code issued to `client`, or None."""
    found = (
        AuthorizationCode.objects.select_related("user", "resource", "consent")
        .filter(code_hash=hash_code(code), client=client, used_at__isnull=True)
        .first()
    )
    if found is None or found.is_expired():
        return None
    return found


class SandcorpAuthorizationCodeGrant(AuthorizationCodeGrant):  # type: ignore[misc]  # no stubs
    TOKEN_ENDPOINT_AUTH_METHODS = ["none", "client_secret_basic", "client_secret_post"]

    # Set by validate_authorization_request.
    resource: Resource
    scopes: list[str]
    # Set by save_authorization_code (for the view's audit record).
    issued: AuthorizationCode | None = None

    def validate_authorization_request(self) -> str:
        redirect_uri: str = super().validate_authorization_request()
        try:
            self.resource = requested_resource(self.request)
            self.scopes = requested_scopes(self.request, self.resource)
        except OAuth2Error as error:
            error.redirect_uri = redirect_uri
            raise
        return redirect_uri

    def generate_authorization_code(self) -> str:
        return random_token(32)

    def save_authorization_code(self, code: str, request: OAuth2Request) -> AuthorizationCode:
        user: User = request.user
        client: Client = request.client
        consent = live_consent(user, client, self.resource)
        if consent is None or not consent.covers(self.scopes):
            raise RuntimeError("an authorization code needs a consent covering its scopes")
        now = get_clock().now()
        self.issued = AuthorizationCode.objects.create(
            code_hash=hash_code(code),
            client=client,
            user=user,
            consent=consent,
            resource=self.resource,
            redirect_uri=request.payload.redirect_uri or "",
            scope=" ".join(self.scopes),
            code_challenge=request.payload.data["code_challenge"],
            code_challenge_method=request.payload.data["code_challenge_method"],
            auth_time=user.last_login or now,
            created_at=now,
        )
        return self.issued

    def query_authorization_code(self, code: str, client: Client) -> AuthorizationCode | None:
        found = find_authorization_code(code, client)
        if found is None:
            replayed = find_used_authorization_code(code, client)
            if replayed is not None:
                report_code_reuse(replayed, request_ip(self.request))
        return found

    def validate_token_request(self) -> None:
        super().validate_token_request()
        code: AuthorizationCode = self.request.authorization_code
        # RFC 8707 2.2: optional here, but if sent it must be the resource the code is for.
        values: list[str] = self.request.payload.datalist.get("resource", [])
        if values and values != [code.resource.url]:
            raise InvalidTargetError("'resource' is not the resource of the authorization code.")

    def create_token_response(self) -> tuple[int, TokenResponse, Headers]:
        code: AuthorizationCode = self.request.authorization_code
        # Claim the code first, so two concurrent exchanges cannot both get tokens.
        with transaction.atomic():
            claimed = AuthorizationCode.objects.filter(pk=code.pk, used_at__isnull=True).update(
                used_at=get_clock().now()
            )
            if claimed:
                response: tuple[int, TokenResponse, Headers] = super().create_token_response()
                return response
        report_code_reuse(code, request_ip(self.request))
        raise InvalidGrantError("Invalid 'code' in request.")

    def generate_token(
        self,
        user: User | None = None,
        scope: str | None = None,
        grant_type: str | None = None,
        expires_in: int | None = None,
        include_refresh_token: bool = True,
    ) -> TokenResponse:
        code: AuthorizationCode = self.request.authorization_code
        token: TokenResponse = self.server.generate_token(
            grant_type=grant_type or self.GRANT_TYPE,
            client=self.request.client,
            user=user,
            scope=scope,
            expires_in=expires_in,
            include_refresh_token=include_refresh_token,
            resource=code.resource,  # the access token's `aud`
        )
        return token

    def delete_authorization_code(self, authorization_code: AuthorizationCode) -> None:
        # Already marked used by create_token_response's claim; the row stays (replays show).
        pass

    def authenticate_user(self, authorization_code: AuthorizationCode) -> User:
        user: User = authorization_code.user
        return user
