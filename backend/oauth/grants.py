"""The authorization code grant (+ PKCE S256) with RFC 8707 `resource`, which authlib lacks.

`SandcorpAuthorizationCodeGrant` is registered on `oauth.server.server`. Authorization request
validation is authlib's (client, redirect URI, response type, PKCE) followed by ours: exactly
one `resource` that is a registered resource URL, and a non-empty `scope` made only of that
resource's scope names. Codes are stored as SHA-256 hashes, bound to the consent that allowed
them, and are good once for `AUTHORIZATION_CODE_LIFETIME`.

OpenID Connect (`services.oidc`) adds login info scopes: without a `resource` they bind the
grant to the internal login info resource, with one they ride along. The `nonce` is kept on the
code for the ID token.

At the token endpoint the code is claimed atomically (`used_at`), a `resource` sent there must
equal the code's, and the access token's `aud` is the code's resource. A used code that comes
back revokes the refresh token family its consent opened (`oauth.tokens.report_code_reuse`).

`SandcorpRefreshTokenGrant` rotates refresh tokens: every refresh returns a new refresh token in
the same family and marks the old one `replaced_by` it. A replaced or revoked refresh token that
comes back is reuse: the whole family is revoked. The family's resource is the only possible
`aud`, and a narrower `scope` may be asked for, never a wider one.
"""

import hashlib

from authlib.oauth2 import OAuth2Error, OAuth2Request
from authlib.oauth2.rfc6749 import InvalidGrantError, InvalidRequestError, InvalidScopeError
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant, RefreshTokenGrant
from authlib.oauth2.rfc7636 import CodeChallenge
from django.contrib.auth.models import User
from django.db import transaction

from adapters.clock import get_clock
from core.http import client_ip
from oauth.models import AuthorizationCode, Client, Consent, RefreshToken, Resource
from oauth.tokens import (
    TokenResponse,
    find_refresh_token,
    report_code_reuse,
    revoke_family,
)
from services import audit
from services.oidc import LOGIN_INFO_SCOPES, OPENID, USERINFO_RESOURCE
from services.signing import random_token

type Headers = list[tuple[str, str]]

NONCE_MAX_LENGTH = 255  # AuthorizationCode.nonce


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
    """The one `resource` asked for; without one, an OpenID Connect request (scope `openid`)
    gets the internal login info resource (`services.oidc.USERINFO_RESOURCE`)."""
    values: list[str] = request.payload.datalist.get("resource", [])
    if not values and OPENID in str(request.payload.scope or "").split():
        values = [USERINFO_RESOURCE]
    if len(values) != 1:
        raise InvalidTargetError("Exactly one 'resource' is required.")
    resource = Resource.objects.filter(url=values[0]).first()
    if resource is None:
        raise InvalidTargetError("Unknown 'resource'.")
    return resource


def requested_scopes(request: OAuth2Request, client: Client, resource: Resource) -> list[str]:
    """The requested scope names (sorted, distinct). Each belongs to `resource`, or is a login
    info scope (`services.oidc`) asked for with `openid` by a confidential client; besides
    those, at least one scope of `resource`."""
    names = sorted(set(str(request.payload.scope or "").split()))
    if not names:
        raise InvalidScopeError("'scope' is required.")
    login_info = LOGIN_INFO_SCOPES.intersection(names)
    if login_info:
        if OPENID not in login_info:
            raise InvalidScopeError("'profile' and 'email' need 'openid'.")
        if client.is_public:
            raise InvalidScopeError("Login info scopes are for confidential clients only.")
    own = set(names) if resource.url == USERINFO_RESOURCE else set(names) - login_info
    if not own:
        raise InvalidScopeError(f"'scope' needs a scope of {resource.url}.")
    known = set(resource.scopes.filter(name__in=own).values_list("name", flat=True))
    if known != own:
        raise InvalidScopeError(f"Scopes not in {resource.url}: {sorted(own - known)}")
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
            self.scopes = requested_scopes(self.request, self.request.client, self.resource)
            if len(str(self.request.payload.data.get("nonce") or "")) > NONCE_MAX_LENGTH:
                raise InvalidRequestError(f"'nonce' is longer than {NONCE_MAX_LENGTH}.")
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
            nonce=str(request.payload.data.get("nonce") or ""),
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
            auth_time=code.auth_time,
            nonce=code.nonce or None,
        )
        return token

    def delete_authorization_code(self, authorization_code: AuthorizationCode) -> None:
        # Already marked used by create_token_response's claim; the row stays (replays show).
        pass

    def authenticate_user(self, authorization_code: AuthorizationCode) -> User:
        user: User = authorization_code.user
        return user


class SandcorpRefreshTokenGrant(RefreshTokenGrant):  # type: ignore[misc]  # no stubs
    TOKEN_ENDPOINT_AUTH_METHODS = ["none", "client_secret_basic", "client_secret_post"]
    INCLUDE_NEW_REFRESH_TOKEN = True

    # Set by save_token: the refresh token that replaces the one presented.
    issued: RefreshToken | None = None

    def validate_token_request(self) -> None:
        # authlib's order, except that request.client is known before the refresh token is
        # looked up: another client's token is refused without touching its family.
        client: Client = self._validate_request_client()
        self.request.client = client
        token: RefreshToken = self._validate_request_token(client)
        self._validate_token_scope(token)  # narrower is fine, wider is invalid_scope
        self.request.refresh_token = token
        # RFC 8707 2.2: the family is bound to one resource; a `resource` sent must be it.
        values: list[str] = self.request.payload.datalist.get("resource", [])
        if values and values != [token.family.resource.url]:
            raise InvalidTargetError("'resource' is not the resource of the refresh token.")

    def authenticate_refresh_token(self, refresh_token: str) -> RefreshToken | None:
        client: Client = self.request.client
        found = find_refresh_token(refresh_token)
        if found is None or not found.check_client(client):
            return None
        if found.replaced_by_id is not None or found.revoked_at is not None:
            # Reuse: someone holds a token that was already spent. Trust nobody in the family.
            family = found.family
            revoke_family(family, "refresh_reuse")
            audit.record(
                audit.TOKEN_REUSE_DETECTED,
                actor=family.user.get_username(),
                client_id=client.client_id,
                ip=request_ip(self.request),
                detail={"resource": family.resource.url, "family": family.pk},
            )
            return None
        if found.family.revoked_at is not None or found.is_expired():
            return None
        return found

    def create_token_response(self) -> tuple[int, TokenResponse, Headers]:
        token: RefreshToken = self.request.refresh_token
        # Lock the presented token and check it is still unspent, so two concurrent refreshes
        # with the same token cannot both rotate it. The loser gets invalid_grant (not reuse:
        # its token was valid when it was sent).
        with transaction.atomic():
            unspent = (
                RefreshToken.objects.select_for_update()
                .filter(pk=token.pk, replaced_by__isnull=True, revoked_at__isnull=True)
                .exists()
            )
            if unspent:
                response: tuple[int, TokenResponse, Headers] = super().create_token_response()
                return response
        raise InvalidGrantError("Invalid 'refresh_token' in request.")

    def generate_token(
        self,
        user: User | None = None,
        scope: str | None = None,
        grant_type: str | None = None,
        expires_in: int | None = None,
        include_refresh_token: bool = True,
    ) -> TokenResponse:
        token: RefreshToken = self.request.refresh_token
        generated: TokenResponse = self.server.generate_token(
            grant_type=grant_type or self.GRANT_TYPE,
            client=self.request.client,
            user=user,
            scope=scope,
            expires_in=expires_in,
            include_refresh_token=include_refresh_token,
            resource=token.family.resource,  # the access token's `aud`, always the family's
            auth_time=token.auth_time,  # OpenID Connect Core 12.2: the original login; no nonce
        )
        return generated

    def save_token(self, token: TokenResponse) -> None:
        self.issued = self.server.save_token(token, self.request)

    def authenticate_user(self, refresh_token: RefreshToken) -> User:
        user: User = refresh_token.family.user
        return user

    def revoke_old_credential(self, refresh_token: RefreshToken) -> None:
        if self.issued is None:
            raise RuntimeError("a rotated refresh token needs its replacement")
        RefreshToken.objects.filter(pk=refresh_token.pk).update(replaced_by=self.issued)
