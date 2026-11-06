"""The authlib authorization server: the one place OAuth protocol handling is wired up.

`server` is the `AuthorizationServer` every OAuth view uses. Clients come from
`services.clients.find_client` (stored clients, then CIMD). Registered here now: the dynamic
client registration endpoint (RFC 7591) and the authorization code grant with required PKCE
S256 and RFC 8707 `resource` (`oauth.grants`), whose tokens come from `oauth.tokens` (JWT
access token with `aud` = the code's resource; refresh token stored as a hash in the consent's
family by `save_token`), the refresh token grant that rotates them, and the revocation
endpoint (RFC 7009) that revokes a refresh token's whole family. Later grants and endpoints are
registered with `server.register_grant(...)` / `server.register_endpoint(...)` at the bottom of
this module.
"""

from datetime import datetime
from typing import Final

from authlib.integrations.django_oauth2 import AuthorizationServer, RevocationEndpoint
from authlib.oauth2 import OAuth2Request
from authlib.oauth2.rfc6749 import InvalidRequestError, JsonRequest
from authlib.oauth2.rfc7591 import (
    ClientRegistrationEndpoint,
    InvalidClientMetadataError,
    InvalidRedirectURIError,
)
from authlib.oidc.discovery import OpenIDProviderMetadata
from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser

from adapters.clock import get_clock
from oauth.grants import (
    S256CodeChallenge,
    SandcorpAuthorizationCodeGrant,
    SandcorpClientCredentialsGrant,
    SandcorpRefreshTokenGrant,
    request_ip,
)
from oauth.models import AuthorizationCode, Client, RefreshToken, Resource, Scope
from oauth.tokens import (
    SandcorpTokenGenerator,
    TokenResponse,
    access_token_jti,
    find_refresh_token,
    live_family,
    revoke_family,
    store_refresh_token,
)
from services import audit
from services.clients import find_client
from services.oidc import CLAIMS_SUPPORTED
from services.redirect_uris import ALLOWED_GRANT_TYPES, CLIENT_CREDENTIALS, valid_redirect_uri
from services.signing import ALGORITHM, random_token

type JSON = str | int | float | bool | None | list[JSON] | dict[str, JSON]

# Endpoint paths (relative to SITE_URL). Later tickets mount their views at these paths.
AUTHORIZE_PATH: Final = "/authorize"
TOKEN_PATH: Final = "/token"
REGISTER_PATH: Final = "/register"
REVOKE_PATH: Final = "/revoke"
JWKS_PATH: Final = "/.well-known/jwks.json"
USERINFO_PATH: Final = "/userinfo"

CLIENT_AUTH_METHODS: Final = ["none", "client_secret_basic", "client_secret_post"]


class ProviderMetadata(OpenIDProviderMetadata):  # type: ignore[misc]  # no stubs
    """OpenID Provider metadata checks, except that RS256 is not demanded: ID tokens are
    EdDSA only, signed with the same Ed25519 keys as access tokens (docs/adr/0001)."""

    def validate_id_token_signing_alg_values_supported(self) -> None:
        values = self.get("id_token_signing_alg_values_supported")
        if not isinstance(values, list) or not values:
            raise ValueError('"id_token_signing_alg_values_supported" MUST be a JSON array')


def authorization_server_metadata() -> dict[str, JSON]:
    """The one metadata document, served both as RFC 8414 (`oauth-authorization-server`) and
    as OpenID Connect Discovery (`openid-configuration`) so the two never disagree; validated
    with authlib's OpenID Provider model (a superset of RFC 8414) before it is served."""
    site = settings.SITE_URL
    scope_names = sorted(set(Scope.objects.values_list("name", flat=True)))
    metadata: dict[str, JSON] = {
        "issuer": site,
        "authorization_endpoint": site + AUTHORIZE_PATH,
        "token_endpoint": site + TOKEN_PATH,
        "registration_endpoint": site + REGISTER_PATH,
        "revocation_endpoint": site + REVOKE_PATH,
        "jwks_uri": site + JWKS_PATH,
        "userinfo_endpoint": site + USERINFO_PATH,
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [ALGORITHM],
        "claims_supported": list(CLAIMS_SUPPORTED),
        "grant_types_supported": [*ALLOWED_GRANT_TYPES, CLIENT_CREDENTIALS],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": list(CLIENT_AUTH_METHODS),
        "revocation_endpoint_auth_methods_supported": list(CLIENT_AUTH_METHODS),
        "scopes_supported": list(scope_names),
        "client_id_metadata_document_supported": True,
    }
    ProviderMetadata(metadata).validate()
    return metadata


class SandcorpAuthorizationServer(AuthorizationServer):  # type: ignore[misc]  # no stubs
    token_generator: SandcorpTokenGenerator

    def query_client(self, client_id: str) -> Client | None:
        return find_client(client_id)

    def create_bearer_token_generator(self) -> SandcorpTokenGenerator:
        # Called by authlib's __init__ (load_config) to register the "default" generator.
        self.token_generator = SandcorpTokenGenerator()
        return self.token_generator

    def generate_token(
        self,
        grant_type: str,
        client: Client,
        user: AbstractBaseUser | None = None,
        scope: str | None = None,
        expires_in: int | None = None,
        include_refresh_token: bool = True,
        *,
        resource: Resource | None = None,
        auth_time: datetime | None = None,
        nonce: str | None = None,
    ) -> TokenResponse:
        """authlib's signature plus `resource`, the access token's audience (RFC 8707), and
        the ID token's `auth_time` and `nonce` (used only with the `openid` scope)."""
        return self.token_generator.generate(
            grant_type,
            client,
            user=user,
            scope=scope,
            expires_in=expires_in,
            include_refresh_token=include_refresh_token,
            resource=resource,
            auth_time=auth_time,
            nonce=nonce,
        )

    def save_token(self, token: TokenResponse, request: OAuth2Request) -> RefreshToken | None:
        """Access tokens are self-contained JWTs and are not stored. The refresh token goes (as
        a hash) into a family: on a code exchange the live family of the code's consent, on a
        refresh the presented token's family, with the presented token's scope (RFC 6749 6:
        a new refresh token has exactly the scope of the one it replaces). Returns it."""
        presented: RefreshToken | None = request.refresh_token
        if presented is not None:
            family = presented.family
            kind = audit.TOKEN_REFRESHED
            refresh_scope = presented.scope
            auth_time = presented.auth_time
        else:
            code: AuthorizationCode = request.authorization_code
            family = live_family(code.consent)
            kind = audit.TOKEN_ISSUED
            refresh_scope = token["scope"]
            auth_time = code.auth_time
        jti = access_token_jti(token["access_token"])
        stored = None
        if "refresh_token" in token:
            stored = store_refresh_token(
                family, token["refresh_token"], refresh_scope, jti, auth_time
            )
        client: Client = request.client
        audit.record(
            kind,
            actor=family.user.get_username(),
            client_id=client.client_id,
            ip=request_ip(request),
            detail={
                "client_id": client.client_id,
                "resource": family.resource.url,
                "scope": token["scope"],
                "jti": jti,
                "family": family.pk,
            },
        )
        return stored


class SandcorpRevocationEndpoint(RevocationEndpoint):  # type: ignore[misc]  # no stubs
    """RFC 7009. A refresh token revokes its whole family. Access tokens are short-lived JWTs
    with no deny list: revoking one is accepted (200) and does nothing; cutting the refresh
    token is what stops a client. Unknown tokens get 200 too. Another client's refresh token is
    refused by authlib with `invalid_grant` (RFC 7009 2.1) and is left alone."""

    CLIENT_AUTH_METHODS = list(CLIENT_AUTH_METHODS)

    def query_token(self, token_string: str, token_type_hint: str | None) -> RefreshToken | None:
        # The hint is ignored: RFC 7009 2.1 says to search every type when it does not match,
        # and refresh tokens are the only kind stored.
        return find_refresh_token(token_string)

    def revoke_token(self, token: RefreshToken, request: OAuth2Request) -> None:
        family = token.family
        revoke_family(family, "revoked_by_client")
        audit.record(
            audit.TOKEN_REVOKED,
            actor=family.user.get_username(),
            client_id=family.client.client_id,
            ip=request_ip(request),
            detail={
                "resource": family.resource.url,
                "family": family.pk,
                "reason": "revoked_by_client",
            },
        )


class OpenRegistration:
    """The credential of an open (unauthenticated) registration request."""


class DynamicClientRegistration(ClientRegistrationEndpoint):  # type: ignore[misc]  # no stubs
    """RFC 7591 for public clients only: `token_endpoint_auth_method=none`, code flow, no
    secret. Confidential clients are registered in admin."""

    def authenticate_token(self, request: JsonRequest) -> OpenRegistration:
        return OpenRegistration()  # open registration; requests are limited per IP by the view

    def get_server_metadata(self) -> dict[str, JSON]:
        # What a dynamically registered client may ask for; authlib checks the claims against it.
        return {
            "response_types_supported": ["code"],
            "grant_types_supported": list(ALLOWED_GRANT_TYPES),
            "token_endpoint_auth_methods_supported": ["none"],
        }

    def extract_client_metadata(self, request: JsonRequest) -> dict[str, JSON]:
        try:
            data: object = request.payload.data
        except ValueError as error:
            raise InvalidRequestError("body is not JSON") from error
        if not isinstance(data, dict):
            raise InvalidRequestError("body is not a JSON object")
        data.setdefault("grant_types", list(ALLOWED_GRANT_TYPES))
        data.setdefault("response_types", ["code"])
        data.setdefault("token_endpoint_auth_method", "none")
        uris = data.get("redirect_uris")
        if not isinstance(uris, list) or not uris or not all(map(valid_redirect_uri, uris)):
            raise InvalidRedirectURIError(
                "redirect_uris must be https, or http on localhost/127.0.0.1/[::1]"
            )
        name = data.get("client_name")
        if not isinstance(name, str) or not name.strip():
            raise InvalidClientMetadataError("client_name is required")
        metadata: dict[str, JSON] = super().extract_client_metadata(request)
        return metadata

    def generate_client_info(self, request: JsonRequest) -> dict[str, JSON]:
        # No client secret: dynamically registered clients are public.
        return {
            "client_id": random_token(),
            "client_id_issued_at": int(get_clock().now().timestamp()),
        }

    def save_client(
        self, client_info: dict[str, JSON], client_metadata: dict[str, JSON], request: JsonRequest
    ) -> Client:
        return Client.objects.create(
            client_id=str(client_info["client_id"]),
            name=str(client_metadata["client_name"]).strip()[:200],
            redirect_uris=client_metadata["redirect_uris"],
            kind=Client.Kind.PUBLIC,
            registered_via=Client.Via.DCR,
            created_at=get_clock().now(),
        )


server = SandcorpAuthorizationServer(Client, None)  # no token model: see save_token
server.register_endpoint(DynamicClientRegistration)
server.register_grant(SandcorpAuthorizationCodeGrant, [S256CodeChallenge(required=True)])
server.register_grant(SandcorpRefreshTokenGrant)
server.register_grant(SandcorpClientCredentialsGrant)  # machine clients only (#76)
server.register_endpoint(SandcorpRevocationEndpoint)
