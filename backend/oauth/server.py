"""The authlib authorization server: the one place OAuth protocol handling is wired up.

`server` is the `AuthorizationServer` every OAuth view uses. Clients come from
`services.clients.find_client` (stored clients, then CIMD). Registered here now: the dynamic
client registration endpoint (RFC 7591) and the authorization code grant with required PKCE
S256 and RFC 8707 `resource` (`oauth.grants`), whose tokens come from `oauth.tokens` (JWT
access token with `aud` = the code's resource; refresh token stored as a hash in the consent's
family by `save_token`). The refresh token grant and the revocation
endpoint are registered by later tickets with `server.register_grant(...)` /
`server.register_endpoint(...)` at the bottom of this module.
"""

from typing import Final

from authlib.integrations.django_oauth2 import AuthorizationServer
from authlib.oauth2 import OAuth2Request
from authlib.oauth2.rfc6749 import InvalidRequestError, JsonRequest
from authlib.oauth2.rfc7591 import (
    ClientRegistrationEndpoint,
    InvalidClientMetadataError,
    InvalidRedirectURIError,
)
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser

from adapters.clock import get_clock
from oauth.grants import S256CodeChallenge, SandcorpAuthorizationCodeGrant, request_ip
from oauth.models import AuthorizationCode, Client, Resource, Scope
from oauth.tokens import (
    SandcorpTokenGenerator,
    TokenResponse,
    access_token_jti,
    live_family,
    store_refresh_token,
)
from services import audit
from services.clients import find_client
from services.redirect_uris import ALLOWED_GRANT_TYPES, valid_redirect_uri
from services.signing import random_token

type JSON = str | int | float | bool | None | list[JSON] | dict[str, JSON]

# Endpoint paths (relative to SITE_URL). Later tickets mount their views at these paths.
AUTHORIZE_PATH: Final = "/authorize"
TOKEN_PATH: Final = "/token"
REGISTER_PATH: Final = "/register"
REVOKE_PATH: Final = "/revoke"
JWKS_PATH: Final = "/.well-known/jwks.json"

CLIENT_AUTH_METHODS: Final = ["none", "client_secret_basic", "client_secret_post"]


def authorization_server_metadata() -> dict[str, JSON]:
    """RFC 8414 metadata, validated with authlib's model before it is served."""
    site = settings.SITE_URL
    scope_names = sorted(set(Scope.objects.values_list("name", flat=True)))
    metadata: dict[str, JSON] = {
        "issuer": site,
        "authorization_endpoint": site + AUTHORIZE_PATH,
        "token_endpoint": site + TOKEN_PATH,
        "registration_endpoint": site + REGISTER_PATH,
        "revocation_endpoint": site + REVOKE_PATH,
        "jwks_uri": site + JWKS_PATH,
        "response_types_supported": ["code"],
        "grant_types_supported": list(ALLOWED_GRANT_TYPES),
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": list(CLIENT_AUTH_METHODS),
        "revocation_endpoint_auth_methods_supported": list(CLIENT_AUTH_METHODS),
        "scopes_supported": list(scope_names),
        "client_id_metadata_document_supported": True,
    }
    AuthorizationServerMetadata(metadata).validate()
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
    ) -> TokenResponse:
        """authlib's signature plus `resource`, the access token's audience (RFC 8707)."""
        return self.token_generator.generate(
            grant_type,
            client,
            user=user,
            scope=scope,
            expires_in=expires_in,
            include_refresh_token=include_refresh_token,
            resource=resource,
        )

    def save_token(self, token: TokenResponse, request: OAuth2Request) -> None:
        """Access tokens are self-contained JWTs and are not stored. The refresh token goes
        (as a hash) into the live family of the consent behind the authorization code."""
        code: AuthorizationCode = request.authorization_code
        family = live_family(code.consent)
        jti = access_token_jti(token["access_token"])
        if "refresh_token" in token:
            store_refresh_token(family, token["refresh_token"], token["scope"], jti)
        client: Client = request.client
        audit.record(
            audit.TOKEN_ISSUED,
            actor=code.user.get_username(),
            client_id=client.client_id,
            ip=request_ip(request),
            detail={
                "client_id": client.client_id,
                "resource": code.resource.url,
                "scope": token["scope"],
                "jti": jti,
                "family": family.pk,
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
                "redirect_uris must be https, or http on localhost/127.0.0.1"
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
