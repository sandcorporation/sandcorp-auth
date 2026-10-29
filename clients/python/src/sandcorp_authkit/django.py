"""Bearer authentication for Django views and django-ninja (§3 rules, §5 responses).

Needs the `[django]` extra. Settings are never read here: the site's adapter builds a
`BearerConfig` (or a zero-argument function returning one, so tests can change settings).

- `require_bearer(scope, config=…)`  — Django view decorator; the view gets `(request, token, …)`
  and `request.access_token` is set too.
- `BearerAuth(scope, config=…)`      — django-ninja `auth=`; `request.auth` is the AccessToken.
- `install_bearer_errors(api)`       — once per NinjaAPI, turns `BearerAuth` refusals into the
  §5 responses (401/403 + `WWW-Authenticate`, 503 when auth is not configured).
- `authenticate(request, scope, config)` — the check itself, raising the exceptions below.
- `deny(request, error, resource_metadata_url=…)` — the response for one of those exceptions.
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Concatenate

try:
    from django.http import HttpRequest, HttpResponse, JsonResponse
    from ninja import NinjaAPI
    from ninja.security.base import AuthBase
except ModuleNotFoundError as exc:  # pragma: no cover - exercised in a subprocess
    raise ModuleNotFoundError(
        "sandcorp_authkit.django needs the [django] extra: sandcorp-authkit[django]"
    ) from exc

from .resource import protected_resource_metadata, www_authenticate
from .tokens import (
    AccessToken,
    ClaimsHook,
    Clock,
    InsufficientScope,
    JwksCache,
    TokenRejected,
    validate_access_token,
)

logger = logging.getLogger(__name__)


class AuthNotConfigured(Exception):
    """A setting auth needs is empty: 503, so the rest of the site keeps working.
    Raise it from a config function too (e.g. when the owner sub setting is empty)."""


class MissingToken(Exception):
    """No `Authorization: Bearer …`: 401 with `resource_metadata` and no `error`."""


type BearerError = MissingToken | TokenRejected | InsufficientScope | AuthNotConfigured


@dataclass(frozen=True)
class BearerConfig:
    issuer: str
    audience: str
    """This resource's URL (the token's `aud`)."""
    resource_metadata_url: str
    """Where `WWW-Authenticate` points (the site's protected-resource metadata URL)."""
    jwks: JwksCache
    clock: Clock
    extra_claims_hook: ClaimsHook | None = None
    """`tokens.owner_only(sub)` for owner-only sites, `owner_or_member(sub)` for flow."""


type ConfigSource = BearerConfig | Callable[[], BearerConfig]


def _resolve(config: ConfigSource) -> BearerConfig:
    resolved = config() if callable(config) else config
    if not (resolved.issuer and resolved.audience and resolved.resource_metadata_url):
        raise AuthNotConfigured("issuer, audience and resource_metadata_url must be set")
    return resolved


def bearer_token(request: HttpRequest) -> str:
    """The token from `Authorization: Bearer <token>` (scheme case-insensitive, one space, the
    token as sent — `Bearer  x` is the token ` x`, refused later). Never the query string."""
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise MissingToken()
    return token


def authenticate(request: HttpRequest, scope: str, config: ConfigSource) -> AccessToken:
    """Config first (503 before the header is even looked at), then the header, then §3."""
    resolved = _resolve(config)
    return validate_access_token(
        bearer_token(request),
        issuer=resolved.issuer,
        audience=resolved.audience,
        required_scope=scope,
        jwks=resolved.jwks,
        clock=resolved.clock,
        extra_claims_hook=resolved.extra_claims_hook,
    )


def deny(
    request: HttpRequest,
    error: BearerError,
    *,
    resource_metadata_url: str,
    scope: str | None = None,
) -> HttpResponse:
    """§5 responses. 401 `{"error": "unauthorized"}` (+ `error="invalid_token"` unless the token
    was missing), 403 `{"error": "forbidden"}` with the scope (`scope` overrides the one in
    the exception), 503 `{"error": "auth_not_configured"}` without `WWW-Authenticate`."""
    if isinstance(error, AuthNotConfigured):
        logger.error("bearer auth is not configured: %s", error)
        return JsonResponse({"error": "auth_not_configured"}, status=503)
    if isinstance(error, InsufficientScope):
        response = JsonResponse({"error": "forbidden"}, status=403)
        response["WWW-Authenticate"] = www_authenticate(
            resource_metadata_url,
            error="insufficient_scope",
            scope=scope or error.required_scope,
        )
        return response
    if isinstance(error, TokenRejected):
        logger.info("bearer token rejected on %s: %s", request.path, error)
    response = JsonResponse({"error": "unauthorized"}, status=401)
    response["WWW-Authenticate"] = www_authenticate(
        resource_metadata_url,
        error="invalid_token" if isinstance(error, TokenRejected) else None,
    )
    return response


def _deny_for(request: HttpRequest, error: BearerError, config: ConfigSource) -> HttpResponse:
    if isinstance(error, AuthNotConfigured):
        return deny(request, error, resource_metadata_url="")
    url = (config() if callable(config) else config).resource_metadata_url
    return deny(request, error, resource_metadata_url=url)


def require_bearer[**P, R: HttpResponse](
    scope: str, *, config: ConfigSource
) -> Callable[
    [Callable[Concatenate[HttpRequest, AccessToken, P], R]],
    Callable[Concatenate[HttpRequest, P], HttpResponse],
]:
    """Django view decorator: the view runs as `view(request, token, *args, **kwargs)` with a
    verified `token`, which is also `request.access_token`; otherwise `deny(...)`."""

    def decorate(
        view: Callable[Concatenate[HttpRequest, AccessToken, P], R],
    ) -> Callable[Concatenate[HttpRequest, P], HttpResponse]:
        def wrapped(request: HttpRequest, /, *args: P.args, **kwargs: P.kwargs) -> HttpResponse:
            try:
                token = authenticate(request, scope, config)
            except (MissingToken, TokenRejected, InsufficientScope, AuthNotConfigured) as exc:
                return _deny_for(request, exc, config)
            request.access_token = token  # type: ignore[attr-defined]  # news reads it here
            return view(request, token, *args, **kwargs)

        functools.update_wrapper(wrapped, view)
        return wrapped

    return decorate


class BearerDenied(Exception):
    """Raised by `BearerAuth` with the finished response; `install_bearer_errors` returns it.
    `error` is the refusal (`MissingToken`, `TokenRejected`, …) for logs and tests."""

    def __init__(self, error: BearerError, response: HttpResponse) -> None:
        super().__init__(repr(error))
        self.error = error
        self.response = response


class BearerAuth(AuthBase):
    """django-ninja `auth=BearerAuth("admin", config=…)`. Needs `install_bearer_errors(api)`."""

    openapi_type = "http"
    openapi_scheme = "bearer"

    def __init__(self, scope: str, *, config: ConfigSource) -> None:
        self.scope = scope
        self.config = config
        super().__init__()

    def __call__(self, request: HttpRequest) -> AccessToken:
        try:
            return authenticate(request, self.scope, self.config)
        except (MissingToken, TokenRejected, InsufficientScope, AuthNotConfigured) as exc:
            raise BearerDenied(exc, _deny_for(request, exc, self.config)) from exc


def install_bearer_errors(api: NinjaAPI) -> None:
    """Register the handler that sends `BearerAuth` refusals as built (§5)."""

    # ninja's ExcHandler type also admits the class; it always passes the instance.
    def on_denied(request: HttpRequest, exc: BearerDenied | type[BearerDenied]) -> HttpResponse:
        if not isinstance(exc, BearerDenied):
            raise TypeError("ninja passed an exception class")
        return exc.response

    api.add_exception_handler(BearerDenied, on_denied)


def metadata_response(
    resource: str,
    authorization_server: str,
    scopes_supported: Sequence[str],
    *,
    resource_name: str | None = None,
) -> JsonResponse:
    """The §6 metadata as a response, readable cross-origin (MCP clients fetch it from the
    browser): `Access-Control-Allow-Origin: *`, as portfolio and metrics send it."""
    body = protected_resource_metadata(
        resource, authorization_server, scopes_supported, resource_name=resource_name
    )
    response = JsonResponse(body)
    response["Access-Control-Allow-Origin"] = "*"
    return response
