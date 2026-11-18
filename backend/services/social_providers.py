"""Social login providers behind one Protocol (#36): Google (OpenID Connect), Kakao and GitHub
(#91, both OAuth 2.0). Each builds its authorization URL (state, PKCE S256, and for Google a
nonce) and turns the code from its callback into an `ExternalProfile`, refusing anything it
cannot trust (`SocialLoginFailed`).

Google's `id_token` is checked here, not trusted from the TLS channel alone: RS256 signature
against Google's JWKS, `aud` = our client id, `iss` = accounts.google.com, `exp` (with
`get_clock()`), and `nonce` = the one this login sent. Kakao's profile comes from its user API
with the access token (Kakao Login without OIDC); its email is optional and counts as verified
only when Kakao says it is both valid and verified. GitHub's profile is `/user` (provider_sub =
the numeric `id`; `login` can be renamed) and its email is the one `/user/emails` marks both
primary and verified, or none. GitHub supports PKCE (S256) on OAuth Apps, so it gets the same
challenge and verifier as Kakao; it has no OIDC, so no nonce.

All HTTP goes through `adapters.social_http` (a fake in tests). A provider whose client id or
secret is empty in settings is not configured: `configured_providers()` leaves it out, so its
button is hidden and its routes 404.
"""

import hmac
import json
from dataclasses import dataclass
from typing import Final, Protocol
from urllib.parse import urlencode

import jwt
from django.conf import settings

from adapters.clock import get_clock
from adapters.http import FetchedDocument, FetchError
from adapters.social_http import get_provider_http
from services.members import ExternalProfile

type JSONObject = dict[str, object]

GOOGLE: Final = "google"
KAKAO: Final = "kakao"
GITHUB: Final = "github"

GOOGLE_AUTHORIZE_URL: Final = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL: Final = "https://oauth2.googleapis.com/token"
GOOGLE_JWKS_URL: Final = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS: Final = frozenset({"https://accounts.google.com", "accounts.google.com"})
GOOGLE_SCOPE: Final = "openid email profile"

KAKAO_AUTHORIZE_URL: Final = "https://kauth.kakao.com/oauth/authorize"
KAKAO_TOKEN_URL: Final = "https://kauth.kakao.com/oauth/token"
KAKAO_USER_URL: Final = "https://kapi.kakao.com/v2/user/me"

GITHUB_AUTHORIZE_URL: Final = "https://github.com/login/oauth/authorize"
# The token answer is form-encoded unless asked for JSON: `social_http.post_form` always sends
# `Accept: application/json`. A bad code still answers 200, with `{"error": …}`.
GITHUB_TOKEN_URL: Final = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL: Final = "https://api.github.com/user"
GITHUB_EMAILS_URL: Final = "https://api.github.com/user/emails"
GITHUB_SCOPE: Final = "read:user user:email"
GITHUB_API_VERSION: Final = "2022-11-28"

# Clock skew allowed when checking `exp`.
LEEWAY_SECONDS: Final = 60


class SocialLoginFailed(Exception):
    """The provider's answer cannot be trusted or used. `reason` is a short code for the audit
    log (never a token or a code)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class AuthorizationRequest:
    redirect_uri: str
    state: str
    nonce: str
    code_challenge: str


class SocialProvider(Protocol):
    name: str
    label: str

    def authorization_url(self, request: AuthorizationRequest) -> str: ...

    def fetch_profile(
        self, *, code: str, redirect_uri: str, code_verifier: str, nonce: str
    ) -> ExternalProfile:
        """Exchange `code` and return who signed in. Raises SocialLoginFailed."""
        ...


def _json_value(document: FetchedDocument, what: str) -> object:
    if not 200 <= document.status < 300:
        raise SocialLoginFailed(f"{what}_status_{document.status}")
    try:
        value: object = json.loads(document.body)
    except ValueError as error:
        raise SocialLoginFailed(f"{what}_not_json") from error
    return value


def _json_object(document: FetchedDocument, what: str) -> JSONObject:
    value = _json_value(document, what)
    if not isinstance(value, dict):
        raise SocialLoginFailed(f"{what}_not_object")
    return value


def _post(url: str, data: dict[str, str], what: str) -> JSONObject:
    try:
        return _json_object(get_provider_http().post_form(url, data), what)
    except FetchError as error:
        raise SocialLoginFailed(f"{what}_unreachable") from error


def _fetch(url: str, headers: dict[str, str], what: str) -> FetchedDocument:
    try:
        return get_provider_http().get(url, headers=headers)
    except FetchError as error:
        raise SocialLoginFailed(f"{what}_unreachable") from error


def _get(url: str, headers: dict[str, str], what: str) -> JSONObject:
    return _json_object(_fetch(url, headers, what), what)


def _get_list(url: str, headers: dict[str, str], what: str) -> list[object]:
    value = _json_value(_fetch(url, headers, what), what)
    if not isinstance(value, list):
        raise SocialLoginFailed(f"{what}_not_list")
    return value


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


class GoogleProvider:
    name = GOOGLE
    label = "Google"

    def __init__(self, client_id: str, client_secret: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret

    def authorization_url(self, request: AuthorizationRequest) -> str:
        query = {
            "client_id": self.client_id,
            "redirect_uri": request.redirect_uri,
            "response_type": "code",
            "scope": GOOGLE_SCOPE,
            "state": request.state,
            "nonce": request.nonce,
            "code_challenge": request.code_challenge,
            "code_challenge_method": "S256",
            "prompt": "select_account",
        }
        return f"{GOOGLE_AUTHORIZE_URL}?{urlencode(query)}"

    def fetch_profile(
        self, *, code: str, redirect_uri: str, code_verifier: str, nonce: str
    ) -> ExternalProfile:
        answer = _post(
            GOOGLE_TOKEN_URL,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code_verifier": code_verifier,
            },
            "google_token",
        )
        id_token = answer.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise SocialLoginFailed("google_no_id_token")
        claims = self.verify_id_token(id_token, nonce=nonce)
        email = _text(claims.get("email"))
        return ExternalProfile(
            provider=GOOGLE,
            provider_sub=_text(claims.get("sub")),
            email=email,
            email_verified=bool(email) and claims.get("email_verified") is True,
            display_name=_text(claims.get("name")),
        )

    def verify_id_token(self, id_token: str, *, nonce: str) -> JSONObject:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as error:
            raise SocialLoginFailed("id_token_malformed") from error
        if header.get("alg") != "RS256":
            raise SocialLoginFailed("id_token_alg")
        key = self._signing_key(header.get("kid"))
        try:
            claims: JSONObject = jwt.decode(
                id_token,
                key,
                algorithms=["RS256"],
                audience=self.client_id,
                # exp is checked below against get_clock(); iss allows two spellings.
                options={
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                    "verify_iss": False,
                    "require": ["iss", "aud", "exp", "sub"],
                },
            )
        except jwt.InvalidAudienceError as error:
            raise SocialLoginFailed("id_token_aud") from error
        except jwt.PyJWTError as error:
            raise SocialLoginFailed("id_token_invalid") from error
        if claims.get("iss") not in GOOGLE_ISSUERS:
            raise SocialLoginFailed("id_token_iss")
        exp = claims.get("exp")
        now = get_clock().now().timestamp()
        if not isinstance(exp, int | float) or exp + LEEWAY_SECONDS <= now:
            raise SocialLoginFailed("id_token_expired")
        sent = claims.get("nonce")
        if not nonce or not isinstance(sent, str) or not hmac.compare_digest(sent, nonce):
            raise SocialLoginFailed("id_token_nonce")
        if not _text(claims.get("sub")):
            raise SocialLoginFailed("id_token_sub")
        return claims

    def _signing_key(self, kid: object) -> jwt.PyJWK:
        jwks = _get(GOOGLE_JWKS_URL, {}, "google_jwks")
        try:
            key_set = jwt.PyJWKSet.from_dict(jwks)
        except jwt.PyJWTError as error:
            raise SocialLoginFailed("google_jwks_invalid") from error
        for key in key_set.keys:
            if key.key_id == kid:
                return key
        raise SocialLoginFailed("id_token_unknown_kid")


class KakaoProvider:
    name = KAKAO
    label = "Kakao"

    def __init__(self, client_id: str, client_secret: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret

    def authorization_url(self, request: AuthorizationRequest) -> str:
        query = {
            "client_id": self.client_id,
            "redirect_uri": request.redirect_uri,
            "response_type": "code",
            "state": request.state,
            "code_challenge": request.code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{KAKAO_AUTHORIZE_URL}?{urlencode(query)}"

    def fetch_profile(
        self, *, code: str, redirect_uri: str, code_verifier: str, nonce: str
    ) -> ExternalProfile:
        answer = _post(
            KAKAO_TOKEN_URL,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code_verifier": code_verifier,
            },
            "kakao_token",
        )
        access_token = answer.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise SocialLoginFailed("kakao_no_access_token")
        user = _get(KAKAO_USER_URL, {"Authorization": f"Bearer {access_token}"}, "kakao_user")
        kakao_id = user.get("id")
        if isinstance(kakao_id, bool) or not isinstance(kakao_id, int | str) or not str(kakao_id):
            raise SocialLoginFailed("kakao_no_id")
        account = user.get("kakao_account")
        account = account if isinstance(account, dict) else {}
        profile = account.get("profile")
        profile = profile if isinstance(profile, dict) else {}
        email = _text(account.get("email"))
        verified = (
            account.get("is_email_valid") is True and account.get("is_email_verified") is True
        )
        return ExternalProfile(
            provider=KAKAO,
            provider_sub=str(kakao_id),
            email=email,
            email_verified=bool(email) and verified,
            display_name=_text(profile.get("nickname")),
        )


class GitHubProvider:
    name = GITHUB
    label = "GitHub"

    def __init__(self, client_id: str, client_secret: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret

    def authorization_url(self, request: AuthorizationRequest) -> str:
        query = {
            "client_id": self.client_id,
            "redirect_uri": request.redirect_uri,
            "scope": GITHUB_SCOPE,
            "state": request.state,
            "code_challenge": request.code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{GITHUB_AUTHORIZE_URL}?{urlencode(query)}"

    def fetch_profile(
        self, *, code: str, redirect_uri: str, code_verifier: str, nonce: str
    ) -> ExternalProfile:
        answer = _post(
            GITHUB_TOKEN_URL,
            {
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code_verifier": code_verifier,
            },
            "github_token",
        )
        access_token = answer.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise SocialLoginFailed("github_no_access_token")
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "User-Agent": "sandcorp-auth",  # the GitHub API refuses requests without one
        }
        user = _get(GITHUB_USER_URL, headers, "github_user")
        github_id = user.get("id")
        if isinstance(github_id, bool) or not isinstance(github_id, int):
            raise SocialLoginFailed("github_no_id")
        emails = _get_list(GITHUB_EMAILS_URL, headers, "github_emails")
        email = next(
            (
                _text(entry.get("email"))
                for entry in emails
                if isinstance(entry, dict)
                and entry.get("primary") is True
                and entry.get("verified") is True
            ),
            "",
        )
        return ExternalProfile(
            provider=GITHUB,
            provider_sub=str(github_id),
            email=email,
            email_verified=bool(email),
            display_name=_text(user.get("name")) or _text(user.get("login")),
        )


def configured_providers() -> dict[str, SocialProvider]:
    """The providers whose client id and secret are both set, in button order."""
    providers: dict[str, SocialProvider] = {}
    if settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET:
        providers[GOOGLE] = GoogleProvider(settings.GOOGLE_CLIENT_ID, settings.GOOGLE_CLIENT_SECRET)
    if settings.KAKAO_CLIENT_ID and settings.KAKAO_CLIENT_SECRET:
        providers[KAKAO] = KakaoProvider(settings.KAKAO_CLIENT_ID, settings.KAKAO_CLIENT_SECRET)
    if settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET:
        providers[GITHUB] = GitHubProvider(settings.GITHUB_CLIENT_ID, settings.GITHUB_CLIENT_SECRET)
    return providers
