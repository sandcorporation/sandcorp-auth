"""Operator login (docs/resource-server-token-validation.md §7, §10) against the fake
sandcorp-auth in `sandcorp_authkit.testing`.

Cases carried over from portfolio/metrics `tests/test_admin_oauth.py`, news
`tests/test_admin_login.py` and flow `tests/test_operator_login.py`.
"""

import base64
import json
import re
import threading
import urllib.parse
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from conftest import ISSUER, OWNER, START

from sandcorp_authkit.login import (
    ATTEMPT_MAX_AGE_SECONDS,
    LoginAttempt,
    LoginConfig,
    LoginRejected,
    LoginResult,
    SessionAttemptStore,
    TokenExchangeFailed,
    TokenRequest,
    TransportResponse,
    code_challenge,
    complete_login,
    exchange_code,
    start_login,
    urllib_transport,
)
from sandcorp_authkit.testing import (
    MEMBER_SUB,
    FakeJwks,
    FakeTokenEndpoint,
    FixedClock,
    SigningKey,
)
from sandcorp_authkit.tokens import ClaimsHook, JwksCache, owner_only, owner_or_member

RESOURCE = "https://news.sandcorp.co.kr/mcp"
CLIENT_ID = "news-admin"
SECRET = "news-admin-secret"


def make_config(**overrides: str) -> LoginConfig:
    values = {
        "client_id": CLIENT_ID,
        "client_secret": SECRET,
        "redirect_uri": "https://news.sandcorp.co.kr/auth/callback",
        "authorize_url": f"{ISSUER}/authorize",
        "token_url": f"{ISSUER}/token",
        "issuer": ISSUER,
        "resource": RESOURCE,
        "scope": "openid profile email login admin",
    }
    values.update(overrides)
    return LoginConfig(**values)


class Login:
    """One site: config + session store + the fake auth server, sharing one clock."""

    def __init__(self, config: LoginConfig | None = None) -> None:
        self.clock = FixedClock(START)
        self.fake_jwks = FakeJwks(SigningKey("k1"))
        self.jwks = JwksCache(self.fake_jwks, self.clock)
        self.server = FakeTokenEndpoint(
            self.fake_jwks, self.clock, client_id=CLIENT_ID, client_secret=SECRET
        )
        self.config = config or make_config()
        self.session: dict[str, object] = {}
        self.store = SessionAttemptStore(self.session)

    def start(self, **extra: str) -> str:
        return start_login(self.config, self.store, clock=self.clock, extra=extra)

    def complete(
        self,
        query: dict[str, str],
        *,
        required_scope: str = "login",
        extra_claims_hook: ClaimsHook | None = None,
    ) -> LoginResult:
        return complete_login(
            query,
            self.config,
            self.store,
            jwks=self.jwks,
            clock=self.clock,
            transport=self.server,
            required_scope=required_scope,
            extra_claims_hook=extra_claims_hook,
        )

    def refused(
        self,
        query: dict[str, str],
        *,
        required_scope: str = "login",
        extra_claims_hook: ClaimsHook | None = None,
    ) -> str:
        with pytest.raises(LoginRejected) as caught:
            self.complete(query, required_scope=required_scope, extra_claims_hook=extra_claims_hook)
        return caught.value.reason


@pytest.fixture
def login() -> Login:
    return Login()


def params(url: str) -> dict[str, str]:
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))


# ── start ──


def test_start_redirects_to_authorize_with_pkce_state_nonce_and_resource(login: Login) -> None:
    url = login.start()
    assert url.startswith(f"{ISSUER}/authorize?")
    query = params(url)
    attempt = LoginAttempt.from_dict(login.session["sandcorp_authkit.login"])
    assert attempt is not None
    assert query == {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": "https://news.sandcorp.co.kr/auth/callback",
        "scope": "openid profile email login admin",
        "resource": RESOURCE,
        "state": attempt.state,
        "nonce": attempt.nonce,
        "code_challenge": code_challenge(attempt.code_verifier),
        "code_challenge_method": "S256",
    }
    assert 43 <= len(attempt.code_verifier) <= 128
    assert attempt.code_verifier not in url
    assert attempt.started_at == int(START.timestamp())


def test_code_challenge_is_rfc7636_s256() -> None:
    # RFC 7636 appendix B
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert code_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_each_attempt_gets_fresh_state_verifier_and_nonce(login: Login) -> None:
    first, second = params(login.start()), params(login.start())
    for name in ("state", "nonce", "code_challenge"):
        assert first[name] != second[name]


def test_incomplete_config_refuses_to_start_and_to_finish() -> None:
    for blank in ("client_id", "client_secret", "redirect_uri", "issuer", "resource"):
        site = Login(make_config(**{blank: ""}))
        with pytest.raises(LoginRejected) as caught:
            site.start()
        assert caught.value.reason == "config"
        assert site.session == {}
        assert site.refused({"state": "x", "code": "y"}) == "config"


# ── the happy paths ──


def test_owner_signs_in(login: Login) -> None:
    result = login.complete(login.server.approve(login.start(next="/admin/")))
    assert result.access.sub == OWNER
    assert result.access.acct is None
    assert "admin" in result.access.scopes
    assert result.identity == {"sub": OWNER}
    assert result.extra == {"next": "/admin/"}
    assert login.session == {}  # the attempt is used up


def test_identity_carries_profile_claims(login: Login) -> None:
    query = login.server.approve(
        login.start(),
        id_token_overrides={"name": "대표", "email": "o@sandcorp.co.kr", "email_verified": True},
    )
    assert login.complete(query).identity == {
        "sub": OWNER,
        "name": "대표",
        "email": "o@sandcorp.co.kr",
        "email_verified": True,
    }


def test_member_signs_in_with_owner_or_member_hook(login: Login) -> None:
    query = login.server.approve_member(login.start(), scope="openid login")
    result = login.complete(query, extra_claims_hook=owner_or_member(OWNER))
    assert (result.access.sub, result.access.acct) == (MEMBER_SUB, "member")
    assert result.identity == {"sub": MEMBER_SUB}


def test_login_scope_only_site_needs_no_id_token() -> None:
    site = Login(make_config(scope="login"))
    result = site.complete(site.server.approve(site.start()), extra_claims_hook=owner_only(OWNER))
    assert result.identity is None
    assert site.server.requests[0].form["grant_type"] == "authorization_code"


def test_token_request_is_client_secret_basic_with_pkce(login: Login) -> None:
    login.complete(login.server.approve(login.start()))
    (request,) = login.server.requests
    assert request.url == f"{ISSUER}/token"
    assert request.timeout == 5.0 and request.max_bytes == 64 * 1024
    assert base64.b64decode(request.headers["Authorization"].removeprefix("Basic ")) == (
        f"{CLIENT_ID}:{SECRET}".encode()
    )
    assert request.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert set(request.form) == {"grant_type", "code", "redirect_uri", "code_verifier"}
    assert "client_secret" not in request.body.decode()


def test_basic_credentials_are_percent_encoded() -> None:
    config = make_config(client_id="a b:c", client_secret="p+w/=")
    sent: list[TokenRequest] = []

    def transport(request: TokenRequest) -> TransportResponse:
        sent.append(request)
        return TransportResponse(200, b'{"access_token": "t", "token_type": "Bearer"}')

    exchange_code(config, code="c", code_verifier="v", transport=transport)
    raw = base64.b64decode(sent[0].headers["Authorization"].removeprefix("Basic ")).decode()
    assert raw == "a%20b%3Ac:p%2Bw%2F%3D"


# ── the callback ──


def test_state_mismatch_is_refused_before_the_code_is_used(login: Login) -> None:
    query = login.server.approve(login.start())
    assert login.refused({**query, "state": "forged"}) == "state"
    assert login.server.requests == []
    assert login.session == {}  # a wrong state burns the attempt too


def test_callback_without_start_or_replayed_is_refused(login: Login) -> None:
    assert login.refused({"state": "s", "code": "c"}) == "state"
    query = login.server.approve(login.start())
    login.complete(query)
    assert login.refused(query) == "state"


def test_a_newer_start_replaces_the_older_attempt(login: Login) -> None:
    old = login.server.approve(login.start())
    login.start()
    assert login.refused(old) == "state"


def test_expired_attempt_is_refused(login: Login) -> None:
    query = login.server.approve(login.start())
    login.clock.advance(ATTEMPT_MAX_AGE_SECONDS + 1)
    assert login.refused(query) == "expired"
    assert login.server.requests == []


def test_attempt_at_exactly_600_seconds_still_works(login: Login) -> None:
    query = login.server.approve(login.start())
    login.clock.advance(ATTEMPT_MAX_AGE_SECONDS)
    # the tokens are minted at exchange time by the fake, so they are fresh
    assert login.complete(query).access.sub == OWNER


def test_authorization_error_is_refused(login: Login) -> None:
    assert login.refused(login.server.deny(login.start())) == "denied"
    assert login.server.requests == []


def test_missing_code_is_refused(login: Login) -> None:
    state = params(login.start())["state"]
    assert login.refused({"state": state}) == "exchange"


def test_tampered_or_foreign_attempt_in_the_session_is_refused(login: Login) -> None:
    query = login.server.approve(login.start())
    login.session["sandcorp_authkit.login"] = {"state": query["state"], "code_verifier": 1}
    assert login.refused(query) == "state"
    assert LoginAttempt.from_dict("nope") is None
    assert (
        LoginAttempt.from_dict(
            {"state": "s", "code_verifier": "v", "nonce": "n", "started_at": True}
        )
        is None
    )


# ── PKCE and the token endpoint ──


def test_code_injected_into_another_attempt_fails_pkce(login: Login) -> None:
    stolen = login.server.approve(login.start())  # someone else's code
    mine = params(login.start())
    assert login.refused({"state": mine["state"], "code": stolen["code"]}) == "exchange"


def test_code_cannot_be_used_twice(login: Login) -> None:
    query = login.server.approve(login.start())
    login.complete(query)
    attempt_state = params(login.start())["state"]
    assert login.refused({"state": attempt_state, "code": query["code"]}) == "exchange"


def test_wrong_client_secret_fails_the_exchange() -> None:
    site = Login(make_config(client_secret="wrong"))
    assert site.refused(site.server.approve(site.start())) == "exchange"


def test_redirect_uri_mismatch_fails_the_exchange(login: Login) -> None:
    query = login.server.approve(login.start())
    login.config = make_config(redirect_uri="https://news.sandcorp.co.kr/auth/callback/")
    assert login.refused(query) == "exchange"


@pytest.mark.parametrize(
    ("status", "body", "message"),
    [
        (400, b'{"error": "invalid_grant"}', "400: invalid_grant"),
        (500, b"<html>oops</html>", "500: (no JSON body)"),
        (200, b"not json", "not JSON"),
        (200, b"[1]", "not an object"),
        (200, b'{"token_type": "Bearer"}', "no access_token"),
        (200, b'{"access_token": "", "token_type": "Bearer"}', "no access_token"),
        (200, b'{"access_token": "t"}', "not Bearer"),
        (200, b'{"access_token": "t", "token_type": "mac"}', "not Bearer"),
        (200, b'{"access_token": "t", "token_type": "Bearer", "id_token": 3}', "id_token"),
        (200, b"\xff\xfe", "not JSON"),
    ],
)
def test_bad_token_responses_fail(status: int, body: bytes, message: str) -> None:
    with pytest.raises(TokenExchangeFailed, match=re.escape(message)):
        exchange_code(
            make_config(),
            code="c",
            code_verifier="v",
            transport=lambda _: TransportResponse(status, body),
        )


def test_token_response_over_64kb_fails() -> None:
    big = json.dumps({"access_token": "t", "token_type": "Bearer", "pad": "x" * 65536}).encode()
    with pytest.raises(TokenExchangeFailed, match="too large"):
        exchange_code(
            make_config(),
            code="c",
            code_verifier="v",
            transport=lambda _: TransportResponse(200, big),
        )
    exact = b'{"access_token": "t", "token_type": "bearer"}'
    response = exchange_code(
        make_config(),
        code="c",
        code_verifier="v",
        max_bytes=len(exact),
        transport=lambda _: TransportResponse(200, exact),
    )
    assert response == {"access_token": "t", "token_type": "bearer"}


@pytest.mark.parametrize("error", [TimeoutError("slow"), ConnectionRefusedError("down")])
def test_network_errors_fail_the_exchange(login: Login, error: OSError) -> None:
    query = login.server.approve(login.start())
    login.server.fail(error)
    assert login.refused(query) == "exchange"


def test_server_error_status_fails_the_login(login: Login) -> None:
    query = login.server.approve(login.start())
    login.server.respond(503, {"error": "temporarily_unavailable"})
    assert login.refused(query) == "exchange"


# ── the access token ──


def test_access_token_without_login_scope_is_refused(login: Login) -> None:
    query = login.server.approve(login.start(), scope="openid admin")
    assert login.refused(query) == "token"


def test_required_scope_is_the_sites_choice(login: Login) -> None:
    query = login.server.approve(login.start(), scope="openid login")
    assert login.refused(query, required_scope="admin") == "token"


def test_someone_else_is_refused_by_the_owner_hook(login: Login) -> None:
    query = login.server.approve(login.start(), sub="intruder")
    assert login.refused(query, extra_claims_hook=owner_only(OWNER)) == "token"


def test_member_is_refused_by_owner_only(login: Login) -> None:
    query = login.server.approve_member(login.start(), scope="openid login")
    assert login.refused(query, extra_claims_hook=owner_only(OWNER)) == "token"


def test_access_token_of_another_client_is_refused(login: Login) -> None:
    query = login.server.approve(login.start(), access_overrides={"client_id": "other"})
    assert login.refused(query) == "token"


def test_access_token_for_another_resource_is_refused(login: Login) -> None:
    query = login.server.approve(login.start(), access_overrides={"aud": "https://x/mcp"})
    assert login.refused(query) == "token"


def test_token_signed_by_an_unpublished_key_is_refused(login: Login) -> None:
    query = login.server.approve(login.start())
    login.fake_jwks.key = SigningKey("k1")  # same kid, different key
    assert login.refused(query) == "token"


# ── the ID token (§10) ──


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://evil.example"},
        {"aud": "other-client"},
        {"aud": [CLIENT_ID]},
        {"azp": "other-client"},
        {"nonce": "replayed"},
        {"nonce": None},
        {"nonce": 7},
        {"sub": "someone-else"},
        {"acct": "member"},
        {"exp": int(START.timestamp()) - 31},
        {"exp": None},
        {"iat": None},
        {"iat": True},
        {"exp": "soon"},
        {"iss": None},
        {"sub": None},
    ],
    ids=lambda o: ",".join(f"{k}={v}" for k, v in o.items()),
)
def test_bad_id_token_is_refused(login: Login, overrides: dict[str, object]) -> None:
    query = login.server.approve(login.start(), id_token_overrides=overrides)
    assert login.refused(query) == "token"


def test_id_token_exp_has_30_seconds_of_leeway(login: Login) -> None:
    query = login.server.approve(
        login.start(), id_token_overrides={"exp": int(START.timestamp()) - 30}
    )
    assert login.complete(query).identity == {"sub": OWNER}


def test_id_token_azp_equal_to_the_client_passes(login: Login) -> None:
    query = login.server.approve(login.start(), id_token_overrides={"azp": CLIENT_ID})
    assert login.complete(query).identity == {"sub": OWNER}


def test_member_id_token_without_acct_is_refused(login: Login) -> None:
    query = login.server.approve_member(login.start(), scope="openid login")
    login.server.codes[query["code"]].id_token_overrides["acct"] = None
    assert login.refused(query, extra_claims_hook=owner_or_member(OWNER)) == "token"


def test_openid_without_id_token_is_refused(login: Login) -> None:
    query = login.server.approve(login.start(), scope="login admin")  # granted without openid
    assert login.refused(query) == "token"


def test_unasked_id_token_is_still_verified() -> None:
    site = Login(make_config(scope="login"))
    query = site.server.approve(
        site.start(), scope="openid login", id_token_overrides={"nonce": "x"}
    )
    assert site.refused(query) == "token"


def test_id_token_with_bad_header_is_refused(login: Login) -> None:
    start = login.start()
    nonce = params(start)["nonce"]
    good = login.server.approve(start)
    token = login.fake_jwks.issue_id_token(
        login.clock,
        client_id=CLIENT_ID,
        nonce=nonce,
        headers={"typ": "JWT"},  # no kid
    )
    replies = {
        "access_token": login.fake_jwks.issue_access_token(
            login.clock, audience=RESOURCE, client_id=CLIENT_ID
        ),
        "token_type": "Bearer",
        "id_token": token,
    }
    login.server.respond(200, replies)
    assert login.refused(good) == "token"


# ── the default urllib transport against a local server ──


class _TokenHandler(BaseHTTPRequestHandler):
    replies: dict[str, tuple[int, bytes, dict[str, str]]] = {}
    seen: list[tuple[str, dict[str, str], bytes]] = []

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.seen.append((self.path, dict(self.headers), body))
        status, payload, headers = self.replies[self.path]
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def token_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TokenHandler)
    thread = threading.Thread(target=server.serve_forever, args=(0.01,), daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        _TokenHandler.seen.clear()


def test_urllib_transport_posts_the_form(token_server: str) -> None:
    ok = b'{"access_token": "t", "token_type": "Bearer", "scope": "login"}'
    _TokenHandler.replies = {"/token": (200, ok, {"Content-Type": "application/json"})}
    response = exchange_code(
        make_config(token_url=f"{token_server}/token"), code="c", code_verifier="v"
    )
    assert response == {"access_token": "t", "token_type": "Bearer", "scope": "login"}
    path, headers, body = _TokenHandler.seen[0]
    assert headers["Authorization"].startswith("Basic ")
    assert urllib.parse.parse_qs(body.decode())["code_verifier"] == ["v"]


def test_urllib_transport_returns_error_statuses_and_does_not_follow_redirects(
    token_server: str,
) -> None:
    _TokenHandler.replies = {
        "/bad": (400, b'{"error": "invalid_grant"}', {}),
        "/moved": (307, b"", {"Location": f"{token_server}/bad"}),
    }
    request = TokenRequest(f"{token_server}/bad", {}, {"a": "b"}, 5.0, 1024)
    assert urllib_transport(request) == TransportResponse(400, b'{"error": "invalid_grant"}')
    moved = TokenRequest(f"{token_server}/moved", {}, {"a": "b"}, 5.0, 1024)
    assert urllib_transport(moved).status == 307
    assert [seen[0] for seen in _TokenHandler.seen] == ["/bad", "/moved"]


def test_urllib_transport_unreachable_is_exchange_failure() -> None:
    config = make_config(token_url="http://127.0.0.1:9/token")
    with pytest.raises(TokenExchangeFailed, match="unreachable"):
        exchange_code(config, code="c", code_verifier="v", timeout=1.0)


def test_unusable_token_url_is_exchange_failure() -> None:
    with pytest.raises(TokenExchangeFailed, match="unreachable"):
        exchange_code(make_config(token_url="ftp-ish:nowhere"), code="c", code_verifier="v")
