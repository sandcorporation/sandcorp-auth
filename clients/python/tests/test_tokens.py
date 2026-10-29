"""validate_access_token and JwksCache against docs/resource-server-token-validation.md §3–§4.

Cases carried over from the sites' suites: portfolio/metrics `tests/test_resource_auth.py`,
news `tests/test_token_validation.py`, flow `tests/test_resource_token.py`.
"""

import base64
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
import pytest
from conftest import (
    ISSUER,
    MEMBER,
    OWNER,
    RESOURCE,
    FakeJwks,
    FrozenClock,
    SigningKey,
    claims_at,
    sign,
)

from sandcorp_authkit.tokens import (
    AccessToken,
    ClaimsHook,
    InsufficientScope,
    JwksCache,
    SystemClock,
    TokenRejected,
    http_jwks_fetcher,
    owner_only,
    owner_or_member,
    validate_access_token,
)


def check(
    token: str,
    jwks: JwksCache,
    clock: FrozenClock,
    *,
    scope: str = "admin",
    hook: ClaimsHook | None = None,
) -> AccessToken:
    return validate_access_token(
        token,
        issuer=ISSUER,
        audience=RESOURCE,
        required_scope=scope,
        jwks=jwks,
        clock=clock,
        extra_claims_hook=hook,
    )


# --- passing tokens ---


def test_valid_token_passes(key: SigningKey, jwks: JwksCache, clock: FrozenClock) -> None:
    token = check(sign(key, claims_at(clock)), jwks, clock, hook=owner_only(OWNER))
    assert token.sub == OWNER
    assert token.scopes == {"admin", "login"}
    assert token.jti == "jti-1"
    assert token.exp == token.iat + 600
    assert token.acct is None


def test_without_a_hook_any_sub_passes(
    key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    token = check(sign(key, claims_at(clock, sub="someone", acct="member")), jwks, clock)
    assert token.sub == "someone"
    assert token.acct == "member"


def test_iat_and_nbf_in_the_future_are_not_compared(
    key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    now = int(clock.now().timestamp())
    token = sign(key, claims_at(clock, iat=now + 3600, nbf=now + 3600, exp=now + 4000))
    assert check(token, jwks, clock).sub == OWNER


def test_system_clock_is_aware() -> None:
    assert SystemClock().now().tzinfo is not None


# --- header and key (T1–T5) ---


@pytest.mark.parametrize("token", ["", "not-a-jwt", "a.b", "a.b.c", "x.y", "!!!.e30.sig"])
def test_malformed_token_is_rejected(token: str, jwks: JwksCache, clock: FrozenClock) -> None:
    with pytest.raises(TokenRejected):
        check(token, jwks, clock)


def _b64(data: object) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def test_alg_none_is_rejected(jwks: JwksCache, clock: FrozenClock) -> None:
    token = f"{_b64({'alg': 'none', 'kid': 'k1'})}.{_b64(claims_at(clock))}."
    with pytest.raises(TokenRejected):
        check(token, jwks, clock)


def test_hs256_signed_with_the_public_key_is_rejected(
    key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    secret = key.jwk()["x"].encode()
    token = jwt.encode(claims_at(clock), secret, algorithm="HS256", headers={"kid": "k1"})
    with pytest.raises(TokenRejected):
        check(token, jwks, clock)


def test_alg_header_says_eddsa_but_kid_missing(
    key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    with pytest.raises(TokenRejected):
        check(sign(key, claims_at(clock), headers={"typ": "JWT"}), jwks, clock)


def test_kid_that_is_not_a_string_is_rejected(
    key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    header = _b64({"alg": "EdDSA", "kid": 1})
    signing_input = f"{header}.{_b64(claims_at(clock))}"
    signature = base64.urlsafe_b64encode(key.private.sign(signing_input.encode()))
    with pytest.raises(TokenRejected):
        check(f"{signing_input}.{signature.rstrip(b'=').decode()}", jwks, clock)


def test_signature_by_another_key_with_the_same_kid_is_rejected(
    jwks: JwksCache, clock: FrozenClock
) -> None:
    impostor = SigningKey(kid="k1")
    with pytest.raises(TokenRejected):
        check(sign(impostor, claims_at(clock)), jwks, clock)


def test_tampered_payload_is_rejected(key: SigningKey, jwks: JwksCache, clock: FrozenClock) -> None:
    header, _, signature = sign(key, claims_at(clock)).split(".")
    forged = _b64(claims_at(clock, scope="admin login extra"))
    with pytest.raises(TokenRejected):
        check(f"{header}.{forged}.{signature}", jwks, clock)


# --- claims (T6–T10) ---


@pytest.mark.parametrize(
    "missing", ["iss", "sub", "aud", "client_id", "scope", "iat", "exp", "jti"]
)
def test_missing_required_claim_is_rejected(
    missing: str, key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    with pytest.raises(TokenRejected):
        check(sign(key, claims_at(clock, **{missing: ...})), jwks, clock)


@pytest.mark.parametrize(
    "overrides",
    [
        {"iat": "1700000000"},
        {"exp": 1.5e10},
        {"exp": True},
        {"iat": False},
        {"exp": "9999999999"},
        {"aud": [RESOURCE]},
        {"scope": ["admin"]},
        {"client_id": 7},
        {"sub": None},
        {"jti": 1},
    ],
)
def test_claim_with_the_wrong_type_is_rejected(
    overrides: dict[str, object], key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    with pytest.raises(TokenRejected):
        check(sign(key, claims_at(clock, **overrides)), jwks, clock)


@pytest.mark.parametrize(
    "iss",
    [
        "https://evil.example",
        ISSUER + "/",
        "https://AUTH.sandcorp.co.kr",
        "http://auth.sandcorp.co.kr",
    ],
)
def test_other_issuer_is_rejected(
    iss: str, key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    with pytest.raises(TokenRejected):
        check(sign(key, claims_at(clock, iss=iss)), jwks, clock)


@pytest.mark.parametrize(
    "aud",
    [
        "https://news.sandcorp.co.kr/mcp",
        RESOURCE + "/",
        "https://SANDCORP.co.kr/mcp",
        "https://sandcorp.co.kr",
    ],
)
def test_other_audience_is_rejected(
    aud: str, key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    with pytest.raises(TokenRejected):
        check(sign(key, claims_at(clock, aud=aud)), jwks, clock)


def test_expiry_allows_30_seconds_of_leeway_then_rejects(
    key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    token = sign(key, claims_at(clock))
    clock.advance(600 + 30)
    assert check(token, jwks, clock).sub == OWNER
    clock.advance(1)
    with pytest.raises(TokenRejected, match="expired"):
        check(token, jwks, clock)


# --- scope (S1) ---


@pytest.mark.parametrize(
    "scope", ["login", "administrator", "adminlogin", "", "admins", "Admin", "   "]
)
def test_missing_scope_is_forbidden_not_unauthorized(
    scope: str, key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    with pytest.raises(InsufficientScope) as raised:
        check(sign(key, claims_at(clock, scope=scope)), jwks, clock)
    assert raised.value.required_scope == "admin"


@pytest.mark.parametrize("scope", ["login  admin", "  login   admin "])
def test_scope_is_split_on_single_spaces_dropping_empty_pieces(
    scope: str, key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    assert check(sign(key, claims_at(clock, scope=scope)), jwks, clock).scopes == {"login", "admin"}


def test_rejection_beats_insufficient_scope(
    key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    token = sign(key, claims_at(clock, sub="stranger", scope="login"))
    with pytest.raises(TokenRejected):
        check(token, jwks, clock, hook=owner_only(OWNER))


# --- account hooks (T11, §10 A1–A3) ---


@pytest.mark.parametrize("sub", ["someone", "Farrar142", " farrar142", "farrar142 ", MEMBER])
def test_owner_only_rejects_other_subjects(
    sub: str, key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    with pytest.raises(TokenRejected):
        check(sign(key, claims_at(clock, sub=sub)), jwks, clock, hook=owner_only(OWNER))


def test_owner_only_rejects_a_token_with_acct(
    key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    token = sign(key, claims_at(clock, acct="owner"))
    with pytest.raises(TokenRejected):
        check(token, jwks, clock, hook=owner_only(OWNER))


@pytest.mark.parametrize("hook_factory", [owner_only, owner_or_member])
def test_empty_owner_sub_setting_rejects_every_owner_token(
    hook_factory: object, key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    assert callable(hook_factory)
    hook = hook_factory("")
    with pytest.raises(TokenRejected):
        check(sign(key, claims_at(clock, sub="")), jwks, clock, hook=hook)


def test_member_token_passes_the_account_rules(
    key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    token = sign(key, claims_at(clock, sub=MEMBER, acct="member", scope="login"))
    passed = check(token, jwks, clock, scope="login", hook=owner_or_member(OWNER))
    assert (passed.sub, passed.acct, passed.scopes) == (MEMBER, "member", frozenset({"login"}))


def test_owner_passes_owner_or_member(key: SigningKey, jwks: JwksCache, clock: FrozenClock) -> None:
    assert check(sign(key, claims_at(clock)), jwks, clock, hook=owner_or_member(OWNER)).sub == OWNER


def test_member_without_the_scope_is_insufficient(
    key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    token = sign(key, claims_at(clock, sub=MEMBER, acct="member", scope="login"))
    with pytest.raises(InsufficientScope):
        check(token, jwks, clock, hook=owner_or_member(OWNER))


@pytest.mark.parametrize("sub", [MEMBER, "Farrar142", " farrar142"])
def test_token_without_acct_must_have_the_owner_sub(
    sub: str, key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    with pytest.raises(TokenRejected):
        check(sign(key, claims_at(clock, sub=sub)), jwks, clock, hook=owner_or_member(OWNER))


@pytest.mark.parametrize("acct", ["owner", "Member", "MEMBER", "admin", "", 1, ["member"], None])
def test_acct_other_than_member_is_rejected(
    acct: object, key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    token = sign(key, claims_at(clock, sub=MEMBER, acct=acct))
    with pytest.raises(TokenRejected):
        check(token, jwks, clock, hook=owner_or_member(OWNER))


@pytest.mark.parametrize(
    "sub",
    [
        "m_01JB2Z3Y4X5W6V7T8S9R0Q1P2",  # 25 chars
        "m_01jb2z3y4x5w6v7t8s9r0q1p2n",  # lower case
        "m_81JB2Z3Y4X5W6V7T8S9R0Q1P2N",  # first char above 7
        "m_01JB2Z3Y4X5W6V7T8S9R0Q1P2I",  # I is not Crockford
        "01JB2Z3Y4X5W6V7T8S9R0Q1P2N",  # no prefix
        OWNER,
        MEMBER + "\n",
    ],
)
def test_member_token_needs_a_member_sub(
    sub: str, key: SigningKey, jwks: JwksCache, clock: FrozenClock
) -> None:
    token = sign(key, claims_at(clock, sub=sub, acct="member"))
    with pytest.raises(TokenRejected):
        check(token, jwks, clock, hook=owner_or_member(OWNER))


def test_hook_sees_read_only_claims(key: SigningKey, jwks: JwksCache, clock: FrozenClock) -> None:
    seen: list[object] = []

    def hook(claims: object) -> None:
        seen.append(claims)
        with pytest.raises(TypeError):
            claims["sub"] = "x"  # type: ignore[index]

    check(sign(key, claims_at(clock)), jwks, clock, hook=hook)
    assert len(seen) == 1


# --- JWKS cache (J1–J5) ---


def test_unknown_kid_refetches_jwks_once_then_passes(
    key: SigningKey, fake_jwks: FakeJwks, jwks: JwksCache, clock: FrozenClock
) -> None:
    check(sign(key, claims_at(clock)), jwks, clock)
    rotated = SigningKey(kid="k2")
    fake_jwks.serve(key, rotated)
    assert check(sign(rotated, claims_at(clock)), jwks, clock).sub == OWNER
    assert fake_jwks.fetches == 2


def test_unknown_kid_refetch_is_limited_to_once_per_60_seconds(
    key: SigningKey, fake_jwks: FakeJwks, jwks: JwksCache, clock: FrozenClock
) -> None:
    check(sign(key, claims_at(clock)), jwks, clock)
    stranger = sign(SigningKey(kid="nope"), claims_at(clock))
    with pytest.raises(TokenRejected, match="unknown kid"):
        check(stranger, jwks, clock)
    assert fake_jwks.fetches == 2  # first load + one refetch for the unknown kid
    clock.advance(59)
    with pytest.raises(TokenRejected):
        check(stranger, jwks, clock)
    assert fake_jwks.fetches == 2
    clock.advance(1)
    with pytest.raises(TokenRejected):
        check(stranger, jwks, clock)
    assert fake_jwks.fetches == 3


def test_jwks_is_refetched_after_the_10_minute_ttl(
    key: SigningKey, fake_jwks: FakeJwks, jwks: JwksCache, clock: FrozenClock
) -> None:
    check(sign(key, claims_at(clock)), jwks, clock)
    clock.advance(599)
    check(sign(key, claims_at(clock)), jwks, clock)
    assert fake_jwks.fetches == 1
    clock.advance(1)
    check(sign(key, claims_at(clock)), jwks, clock)
    assert fake_jwks.fetches == 2


def test_failed_jwks_fetch_keeps_the_cached_keys_and_waits_60_seconds(
    key: SigningKey, fake_jwks: FakeJwks, jwks: JwksCache, clock: FrozenClock
) -> None:
    check(sign(key, claims_at(clock)), jwks, clock)
    fake_jwks.failing = True
    clock.advance(600)
    assert check(sign(key, claims_at(clock)), jwks, clock).sub == OWNER
    assert fake_jwks.fetches == 2
    clock.advance(59)
    check(sign(key, claims_at(clock)), jwks, clock)
    assert fake_jwks.fetches == 2
    clock.advance(1)
    check(sign(key, claims_at(clock)), jwks, clock)
    assert fake_jwks.fetches == 3


def test_unreachable_jwks_with_an_empty_cache_rejects(
    key: SigningKey, fake_jwks: FakeJwks, jwks: JwksCache, clock: FrozenClock
) -> None:
    fake_jwks.failing = True
    with pytest.raises(TokenRejected):
        check(sign(key, claims_at(clock)), jwks, clock)


def test_key_dropped_from_jwks_is_dropped_from_the_cache(
    key: SigningKey, fake_jwks: FakeJwks, jwks: JwksCache, clock: FrozenClock
) -> None:
    check(sign(key, claims_at(clock)), jwks, clock)
    fake_jwks.serve(SigningKey(kid="k2"))
    clock.advance(600)
    with pytest.raises(TokenRejected):
        check(sign(key, claims_at(clock)), jwks, clock)


@pytest.mark.parametrize(
    ("change", "usable"),
    [
        ({"alg": "RS256"}, False),
        ({"use": "enc"}, False),
        ({"crv": "X25519"}, False),
        ({"kty": "EC"}, False),
        ({"kid": 5}, False),
        ({"x": "%%%"}, False),
        ({"alg": ..., "use": ...}, True),
    ],
)
def test_only_ed25519_signing_keys_are_used(
    change: dict[str, object],
    usable: bool,
    key: SigningKey,
    fake_jwks: FakeJwks,
    jwks: JwksCache,
    clock: FrozenClock,
) -> None:
    jwk: dict[str, object] = {**key.jwk(), **change}
    fake_jwks.document = {"keys": [{k: v for k, v in jwk.items() if v is not ...}]}
    if usable:
        check(sign(key, claims_at(clock)), jwks, clock)
    else:
        with pytest.raises(TokenRejected):
            check(sign(key, claims_at(clock)), jwks, clock)


@pytest.mark.parametrize("document", [[], {"keys": "x"}, {"nokeys": []}, "text", None])
def test_jwks_document_of_the_wrong_shape_is_a_failed_fetch(
    document: object, key: SigningKey, fake_jwks: FakeJwks, jwks: JwksCache, clock: FrozenClock
) -> None:
    check(sign(key, claims_at(clock)), jwks, clock)
    fake_jwks.document = document
    clock.advance(600)
    assert check(sign(key, claims_at(clock)), jwks, clock).sub == OWNER  # old keys kept


def test_concurrent_first_use_fetches_once(
    key: SigningKey, fake_jwks: FakeJwks, jwks: JwksCache
) -> None:
    barrier = threading.Barrier(8)
    found: list[bool] = []

    def worker() -> None:
        barrier.wait()
        found.append(jwks.key_for(key.kid) is not None)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert found == [True] * 8
    assert fake_jwks.fetches == 1


def test_cache_ttl_and_refetch_interval_are_settable(
    key: SigningKey, fake_jwks: FakeJwks, clock: FrozenClock
) -> None:
    jwks = JwksCache(fake_jwks, clock, ttl_seconds=10, min_refetch_seconds=5)
    check(sign(key, claims_at(clock)), jwks, clock)
    clock.advance(10)
    check(sign(key, claims_at(clock)), jwks, clock)
    assert fake_jwks.fetches == 2


# --- HTTP fetcher (loopback only) ---


@pytest.fixture
def jwks_server(key: SigningKey) -> Iterator[tuple[str, dict[str, tuple[int, bytes]]]]:
    routes: dict[str, tuple[int, bytes]] = {
        "/jwks": (200, json.dumps({"keys": [key.jwk()]}).encode()),
        "/error": (500, b"{}"),
        "/text": (200, b"<html>"),
        "/list": (200, b"[]"),
        "/huge": (200, b'{"keys": []' + b" " * 70_000 + b"}"),
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            status, body = routes.get(self.path, (404, b""))
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, args=(0.01,), daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", routes
    finally:
        server.shutdown()
        server.server_close()


def test_http_fetcher_reads_the_jwks(
    jwks_server: tuple[str, dict[str, tuple[int, bytes]]], key: SigningKey, clock: FrozenClock
) -> None:
    base, _ = jwks_server
    jwks = JwksCache(http_jwks_fetcher(base + "/jwks"), clock)
    assert check(sign(key, claims_at(clock)), jwks, clock).sub == OWNER


@pytest.mark.parametrize("path", ["/error", "/text", "/huge", "/missing"])
def test_http_fetcher_raises_on_bad_responses(
    path: str, jwks_server: tuple[str, dict[str, tuple[int, bytes]]]
) -> None:
    base, _ = jwks_server
    with pytest.raises(Exception):  # noqa: B017 - any failure is J4 for the cache
        http_jwks_fetcher(base + path)()


def test_http_fetcher_list_body_is_a_failed_fetch(
    jwks_server: tuple[str, dict[str, tuple[int, bytes]]], key: SigningKey, clock: FrozenClock
) -> None:
    base, _ = jwks_server
    jwks = JwksCache(http_jwks_fetcher(base + "/list"), clock)
    with pytest.raises(TokenRejected):
        check(sign(key, claims_at(clock)), jwks, clock)


def test_http_fetcher_refuses_other_schemes() -> None:
    with pytest.raises(ValueError):
        http_jwks_fetcher("file:///etc/passwd")
