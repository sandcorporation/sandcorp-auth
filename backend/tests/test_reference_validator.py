"""Reference validator tests: the rules in docs/resource-server-token-validation.md, run on a
frozen clock with locally generated Ed25519 keys (no network, no Django)."""

import base64
from dataclasses import dataclass, field

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tests.conftest import FrozenClock
from tests.reference_validator import (
    ISSUER,
    AccessToken,
    InsufficientScope,
    Jwk,
    JwksCache,
    JwkSet,
    TokenRejected,
    validate_access_token,
    validate_account_access_token,
    www_authenticate,
)

NEWS = "https://news.sandcorp.co.kr/mcp"
PORTFOLIO = "https://sandcorp.co.kr/mcp"
OWNER = "owner"


def public_jwk(private_key: Ed25519PrivateKey, kid: str) -> Jwk:
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid, "alg": "EdDSA", "use": "sig"}


@dataclass
class FakeJwksEndpoint:
    """Serves whatever keys the test puts in `keys` and counts fetches."""

    keys: list[Jwk] = field(default_factory=list)
    fetches: int = 0

    def __call__(self) -> JwkSet:
        self.fetches += 1
        return {"keys": list(self.keys)}


@dataclass
class Signer:
    private_key: Ed25519PrivateKey
    kid: str
    clock: FrozenClock

    def token(self, **overrides: object) -> str:
        now = int(self.clock.now().timestamp())
        claims: dict[str, object] = {
            "iss": ISSUER,
            "sub": OWNER,
            "aud": NEWS,
            "client_id": "client-123",
            "scope": "admin editor",
            "iat": now,
            "exp": now + 600,
            "jti": "jti-1",
        }
        for name, value in overrides.items():
            if value is None:
                claims.pop(name, None)
            else:
                claims[name] = value
        return jwt.encode(claims, self.private_key, algorithm="EdDSA", headers={"kid": self.kid})


@pytest.fixture
def signer(frozen_clock: FrozenClock) -> Signer:
    return Signer(Ed25519PrivateKey.generate(), "key-a", frozen_clock)


@pytest.fixture
def endpoint(signer: Signer) -> FakeJwksEndpoint:
    return FakeJwksEndpoint([public_jwk(signer.private_key, signer.kid)])


@pytest.fixture
def cache(endpoint: FakeJwksEndpoint, frozen_clock: FrozenClock) -> JwksCache:
    return JwksCache(endpoint, frozen_clock)


def validate(
    token: str, cache: JwksCache, clock: FrozenClock, *, audience: str = NEWS, scope: str = "admin"
) -> AccessToken:
    return validate_access_token(
        token, jwks=cache, audience=audience, owner_sub=OWNER, required_scope=scope, clock=clock
    )


def test_valid_token_passes(signer: Signer, cache: JwksCache, frozen_clock: FrozenClock) -> None:
    token = validate(signer.token(), cache, frozen_clock, scope="editor")

    assert token.sub == OWNER
    assert token.client_id == "client-123"
    assert token.scopes == frozenset({"admin", "editor"})
    assert token.jti == "jti-1"


def test_other_audience_is_rejected(
    signer: Signer, cache: JwksCache, frozen_clock: FrozenClock
) -> None:
    with pytest.raises(TokenRejected):
        validate(signer.token(aud=PORTFOLIO), cache, frozen_clock)
    with pytest.raises(TokenRejected):
        validate(signer.token(aud=[NEWS]), cache, frozen_clock)
    with pytest.raises(TokenRejected):
        validate(signer.token(aud=NEWS + "/"), cache, frozen_clock)


def test_other_issuer_is_rejected(
    signer: Signer, cache: JwksCache, frozen_clock: FrozenClock
) -> None:
    with pytest.raises(TokenRejected):
        validate(signer.token(iss="https://evil.example"), cache, frozen_clock)


def test_expiry_allows_30_seconds_of_leeway_then_rejects(
    signer: Signer, cache: JwksCache, frozen_clock: FrozenClock
) -> None:
    token = signer.token()

    frozen_clock.advance(600 + 30)
    validate(token, cache, frozen_clock)

    frozen_clock.advance(1)
    with pytest.raises(TokenRejected):
        validate(token, cache, frozen_clock)


def test_token_is_rejected_eleven_minutes_later(
    signer: Signer, cache: JwksCache, frozen_clock: FrozenClock
) -> None:
    token = signer.token()
    frozen_clock.advance(11 * 60)

    with pytest.raises(TokenRejected):
        validate(token, cache, frozen_clock)


def test_signature_by_another_key_with_the_same_kid_is_rejected(
    signer: Signer, cache: JwksCache, frozen_clock: FrozenClock
) -> None:
    impostor = Signer(Ed25519PrivateKey.generate(), signer.kid, frozen_clock)

    with pytest.raises(TokenRejected):
        validate(impostor.token(), cache, frozen_clock)


def test_hs256_signed_with_the_public_key_is_rejected(
    signer: Signer, endpoint: FakeJwksEndpoint, cache: JwksCache, frozen_clock: FrozenClock
) -> None:
    secret = endpoint.keys[0]["x"]
    forged = jwt.encode(
        jwt.decode(signer.token(), options={"verify_signature": False}),
        secret,
        algorithm="HS256",
        headers={"kid": signer.kid},
    )

    with pytest.raises(TokenRejected):
        validate(forged, cache, frozen_clock)


def test_alg_none_is_rejected(signer: Signer, cache: JwksCache, frozen_clock: FrozenClock) -> None:
    header, payload, _ = signer.token().split(".")
    none_header = base64.urlsafe_b64encode(b'{"alg":"none","kid":"key-a"}').rstrip(b"=").decode()
    assert header != none_header

    with pytest.raises(TokenRejected):
        validate(f"{none_header}.{payload}.", cache, frozen_clock)


def test_missing_required_claims_are_rejected(
    signer: Signer, cache: JwksCache, frozen_clock: FrozenClock
) -> None:
    for claim in ("iss", "sub", "aud", "client_id", "scope", "iat", "exp", "jti"):
        with pytest.raises(TokenRejected):
            validate(signer.token(**{claim: None}), cache, frozen_clock)


def test_subject_other_than_the_owner_is_rejected(
    signer: Signer, cache: JwksCache, frozen_clock: FrozenClock
) -> None:
    with pytest.raises(TokenRejected):
        validate(signer.token(sub="someone-else"), cache, frozen_clock)


def test_missing_scope_is_forbidden_not_unauthorized(
    signer: Signer, cache: JwksCache, frozen_clock: FrozenClock
) -> None:
    with pytest.raises(InsufficientScope) as raised:
        validate(signer.token(scope="editor"), cache, frozen_clock, scope="admin")

    assert raised.value.required_scope == "admin"
    with pytest.raises(InsufficientScope):
        validate(signer.token(scope="administrator"), cache, frozen_clock, scope="admin")


def test_unknown_kid_refetches_jwks_once_then_passes(
    signer: Signer, endpoint: FakeJwksEndpoint, cache: JwksCache, frozen_clock: FrozenClock
) -> None:
    validate(signer.token(), cache, frozen_clock)
    assert endpoint.fetches == 1

    rotated = Signer(Ed25519PrivateKey.generate(), "key-b", frozen_clock)
    endpoint.keys.append(public_jwk(rotated.private_key, rotated.kid))

    validate(rotated.token(), cache, frozen_clock)
    assert endpoint.fetches == 2


def test_unknown_kid_refetch_is_limited_to_once_per_60_seconds(
    signer: Signer, endpoint: FakeJwksEndpoint, cache: JwksCache, frozen_clock: FrozenClock
) -> None:
    validate(signer.token(), cache, frozen_clock)
    assert endpoint.fetches == 1

    stranger = Signer(Ed25519PrivateKey.generate(), "key-x", frozen_clock)
    for _ in range(3):
        with pytest.raises(TokenRejected):
            validate(stranger.token(), cache, frozen_clock)
    assert endpoint.fetches == 2

    frozen_clock.advance(59)
    with pytest.raises(TokenRejected):
        validate(stranger.token(), cache, frozen_clock)
    assert endpoint.fetches == 2

    frozen_clock.advance(1)
    with pytest.raises(TokenRejected):
        validate(stranger.token(), cache, frozen_clock)
    assert endpoint.fetches == 3


def test_jwks_is_refetched_after_the_10_minute_ttl(
    signer: Signer, endpoint: FakeJwksEndpoint, cache: JwksCache, frozen_clock: FrozenClock
) -> None:
    validate(signer.token(), cache, frozen_clock)
    frozen_clock.advance(599)
    validate(signer.token(), cache, frozen_clock)
    assert endpoint.fetches == 1

    frozen_clock.advance(1)
    validate(signer.token(), cache, frozen_clock)
    assert endpoint.fetches == 2


def test_failed_jwks_fetch_keeps_the_cached_keys(
    signer: Signer, endpoint: FakeJwksEndpoint, frozen_clock: FrozenClock
) -> None:
    calls = 0

    def flaky() -> JwkSet:
        nonlocal calls
        calls += 1
        if calls > 1:
            raise OSError("auth server down")
        return endpoint()

    cache = JwksCache(flaky, frozen_clock)
    validate(signer.token(), cache, frozen_clock)
    frozen_clock.advance(600)

    validate(signer.token(), cache, frozen_clock)
    assert calls == 2


def test_www_authenticate_header_values() -> None:
    meta = "https://news.sandcorp.co.kr/.well-known/oauth-protected-resource"

    assert www_authenticate("https://news.sandcorp.co.kr") == f'Bearer resource_metadata="{meta}"'
    assert www_authenticate("https://news.sandcorp.co.kr", error="invalid_token") == (
        f'Bearer resource_metadata="{meta}", error="invalid_token"'
    )
    assert www_authenticate(
        "https://news.sandcorp.co.kr", error="insufficient_scope", scope="admin"
    ) == ('Bearer error="insufficient_scope", scope="admin"')


# --- sites that take members (§10: A1-A3 instead of T11) -----------------------------------

MEMBER_SUB = "m_01JB2Z3Y4X5W6V7T8S9R0Q1P2N"


def validate_account(
    token: str, cache: JwksCache, clock: FrozenClock, *, scope: str = "login"
) -> AccessToken:
    return validate_account_access_token(
        token, jwks=cache, audience=NEWS, owner_sub=OWNER, required_scope=scope, clock=clock
    )


def test_member_token_passes_the_account_rules(
    signer: Signer, cache: JwksCache, frozen_clock: FrozenClock
) -> None:
    token = signer.token(sub=MEMBER_SUB, acct="member", scope="login")
    verified = validate_account(token, cache, frozen_clock)
    assert (verified.sub, verified.acct, verified.scopes) == (
        MEMBER_SUB,
        "member",
        frozenset({"login"}),
    )
    with pytest.raises(TokenRejected):  # the owner-only rules (T11) still refuse it
        validate(token, cache, frozen_clock, scope="login")


def test_token_without_acct_is_the_owner_and_must_have_the_owner_sub(
    signer: Signer, cache: JwksCache, frozen_clock: FrozenClock
) -> None:
    verified = validate_account(signer.token(scope="login"), cache, frozen_clock)
    assert (verified.sub, verified.acct) == (OWNER, "owner")
    with pytest.raises(TokenRejected):
        validate_account(signer.token(sub=MEMBER_SUB, scope="login"), cache, frozen_clock)


@pytest.mark.parametrize("acct", ["owner", "Member", "admin", "", 1, ["member"], None])
def test_acct_other_than_member_is_rejected(
    signer: Signer, cache: JwksCache, frozen_clock: FrozenClock, acct: object
) -> None:
    token = jwt.encode(
        {
            **jwt.decode(signer.token(scope="login"), options={"verify_signature": False}),
            "acct": acct,
        },
        signer.private_key,
        algorithm="EdDSA",
        headers={"kid": signer.kid},
    )
    with pytest.raises(TokenRejected):
        validate_account(token, cache, frozen_clock)


@pytest.mark.parametrize(
    "sub", [OWNER, "m_short", "m_01jb2z3y4x5w6v7t8s9r0q1p2n", "x" + MEMBER_SUB]
)
def test_member_token_needs_a_member_sub(
    signer: Signer, cache: JwksCache, frozen_clock: FrozenClock, sub: str
) -> None:
    with pytest.raises(TokenRejected):
        validate_account(signer.token(sub=sub, acct="member", scope="login"), cache, frozen_clock)


def test_member_token_without_the_scope_is_insufficient(
    signer: Signer, cache: JwksCache, frozen_clock: FrozenClock
) -> None:
    token = signer.token(sub=MEMBER_SUB, acct="member", scope="login")
    with pytest.raises(InsufficientScope):
        validate_account(token, cache, frozen_clock, scope="admin")
