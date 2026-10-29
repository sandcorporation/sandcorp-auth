"""The test doubles themselves, and that the T1 suite runs on them (conftest re-exports
`FakeJwks`, `SigningKey` and `FixedClock`)."""

import subprocess
import sys
import textwrap
from datetime import UTC, datetime

import pytest
from conftest import ISSUER, RESOURCE, START

from sandcorp_authkit.login import TokenRequest
from sandcorp_authkit.testing import (
    MEMBER_SUB,
    OWNER_SUB,
    FakeJwks,
    FakeTokenEndpoint,
    FixedClock,
    SigningKey,
    access_token_claims,
    bearer_header,
)
from sandcorp_authkit.tokens import (
    MEMBER_SUB as MEMBER_PATTERN,
)
from sandcorp_authkit.tokens import (
    TokenRejected,
    owner_or_member,
    validate_access_token,
)


def test_fixed_clock_moves_only_when_told() -> None:
    clock = FixedClock(START)
    assert clock.now() == START
    clock.advance(90.5)
    assert (clock.now() - START).total_seconds() == 90.5
    assert FixedClock().now() == datetime(2026, 1, 1, tzinfo=UTC)
    with pytest.raises(ValueError):
        FixedClock(datetime(2026, 1, 1))


def test_issued_access_token_passes_the_real_validator() -> None:
    clock, fake = FixedClock(START), FakeJwks()
    token = fake.issue_access_token(clock, audience=RESOURCE)
    access = validate_access_token(
        token,
        issuer=ISSUER,
        audience=RESOURCE,
        required_scope="admin",
        jwks=fake.cache(clock),
        clock=clock,
    )
    assert access.sub == OWNER_SUB and access.acct is None
    assert access.exp - access.iat == 600


def test_member_sub_is_well_formed_and_member_tokens_pass() -> None:
    assert MEMBER_PATTERN.fullmatch(MEMBER_SUB)
    clock, fake = FixedClock(START), FakeJwks()
    token = fake.issue_access_token(clock, audience=RESOURCE, sub=MEMBER_SUB, acct="member")
    access = validate_access_token(
        token,
        issuer=ISSUER,
        audience=RESOURCE,
        required_scope="login",
        jwks=fake.cache(clock),
        clock=clock,
        extra_claims_hook=owner_or_member(OWNER_SUB),
    )
    assert access.acct == "member"


def test_none_drops_a_claim() -> None:
    claims = access_token_claims(FixedClock(), audience=RESOURCE, jti=None, scope=None)
    assert "scope" not in claims and claims["jti"]  # jti=None means "generate one"
    assert "client_id" not in access_token_claims(FixedClock(), audience=RESOURCE, client_id=None)


def test_rotate_keeps_old_keys_published() -> None:
    clock, fake = FixedClock(START), FakeJwks(SigningKey("a"))
    cache = fake.cache(clock)
    old = fake.issue_access_token(clock, audience=RESOURCE)
    fake.rotate("b")
    new = fake.issue_access_token(clock, audience=RESOURCE)
    assert [k["kid"] for k in fake.document["keys"]] == ["a", "b"]  # type: ignore[index]
    for token in (old, new):
        validate_access_token(
            token,
            issuer=ISSUER,
            audience=RESOURCE,
            required_scope="admin",
            jwks=cache,
            clock=clock,
        )


def test_failing_jwks_and_foreign_keys() -> None:
    clock, fake = FixedClock(START), FakeJwks()
    fake.failing = True
    with pytest.raises(OSError):
        fake()
    fake.failing = False
    foreign = fake.issue_access_token(clock, audience=RESOURCE, key=SigningKey(fake.key.kid))
    with pytest.raises(TokenRejected):
        validate_access_token(
            foreign,
            issuer=ISSUER,
            audience=RESOURCE,
            required_scope="admin",
            jwks=fake.cache(clock),
            clock=clock,
        )
    assert fake.fetches == 2


def test_headers_replace_the_jwt_header() -> None:
    import jwt

    token = SigningKey("k").sign({"a": 1}, headers={"kid": "other"})
    assert jwt.get_unverified_header(token) == {"alg": "EdDSA", "typ": "JWT", "kid": "other"}


def test_bearer_header_is_for_the_django_test_client() -> None:
    assert bearer_header("t") == {"Authorization": "Bearer t"}


def test_fake_token_endpoint_checks_the_client_and_the_grant() -> None:
    clock = FixedClock(START)
    server = FakeTokenEndpoint(FakeJwks(), clock, client_id="c", client_secret="s")
    url = (
        f"{ISSUER}/authorize?response_type=code&client_id=c&redirect_uri=https%3A%2F%2Fx%2Fcb"
        "&scope=login&resource=https%3A%2F%2Fx%2Fmcp&state=st&code_challenge=ch"
        "&code_challenge_method=S256"
    )
    query = server.approve(url)
    assert query["state"] == "st"
    bad_basic = TokenRequest("u", {"Authorization": "Basic !!"}, {}, 5.0, 10)
    assert server(bad_basic).status == 401
    no_auth = TokenRequest("u", {}, {}, 5.0, 10)
    assert server(no_auth).status == 401
    assert len(server.requests) == 2
    with pytest.raises(AssertionError, match="PKCE"):
        server.approve(url.replace("S256", "plain"))
    with pytest.raises(AssertionError, match="client_id"):
        server.approve(url.replace("client_id=c", "client_id=d"))
    assert server.deny(url) == {"error": "access_denied", "state": "st"}


def test_testing_imports_without_django() -> None:
    """`tokens`, `resource`, `login` and `testing` work without the [django] extra; the
    `django` module says which extra it needs."""
    script = textwrap.dedent(
        """
        import sys
        sys.modules["django"] = None
        sys.modules["ninja"] = None
        import sandcorp_authkit.tokens, sandcorp_authkit.resource
        import sandcorp_authkit.login, sandcorp_authkit.testing
        assert not any(m.split(".")[0] in ("django", "ninja") and sys.modules[m] is not None
                       for m in sys.modules)
        try:
            import sandcorp_authkit.django
        except ModuleNotFoundError as exc:
            assert "[django]" in str(exc), exc
        else:
            raise AssertionError("sandcorp_authkit.django imported without Django")
        print("ok")
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=60, check=False
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
