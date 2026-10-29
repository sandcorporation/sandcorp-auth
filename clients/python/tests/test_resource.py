"""protected_resource_metadata, metadata_path/metadata_url and www_authenticate
(docs/resource-server-token-validation.md §5–§6, RFC 9728)."""

import json

import pytest

from sandcorp_authkit.resource import (
    metadata_path,
    metadata_url,
    protected_resource_metadata,
    www_authenticate,
)

PORTFOLIO_METADATA = "https://sandcorp.co.kr/.well-known/oauth-protected-resource"


def test_www_authenticate_header_values() -> None:
    assert www_authenticate(PORTFOLIO_METADATA) == (
        'Bearer resource_metadata="https://sandcorp.co.kr/.well-known/oauth-protected-resource"'
    )
    assert www_authenticate(PORTFOLIO_METADATA, error="invalid_token") == (
        'Bearer resource_metadata="https://sandcorp.co.kr/.well-known/oauth-protected-resource",'
        ' error="invalid_token"'
    )
    assert www_authenticate(PORTFOLIO_METADATA, error="insufficient_scope", scope="admin") == (
        'Bearer error="insufficient_scope", scope="admin"'
    )


def test_news_example_from_the_document() -> None:
    url = "https://news.sandcorp.co.kr/.well-known/oauth-protected-resource"
    assert www_authenticate(url, error="invalid_token") == (
        'Bearer resource_metadata="https://news.sandcorp.co.kr/.well-known/oauth-protected-resource",'
        ' error="invalid_token"'
    )


def test_insufficient_scope_needs_a_scope() -> None:
    with pytest.raises(ValueError):
        www_authenticate(PORTFOLIO_METADATA, error="insufficient_scope")


def test_scope_without_insufficient_scope_is_a_mistake() -> None:
    with pytest.raises(ValueError):
        www_authenticate(PORTFOLIO_METADATA, scope="admin")


@pytest.mark.parametrize(
    "bad", ['https://x/"evil', "https://x/\\", "https://x/\r\nSet-Cookie: a=b"]
)
def test_values_that_break_the_quoted_string_are_refused(bad: str) -> None:
    with pytest.raises(ValueError):
        www_authenticate(bad)
    with pytest.raises(ValueError):
        www_authenticate(PORTFOLIO_METADATA, error="insufficient_scope", scope=bad)


def test_protected_resource_metadata_matches_the_document() -> None:
    body = protected_resource_metadata(
        "https://sandcorp.co.kr/mcp", "https://auth.sandcorp.co.kr", ["admin", "login"]
    )
    assert json.loads(json.dumps(body)) == {
        "resource": "https://sandcorp.co.kr/mcp",
        "authorization_servers": ["https://auth.sandcorp.co.kr"],
        "scopes_supported": ["admin", "login"],
        "bearer_methods_supported": ["header"],
    }


def test_news_metadata_keeps_scope_order() -> None:
    body = protected_resource_metadata(
        "https://news.sandcorp.co.kr/mcp",
        "https://auth.sandcorp.co.kr",
        ("admin", "editor", "login"),
    )
    assert body["scopes_supported"] == ["admin", "editor", "login"]
    assert "resource_name" not in body


def test_resource_name_is_included_when_given() -> None:
    body = protected_resource_metadata(
        "https://flow.sandcorp.co.kr/mcp",
        "https://auth.sandcorp.co.kr",
        ["flow.read"],
        resource_name="Sandcorp Flow",
    )
    assert body["resource_name"] == "Sandcorp Flow"


def test_a_scope_string_is_refused() -> None:
    with pytest.raises(TypeError):
        protected_resource_metadata("https://sandcorp.co.kr/mcp", "https://auth", "admin login")


@pytest.mark.parametrize(
    ("resource", "path"),
    [
        ("https://sandcorp.co.kr/mcp", "/.well-known/oauth-protected-resource/mcp"),
        ("https://flow.sandcorp.co.kr/api/v1", "/.well-known/oauth-protected-resource/api/v1"),
        ("https://sandcorp.co.kr", "/.well-known/oauth-protected-resource"),
        ("https://sandcorp.co.kr/", "/.well-known/oauth-protected-resource"),
        ("http://127.0.0.1:8000/mcp", "/.well-known/oauth-protected-resource/mcp"),
    ],
)
def test_metadata_path_follows_rfc_9728(resource: str, path: str) -> None:
    assert metadata_path(resource) == path


def test_metadata_url_is_on_the_resource_origin() -> None:
    assert metadata_url("https://news.sandcorp.co.kr/mcp") == (
        "https://news.sandcorp.co.kr/.well-known/oauth-protected-resource/mcp"
    )
    assert metadata_url("https://sandcorp.co.kr") == PORTFOLIO_METADATA


@pytest.mark.parametrize(
    "resource",
    [
        "/mcp",
        "sandcorp.co.kr/mcp",
        "ftp://x/mcp",
        "https://x/mcp?a=1",
        "https://x/mcp#f",
        "https://x/mcp?",
    ],
)
def test_metadata_path_refuses_non_resource_urls(resource: str) -> None:
    with pytest.raises(ValueError):
        metadata_path(resource)
