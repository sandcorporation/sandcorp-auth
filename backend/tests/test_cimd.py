"""Client ID Metadata Documents: an https URL `client_id` is resolved by fetching its JSON
document through the HTTP adapter (fake here), validated, cached in the client table, and
refused on SSRF-shaped URLs. Frozen clock."""

import json

import pytest

from audit.models import AuditEvent
from oauth.models import Client as OAuthClient
from oauth.server import server
from tests.conftest import CIMD_URL, FakeHttp, FrozenClock, cimd_document

pytestmark = pytest.mark.django_db


def rejected_reason() -> str:
    event = AuditEvent.objects.filter(kind="client.cimd_rejected").order_by("-id").first()
    assert event is not None
    return str(event.detail["reason"])


def test_document_becomes_a_cached_client(fake_http: FakeHttp, frozen_clock: FrozenClock) -> None:
    fake_http.put_json(CIMD_URL, cimd_document(CIMD_URL))

    client = server.query_client(CIMD_URL)

    assert client is not None
    assert client.client_id == CIMD_URL
    assert client.name == "Example MCP client"
    assert client.registered_via == "cimd"
    assert client.kind == "public"
    assert client.check_redirect_uri("https://app.example/callback")
    assert client.check_redirect_uri("http://localhost:3000/callback")
    assert not client.check_redirect_uri("https://app.example/other")
    assert client.check_endpoint_auth_method("none", "token")
    assert not client.check_endpoint_auth_method("client_secret_basic", "token")
    assert client.metadata_fetched_at == frozen_clock.now()
    assert fake_http.fetched == [CIMD_URL]

    # Cached for the default hour: no refetch, even after a changed document.
    fake_http.put_json(CIMD_URL, cimd_document(CIMD_URL, client_name="Renamed"))
    frozen_clock.advance(3599)
    again = server.query_client(CIMD_URL)
    assert again is not None and again.name == "Example MCP client"
    assert fake_http.fetched == [CIMD_URL]

    frozen_clock.advance(2)
    refreshed = server.query_client(CIMD_URL)
    assert refreshed is not None and refreshed.name == "Renamed"
    assert fake_http.fetched == [CIMD_URL, CIMD_URL]
    assert OAuthClient.objects.filter(client_id=CIMD_URL).count() == 1


@pytest.mark.parametrize(
    ("cache_control", "seconds"),
    [("public, max-age=600", 600), ("max-age=999999", 24 * 3600), ("no-cache", 3600)],
)
def test_cache_lifetime_follows_max_age_with_a_ceiling(
    fake_http: FakeHttp, frozen_clock: FrozenClock, cache_control: str, seconds: int
) -> None:
    fake_http.put_json(CIMD_URL, cimd_document(CIMD_URL), cache_control=cache_control)
    client = server.query_client(CIMD_URL)
    assert client is not None
    assert (client.metadata_expires_at - frozen_clock.now()).total_seconds() == seconds  # type: ignore[operator]


def test_revoked_cimd_client_is_not_refetched(
    cimd_client: OAuthClient, fake_http: FakeHttp, frozen_clock: FrozenClock
) -> None:
    cimd_client.active = False
    cimd_client.save()
    frozen_clock.advance(7200)
    assert server.query_client(CIMD_URL) is None
    assert fake_http.fetched == [CIMD_URL]


def test_failed_refresh_means_no_client(
    cimd_client: OAuthClient, fake_http: FakeHttp, frozen_clock: FrozenClock
) -> None:
    fake_http.documents.clear()
    frozen_clock.advance(3601)
    assert server.query_client(CIMD_URL) is None
    assert rejected_reason() == "fetch failed"


@pytest.mark.parametrize(
    ("document", "reason"),
    [
        (cimd_document("https://evil.example/client.json"), "client_id does not match"),
        (cimd_document(CIMD_URL + "?x=1"), "client_id does not match"),
        ({k: v for k, v in cimd_document(CIMD_URL).items() if k != "client_name"}, "client_name"),
        ({k: v for k, v in cimd_document(CIMD_URL).items() if k != "redirect_uris"}, "redirect"),
        (cimd_document(CIMD_URL, redirect_uris=[]), "redirect_uris missing"),
        (cimd_document(CIMD_URL, redirect_uris=["http://app.example/cb"]), "invalid redirect"),
        (cimd_document(CIMD_URL, token_endpoint_auth_method="private_key_jwt"), "auth_method"),
        (["not", "an", "object"], "not a JSON object"),
        (b"{not json", "not valid JSON"),
        (b"x" * (64 * 1024 + 1), "too large"),
    ],
)
def test_invalid_documents_are_rejected(fake_http: FakeHttp, document: object, reason: str) -> None:
    fake_http.put_json(CIMD_URL, document)
    assert server.query_client(CIMD_URL) is None
    assert reason in rejected_reason()
    assert not OAuthClient.objects.exists()


def test_non_json_content_type_is_rejected(fake_http: FakeHttp) -> None:
    fake_http.put_json(CIMD_URL, cimd_document(CIMD_URL), content_type="text/html")
    assert server.query_client(CIMD_URL) is None
    assert rejected_reason() == "content type is not JSON"


def test_document_at_exactly_the_size_limit_is_read(fake_http: FakeHttp) -> None:
    document = cimd_document(CIMD_URL, padding="")
    document["padding"] = "p" * (64 * 1024 - len(json.dumps(document).encode()))
    body = json.dumps(document).encode()
    assert len(body) == 64 * 1024
    fake_http.put_json(CIMD_URL, body)
    assert server.query_client(CIMD_URL) is not None


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("https://app.example:8443/client.json", "port other than 443"),
        ("https://user@app.example/client.json", "credentials"),
        ("https://93.184.215.14/client.json", "IP literal"),
        ("https://[2606:2800::1]/client.json", "IP literal"),
    ],
)
def test_ssrf_shaped_urls_are_rejected_before_fetching(
    fake_http: FakeHttp, url: str, reason: str
) -> None:
    fake_http.put_json(url, cimd_document(url))
    assert server.query_client(url) is None
    assert reason in rejected_reason()
    assert fake_http.fetched == []


@pytest.mark.parametrize(
    "url", ["http://app.example/client.json", "https://app.example", "https://app.example/"]
)
def test_urls_that_are_not_cimd_are_unknown_clients(fake_http: FakeHttp, url: str) -> None:
    fake_http.put_json(url, cimd_document(url))
    assert server.query_client(url) is None
    assert fake_http.fetched == []


@pytest.mark.parametrize(
    "addresses",
    [
        ["10.0.0.5"],
        ["127.0.0.1"],
        ["169.254.169.254"],
        ["192.168.1.10"],
        ["93.184.215.14", "172.16.0.1"],
        ["::1"],
        ["fd00::1"],
        ["::ffff:127.0.0.1"],
        ["224.0.0.1"],
        [],
    ],
)
def test_hosts_resolving_to_non_public_addresses_are_rejected(
    fake_http: FakeHttp, addresses: list[str]
) -> None:
    fake_http.addresses["app.example"] = addresses
    fake_http.put_json(CIMD_URL, cimd_document(CIMD_URL))
    assert server.query_client(CIMD_URL) is None
    assert fake_http.fetched == []


def test_unknown_plain_client_id_is_none(fake_http: FakeHttp) -> None:
    assert server.query_client("no-such-client") is None
    assert fake_http.fetched == []
    assert not AuditEvent.objects.exists()
