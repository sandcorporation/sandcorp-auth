"""Identifiers compare exactly on MySQL (#30).

The database collation is `utf8mb4_0900_as_cs` (case- and accent-sensitive) and `client_id` is
an `ascii_bin` column. Under a `_ci` collation `/MCP` would match the `/mcp` resource and `READ`
would collide with `read`; these tests pin that it does not.
"""

import pytest
from django.conf import settings
from django.contrib.auth.models import User
from django.db import connection
from django.test import Client

from audit.models import AuditEvent
from oauth.models import Client as OAuthClient
from oauth.models import Resource, Scope
from oauth.server import server
from services import audit
from tests.conftest import NEWS, PORTFOLIO, FakeHttp, authorize_query, use_https

pytestmark = pytest.mark.django_db


def test_the_test_database_uses_the_production_collation() -> None:
    with connection.cursor() as cursor:
        cursor.execute("SELECT @@collation_database")
        row = cursor.fetchone()
    assert row is not None
    assert row[0] == "utf8mb4_0900_as_cs"


def test_scope_names_differing_in_case_or_accent_are_different_scopes() -> None:
    resource = Resource.objects.get(url=NEWS)
    for name in ("Admin", "ADMIN", "ádmin"):
        Scope.objects.create(resource=resource, name=name, description=name)

    assert list(resource.scopes.filter(name="admin").values_list("name", flat=True)) == ["admin"]


def test_resource_urls_match_exactly() -> None:
    assert Resource.objects.filter(url=PORTFOLIO).exists()
    assert not Resource.objects.filter(url=PORTFOLIO.upper()).exists()
    assert not Resource.objects.filter(url=PORTFOLIO.replace("/mcp", "/MCP")).exists()


def test_usernames_match_exactly(owner: User) -> None:
    assert User.objects.filter(username=owner.username).exists()
    assert not User.objects.filter(username=owner.username.upper()).exists()


def test_client_ids_match_byte_for_byte(dcr_client: OAuthClient) -> None:
    swapped = dcr_client.client_id.swapcase()
    assert swapped != dcr_client.client_id
    assert server.query_client(swapped) is None


def test_a_non_ascii_cimd_url_is_rejected_without_a_query(
    logged_in_client: Client, fake_http: FakeHttp
) -> None:
    url = "https://app.example/클라이언트.json"
    response = use_https(logged_in_client).get(
        "/authorize?" + authorize_query(OAuthClient(client_id=url, redirect_uris=["x"]))
    )

    assert response.status_code == 400
    assert fake_http.fetched == []
    event = AuditEvent.objects.get(kind=audit.CLIENT_CIMD_REJECTED)
    assert event.detail == {"reason": "client_id is not ASCII"}


@pytest.mark.parametrize("model", ["client", "consent", "refreshtokenfamily"])
def test_admin_search_with_a_non_ascii_term_skips_client_ids(
    logged_in_client: Client, dcr_client: OAuthClient, model: str
) -> None:
    # Client names are often Korean; LIKE '%포트폴리오%' on the ascii client_id column would fail.
    response = logged_in_client.get(f"/{settings.ADMIN_PATH}oauth/{model}/", {"q": "포트폴리오"})

    assert response.status_code == 200
