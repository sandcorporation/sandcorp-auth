"""#106 (405 page, CSRF retry target) and #107 (404·500 pages in the service's look)."""

import pytest
from django.conf import settings
from django.test import Client, RequestFactory

from tests.conftest import make_member

HTML = "text/html,application/xhtml+xml,*/*;q=0.8"
HOST = "testserver"


@pytest.mark.parametrize("path", ["/logout", "/account/email"])
def test_get_on_post_only_path_shows_page(client: Client, db: None, path: str) -> None:
    client.force_login(make_member())
    response = client.get(path, HTTP_ACCEPT=HTML)
    assert response.status_code == 405
    assert response["Allow"] == "POST"
    html = response.content.decode()
    assert html.count("<h1") == 1
    assert 'href="/"' in html
    assert "sc-masthead" in html


def test_405_for_non_browser_stays_bare(client: Client, db: None) -> None:
    response = client.get("/token", HTTP_ACCEPT="application/json")
    assert response.status_code == 405
    assert response["Allow"] == "POST"
    assert response.content == b""


def _csrf_retry(html: str) -> str:
    start = html.index('data-slot="retry"')
    tag_start = html.rindex("<a", 0, start)
    tag = html[tag_start : html.index(">", start)]
    href = tag.split('href="', 1)[1]
    return href.split('"', 1)[0].replace("&amp;", "&")


def test_csrf_retry_on_consent_keeps_query(db: None) -> None:
    strict = Client(enforce_csrf_checks=True)
    query = "/authorize?response_type=code&client_id=abc&state=xyz&scope=openid+profile"
    response = strict.post(query, {"decision": "allow"})
    assert response.status_code == 403
    assert _csrf_retry(response.content.decode()) == query


def test_csrf_retry_on_post_only_uses_same_origin_referer(db: None) -> None:
    strict = Client(enforce_csrf_checks=True)
    response = strict.post("/account/email", {}, HTTP_REFERER=f"http://{HOST}/account?tab=1")
    assert _csrf_retry(response.content.decode()) == "/account?tab=1"


@pytest.mark.parametrize(
    "referer",
    [None, "https://evil.example/account", f"http://{HOST}//evil.example/x", "javascript:x"],
)
def test_csrf_retry_on_post_only_falls_back_home(db: None, referer: str | None) -> None:
    strict = Client(enforce_csrf_checks=True)
    extra = {"HTTP_REFERER": referer} if referer else {}
    response = strict.post("/logout", {}, **extra)  # type: ignore[arg-type]
    assert _csrf_retry(response.content.decode()) == "/"


def test_csrf_retry_never_leaves_site() -> None:
    from accounts.views import csrf_failure

    for path in ("//evil.example/x", "/\\evil.example"):
        request = RequestFactory().post("/")
        request.path = request.path_info = path
        assert _csrf_retry(csrf_failure(request).content.decode()) == "/"


def test_unknown_path_gets_404_page(client: Client, db: None) -> None:
    response = client.get("/no-such-page")
    assert response.status_code == 404
    html = response.content.decode()
    assert html.count("<h1") == 1
    assert 'href="/"' in html
    assert "sc-masthead" in html


def test_admin_unknown_path_gets_same_404(logged_in_client: Client) -> None:
    response = logged_in_client.get("/" + settings.ADMIN_PATH + "no-such-app/")
    assert response.status_code == 404
    assert "sc-masthead" in response.content.decode()


def test_500_page_without_database() -> None:
    """No `db` fixture: any query here raises."""
    from accounts.views import server_error

    response = server_error(RequestFactory().get("/"))
    assert response.status_code == 500
    html = response.content.decode()
    assert html.count("<h1") == 1
    assert 'href="/"' in html
