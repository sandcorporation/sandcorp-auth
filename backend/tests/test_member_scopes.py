"""Resource scopes a member may hold (#47, ADR 0003 addendum).

A member holds `login` and the login info scopes, plus the scopes the *requested resource*
marked `members_allowed` (the Flow MCP's `flow.read`·`flow.write`). The same name in another
resource does not count, `admin` and `editor` can never be marked, and the owner is untouched.
"""

import io

import pytest
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError, transaction
from django.test import Client
from django.urls import reverse

from audit.models import AuditEvent
from oauth.models import Client as OAuthClient
from oauth.models import Resource, Scope, SigningKey
from oauth.tokens import SandcorpTokenGenerator
from services.members import member_scopes
from tests.conftest import (
    PORTFOLIO,
    authorize_query,
    exchange_code,
    obtain_authorization_code,
    refresh,
    use_https,
)
from tests.test_members import redirect_error
from tests.test_oidc import unverified

pytestmark = pytest.mark.django_db

FLOW = "https://flow.example.test/mcp"
OTHER = "https://other.example.test/mcp"


@pytest.fixture
def flow(db: None) -> Resource:
    """A resource like the Flow MCP: `flow.read`·`flow.write` allowed for members,
    `flow.admin` not."""
    resource = Resource.objects.create(name="Flow MCP", url=FLOW)
    Scope.objects.create(
        resource=resource, name="flow.read", description="읽기", members_allowed=True
    )
    Scope.objects.create(
        resource=resource, name="flow.write", description="쓰기", members_allowed=True
    )
    Scope.objects.create(resource=resource, name="flow.admin", description="관리")
    Scope.objects.create(resource=resource, name="admin", description="대표 관리")
    return resource


@pytest.fixture
def other(db: None) -> Resource:
    """Another resource with a scope of the same name, not allowed for members."""
    resource = Resource.objects.create(name="Other", url=OTHER)
    Scope.objects.create(resource=resource, name="flow.read", description="읽기")
    return resource


@pytest.fixture
def members_app(dcr_client: OAuthClient, signing_key: SigningKey) -> OAuthClient:
    OAuthClient.objects.filter(pk=dcr_client.pk).update(allows_members=True)
    dcr_client.refresh_from_db()
    return dcr_client


def test_member_scopes_are_login_info_and_the_resources_marked_scopes(
    flow: Resource, other: Resource
) -> None:
    assert member_scopes(flow) == {"login", "openid", "profile", "email", "flow.read", "flow.write"}
    assert member_scopes(other) == {"login", "openid", "profile", "email"}
    assert member_scopes(Resource.objects.get(url=PORTFOLIO)) == {
        "login",
        "openid",
        "profile",
        "email",
    }


def test_member_gets_marked_scopes_through_code_refresh(
    member_client: Client, members_app: OAuthClient, flow: Resource, member: User
) -> None:
    code, verifier = obtain_authorization_code(
        member_client, members_app, resource=FLOW, scope="flow.read flow.write"
    )
    response = exchange_code(member_client, members_app, code, verifier)
    assert response.status_code == 200, response.content
    tokens = response.json()
    claims = unverified(tokens["access_token"])
    assert (claims["sub"], claims["acct"]) == (member.username, "member")
    assert claims["aud"] == FLOW
    assert claims["scope"] == "flow.read flow.write"

    refreshed = refresh(member_client, members_app, tokens["refresh_token"])
    assert refreshed.status_code == 200, refreshed.content
    again = unverified(refreshed.json()["access_token"])
    assert (again["aud"], again["scope"]) == (FLOW, "flow.read flow.write")


@pytest.mark.parametrize(
    ("resource", "scope"),
    [
        (FLOW, "flow.admin"),  # not marked
        (FLOW, "flow.read flow.admin"),
        (FLOW, "admin"),  # never
        (OTHER, "flow.read"),  # same name, another resource
    ],
)
def test_member_is_refused_unmarked_scopes(
    member_client: Client,
    members_app: OAuthClient,
    flow: Resource,
    other: Resource,
    resource: str,
    scope: str,
) -> None:
    use_https(member_client)
    url = "/authorize?" + authorize_query(members_app, resource=resource, scope=scope)
    assert redirect_error(member_client.get(url)) == "invalid_scope"
    assert redirect_error(member_client.post(url, {"decision": "allow"})) == "invalid_scope"


def test_code_and_refresh_are_refused_once_the_mark_is_off(
    member_client: Client, members_app: OAuthClient, flow: Resource
) -> None:
    code, verifier = obtain_authorization_code(
        member_client, members_app, resource=FLOW, scope="flow.write"
    )
    tokens = exchange_code(member_client, members_app, code, verifier).json()
    code2, verifier2 = obtain_authorization_code(
        member_client, members_app, resource=FLOW, scope="flow.write"
    )
    Scope.objects.filter(resource=flow, name="flow.write").update(members_allowed=False)
    exchanged = exchange_code(member_client, members_app, code2, verifier2)
    assert (exchanged.status_code, exchanged.json()["error"]) == (400, "invalid_grant")
    refreshed = refresh(member_client, members_app, tokens["refresh_token"])
    assert (refreshed.status_code, refreshed.json()["error"]) == (400, "invalid_grant")


def test_token_generator_goes_by_the_resource(
    member: User, members_app: OAuthClient, flow: Resource, other: Resource
) -> None:
    generate = SandcorpTokenGenerator().generate
    signed = generate("authorization_code", members_app, member, "flow.read", resource=flow)
    assert unverified(str(signed["access_token"]))["scope"] == "flow.read"
    with pytest.raises(RuntimeError):
        generate("authorization_code", members_app, member, "flow.read", resource=other)
    with pytest.raises(RuntimeError):
        generate("authorization_code", members_app, member, "flow.admin", resource=flow)


def test_owner_still_gets_any_scope(
    logged_in_client: Client, dcr_client: OAuthClient, signing_key: SigningKey, flow: Resource
) -> None:
    code, verifier = obtain_authorization_code(
        logged_in_client, dcr_client, resource=FLOW, scope="flow.admin flow.read"
    )
    claims = unverified(
        exchange_code(logged_in_client, dcr_client, code, verifier).json()["access_token"]
    )
    assert claims["scope"] == "flow.admin flow.read"
    assert "acct" not in claims


# --- admin and editor can never be marked -------------------------------------------------


@pytest.mark.parametrize("name", ["admin", "editor"])
def test_admin_and_editor_can_never_be_marked(flow: Resource, name: str) -> None:
    scope, _ = Scope.objects.get_or_create(resource=flow, name=name, defaults={"description": "x"})
    scope.members_allowed = True
    with pytest.raises(ValidationError):
        scope.full_clean()
    with pytest.raises(IntegrityError), transaction.atomic():
        scope.save()


# --- the command ----------------------------------------------------------------------------


def test_scopes_command_turns_the_mark_on_and_off(flow: Resource) -> None:
    out = io.StringIO()
    call_command(
        "scopes", "members", f"--resource={FLOW}", "--name=flow.admin", "--allow", stdout=out
    )
    assert Scope.objects.get(resource=flow, name="flow.admin").members_allowed is True
    event = AuditEvent.objects.get(kind="scope.members_changed")
    assert event.detail == {"resource": FLOW, "scope": "flow.admin", "members_allowed": True}

    call_command(
        "scopes", "members", f"--resource={FLOW}", "--name=flow.admin", "--deny", stdout=out
    )
    assert Scope.objects.get(resource=flow, name="flow.admin").members_allowed is False

    listing = io.StringIO()
    call_command("scopes", "list", f"--resource={FLOW}", stdout=listing)
    lines = listing.getvalue().splitlines()
    assert f"{FLOW}\tflow.read\tmembers=on" in lines
    assert f"{FLOW}\tflow.admin\tmembers=off" in lines
    assert all(line.startswith(FLOW) for line in lines)
    everything = io.StringIO()
    call_command("scopes", "list", stdout=everything)
    assert f"{PORTFOLIO}\tadmin\tmembers=off" in everything.getvalue()


@pytest.mark.parametrize(
    "args",
    [
        [f"--resource={FLOW}", "--name=admin", "--allow"],
        [f"--resource={FLOW}", "--name=nope", "--allow"],
        [f"--resource={OTHER}", "--name=flow.read", "--allow"],
    ],
)
def test_scopes_command_refuses(flow: Resource, args: list[str]) -> None:
    with pytest.raises(CommandError) as raised:
        call_command("scopes", "members", *args, stdout=io.StringIO())
    assert raised.value.returncode == 1
    assert not Scope.objects.filter(name="admin", members_allowed=True).exists()
    assert not AuditEvent.objects.filter(kind="scope.members_changed").exists()


def test_scopes_list_refuses_an_unknown_resource(db: None) -> None:
    with pytest.raises(CommandError):
        call_command("scopes", "list", f"--resource={OTHER}", stdout=io.StringIO())


# --- admin ----------------------------------------------------------------------------------


def _resource_form(resource: Resource, marks: dict[str, bool]) -> dict[str, str]:
    scopes = list(resource.scopes.order_by("pk"))
    form = {
        "name": resource.name,
        "url": resource.url,
        "scopes-TOTAL_FORMS": str(len(scopes)),
        "scopes-INITIAL_FORMS": str(len(scopes)),
        "scopes-MIN_NUM_FORMS": "0",
        "scopes-MAX_NUM_FORMS": "1000",
    }
    for index, scope in enumerate(scopes):
        prefix = f"scopes-{index}-"
        form[prefix + "id"] = str(scope.pk)
        form[prefix + "resource"] = str(resource.pk)
        form[prefix + "name"] = scope.name
        form[prefix + "description"] = scope.description
        if marks.get(scope.name, scope.members_allowed):
            form[prefix + "members_allowed"] = "on"
    return form


def test_admin_marks_a_scope_and_refuses_admin(logged_in_client: Client, flow: Resource) -> None:
    url = reverse("admin:oauth_resource_change", args=[flow.pk])
    page = logged_in_client.get(url)
    assert b"scopes-0-members_allowed" in page.content

    refused = logged_in_client.post(url, _resource_form(flow, {"admin": True}))
    assert refused.status_code == 200  # the form again, with the error
    assert "일반 사용자에게 줄 수 없습니다" in refused.content.decode()
    assert not Scope.objects.get(resource=flow, name="admin").members_allowed

    saved = logged_in_client.post(url, _resource_form(flow, {"flow.admin": True}))
    assert saved.status_code == 302, saved.content
    assert Scope.objects.get(resource=flow, name="flow.admin").members_allowed is True
    event = AuditEvent.objects.get(kind="scope.members_changed")
    assert event.detail == {"resource": FLOW, "scope": "flow.admin", "members_allowed": True}


# --- consent screen wording and the "other account" link (#49) -----------------------------


def test_member_consent_for_a_resource_scope_speaks_of_their_own_account(
    member_client: Client, member: User, members_app: OAuthClient, flow: Resource
) -> None:
    use_https(member_client)
    url = "/authorize?" + authorize_query(members_app, scope="flow.read", resource=FLOW)
    page = member_client.get(url).content.decode()
    assert "내 Sandcorp 계정으로 아래에 접근합니다" in page
    assert "대표 계정으로 아래 리소스" not in page and "봅니다" not in page
    assert f"{member.first_name}(으)로 로그인됨" in page and "다른 계정으로 로그인" in page


def test_owner_consent_keeps_the_owner_wording(
    logged_in_client: Client, dcr_client: OAuthClient
) -> None:
    use_https(logged_in_client)
    url = "/authorize?" + authorize_query(dcr_client, scope="admin", resource=PORTFOLIO)
    page = logged_in_client.get(url).content.decode()
    assert "이 클라이언트가 대표 계정으로 아래 리소스에 접근하려고 합니다." in page
    assert "farrar142(으)로 로그인됨" in page


def test_other_account_logs_out_and_returns_to_the_same_authorize_request(
    member_client: Client, members_app: OAuthClient, flow: Resource
) -> None:
    use_https(member_client)
    url = "/authorize?" + authorize_query(members_app, scope="flow.read", resource=FLOW)
    assert member_client.get(url).status_code == 200
    response = member_client.post("/logout", {"next": url})
    assert response.status_code == 302 and response["Location"] == url
    assert "_auth_user_id" not in member_client.session
    again = member_client.get(url)
    assert again.status_code == 302 and again["Location"].startswith("/login")


@pytest.mark.parametrize("target", ["//evil.test/x", "https://evil.test", "/\\evil.test", ""])
def test_logout_next_only_accepts_internal_paths(member_client: Client, target: str) -> None:
    response = member_client.post("/logout", {"next": target})
    assert response.status_code == 302 and response["Location"] == reverse("accounts:login")
