"""Initial resources and scopes (names fixed in docs/resource-server-token-validation.md 1절)."""

from django.apps.registry import Apps
from django.db import migrations
from django.db.backends.base.schema import BaseDatabaseSchemaEditor

INITIAL = [
    (
        "portfolio",
        "https://sandcorp.co.kr/mcp",
        [
            ("admin", "포트폴리오 관리: 제안서·포트폴리오 항목 읽기와 쓰기(MCP·관리 API)"),
            ("login", "sandcorp.co.kr 관리 화면 로그인"),
        ],
    ),
    (
        "뉴스",
        "https://news.sandcorp.co.kr/mcp",
        [
            ("admin", "뉴스 관리: 기사·소스·분야 전체 관리(MCP·관리 API)"),
            ("editor", "기사 작성·편집(소스·분야 관리 제외)"),
            ("login", "news.sandcorp.co.kr 관리 화면 로그인"),
        ],
    ),
]


def create(apps: Apps, schema_editor: BaseDatabaseSchemaEditor) -> None:
    Resource = apps.get_model("oauth", "Resource")
    Scope = apps.get_model("oauth", "Scope")
    for name, url, scopes in INITIAL:
        resource, _ = Resource.objects.get_or_create(url=url, defaults={"name": name})
        for scope_name, description in scopes:
            Scope.objects.get_or_create(
                resource=resource, name=scope_name, defaults={"description": description}
            )


def remove(apps: Apps, schema_editor: BaseDatabaseSchemaEditor) -> None:
    Resource = apps.get_model("oauth", "Resource")
    Resource.objects.filter(url__in=[url for _, url, _ in INITIAL]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("oauth", "0002_resources_scopes_clients"),
    ]

    operations = [migrations.RunPython(create, remove)]
