"""The internal login info resource: the audience of access tokens granted only for OpenID
Connect scopes (services.oidc.USERINFO_RESOURCE, accepted only by /userinfo)."""

from django.apps.registry import Apps
from django.db import migrations
from django.db.backends.base.schema import BaseDatabaseSchemaEditor

URL = "https://auth.sandcorp.co.kr/userinfo"
NAME = "로그인 정보"
SCOPES = [
    ("openid", "로그인 정보(이름·이메일) 제공: 대표 계정 식별자"),
    ("profile", "로그인 정보(이름·이메일) 제공: 이름"),
    ("email", "로그인 정보(이름·이메일) 제공: 이메일"),
]


def create(apps: Apps, schema_editor: BaseDatabaseSchemaEditor) -> None:
    Resource = apps.get_model("oauth", "Resource")
    Scope = apps.get_model("oauth", "Scope")
    resource, _ = Resource.objects.get_or_create(url=URL, defaults={"name": NAME})
    for name, description in SCOPES:
        Scope.objects.get_or_create(
            resource=resource, name=name, defaults={"description": description}
        )


def remove(apps: Apps, schema_editor: BaseDatabaseSchemaEditor) -> None:
    Resource = apps.get_model("oauth", "Resource")
    Resource.objects.filter(url=URL).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("oauth", "0006_oidc_nonce_auth_time"),
    ]

    operations = [migrations.RunPython(create, remove)]
