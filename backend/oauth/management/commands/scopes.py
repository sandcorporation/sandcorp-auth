from argparse import ArgumentParser

from django.core.management.base import BaseCommand, CommandError

from oauth.models import Resource, Scope
from services.members import ScopeNeverForMembers, set_scope_members_allowed

ACTOR = "manage.py scopes"


class Command(BaseCommand):
    help = (
        "리소스 스코프 관리: members(스코프의 일반 사용자 허용 켜기·끄기, #47), "
        "list(리소스별 스코프와 허용 여부)."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        actions = parser.add_subparsers(dest="action", required=True)
        members = actions.add_parser(
            "members",
            help="일반 사용자가 이 리소스의 이 스코프를 받게 하거나 막는다(admin·editor 불가)",
        )
        members.add_argument("--resource", required=True, help="리소스 URL(토큰 aud)")
        members.add_argument("--name", required=True, help="스코프 이름")
        switch = members.add_mutually_exclusive_group(required=True)
        switch.add_argument("--allow", dest="allow", action="store_true")
        switch.add_argument("--deny", dest="allow", action="store_false")
        listing = actions.add_parser("list", help="스코프 목록(일반 사용자 허용 여부)")
        listing.add_argument("--resource", help="이 리소스 URL의 스코프만")

    def handle(self, *args: object, **options: object) -> None:
        action = options["action"]
        if action == "members":
            url = str(options["resource"])
            name = str(options["name"])
            matching = Scope.objects.filter(resource__url=url, name=name)
            found = matching.select_related("resource").first()
            if found is None:
                raise CommandError(f"스코프가 없습니다: {url} {name}", returncode=1)
            allowed = bool(options["allow"])
            try:
                set_scope_members_allowed(found, allowed, actor=ACTOR)
            except ScopeNeverForMembers:
                raise CommandError(
                    f"'{name}' 스코프는 일반 사용자에게 줄 수 없습니다.", returncode=1
                ) from None
            state = "켰습니다" if allowed else "껐습니다"
            self.stdout.write(f"{url} {name}의 일반 사용자 허용을 {state}.")
        elif action == "list":
            scopes = Scope.objects.select_related("resource").order_by("resource__url", "name")
            if options.get("resource"):
                url = str(options["resource"])
                if not Resource.objects.filter(url=url).exists():
                    raise CommandError(f"리소스가 없습니다: {url}", returncode=1)
                scopes = scopes.filter(resource__url=url)
            for scope in scopes:
                state = "on" if scope.members_allowed else "off"
                self.stdout.write(f"{scope.resource.url}\t{scope.name}\tmembers={state}")
