from argparse import ArgumentParser

from django.core.management.base import BaseCommand, CommandError

from oauth.models import Client
from services.confidential_clients import (
    InvalidRedirectUri,
    create_confidential_client,
    rotate_client_secret,
)
from services.members import set_allows_members

ACTOR = "manage.py clients"


class Command(BaseCommand):
    help = (
        "OAuth 클라이언트 관리: create-confidential(사이트 관리 화면 로그인용 기밀 클라이언트), "
        "rotate-secret, members(일반 사용자 허용 켜기·끄기), list. "
        "시크릿 원문은 발급할 때 한 번만 출력한다."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        actions = parser.add_subparsers(dest="action", required=True)
        create = actions.add_parser("create-confidential", help="기밀 클라이언트를 만든다")
        create.add_argument("--name", required=True)
        create.add_argument(
            "--redirect-uri",
            dest="redirect_uris",
            action="append",
            required=True,
            help="https만, 정확 일치(끝 슬래시 포함). 여러 번 줄 수 있다",
        )
        create.add_argument(
            "--allow-members",
            action="store_true",
            help="일반 사용자(소셜 로그인 계정)도 받는다. 기본은 대표만",
        )
        rotate = actions.add_parser(
            "rotate-secret", help="시크릿을 새로 발급한다(옛 것은 즉시 무효)"
        )
        rotate.add_argument("--client-id", required=True)
        members = actions.add_parser(
            "members", help="일반 사용자 허용 표시를 켜거나 끈다(ADR 0003)"
        )
        members.add_argument("--client-id", required=True)
        switch = members.add_mutually_exclusive_group(required=True)
        switch.add_argument("--allow", dest="allow", action="store_true")
        switch.add_argument("--deny", dest="allow", action="store_false")
        actions.add_parser("list", help="클라이언트 목록(시크릿 없음)")

    def handle(self, *args: object, **options: object) -> None:
        action = options["action"]
        if action == "create-confidential":
            uris = options["redirect_uris"]
            assert isinstance(uris, list)
            try:
                issued = create_confidential_client(
                    str(options["name"]), [str(uri) for uri in uris], actor=ACTOR
                )
            except (InvalidRedirectUri, ValueError) as error:
                raise CommandError(str(error), returncode=1) from None
            if options["allow_members"]:
                set_allows_members(issued.client, True, actor=ACTOR)
            self._print_secret("기밀 클라이언트를 만들었습니다.", issued.client, issued.secret)
        elif action == "rotate-secret":
            client_id = str(options["client_id"])
            client = Client.objects.filter(
                client_id=client_id, kind=Client.Kind.CONFIDENTIAL
            ).first()
            if client is None:
                raise CommandError(f"기밀 클라이언트가 없습니다: {client_id}", returncode=1)
            secret = rotate_client_secret(client, actor=ACTOR)
            self._print_secret(
                "시크릿을 새로 발급했습니다. 옛 시크릿은 이제 통하지 않습니다.", client, secret
            )
        elif action == "members":
            client_id = str(options["client_id"])
            found = (
                Client.objects.filter(client_id=client_id).first() if client_id.isascii() else None
            )
            if found is None:
                raise CommandError(f"클라이언트가 없습니다: {client_id}", returncode=1)
            allowed = bool(options["allow"])
            set_allows_members(found, allowed, actor=ACTOR)
            state = "켰습니다" if allowed else "껐습니다"
            self.stdout.write(f"{found.name}({found.client_id})의 일반 사용자 허용을 {state}.")
        else:
            for client in Client.objects.order_by("created_at"):
                state = "active" if client.active else "inactive"
                members = "members=on" if client.allows_members else "members=off"
                uris = " ".join(client.redirect_uris)
                self.stdout.write(
                    f"{client.client_id}\t{client.kind}\t{client.registered_via}\t{state}\t"
                    f"{client.name}\t{uris}\t{members}"
                )

    def _print_secret(self, headline: str, client: Client, secret: str) -> None:
        self.stdout.write(
            f"{headline}\n"
            f"name: {client.name}\n"
            f"client_id: {client.client_id}\n"
            f"client_secret: {secret}\n"
            f"redirect_uris: {' '.join(client.redirect_uris)}\n"
            f"allows_members: {'on' if client.allows_members else 'off'}\n"
            "시크릿은 지금 한 번만 보입니다(저장된 것은 해시뿐). 사이트 설정에 바로 넣으세요."
        )
