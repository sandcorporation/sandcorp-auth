from argparse import ArgumentParser

from django.core.management.base import BaseCommand, CommandError

from oauth.models import Client
from services.confidential_clients import (
    InvalidRedirectUri,
    create_confidential_client,
    rotate_client_secret,
)
from services.machine_clients import MachineClientError, create_machine_client
from services.members import set_allows_members
from services.webhooks import InvalidWebhookUrl, set_webhook

ACTOR = "manage.py clients"


class Command(BaseCommand):
    help = (
        "OAuth 클라이언트 관리: create-confidential(사이트 관리 화면 로그인용 기밀 클라이언트), "
        "create-machine(client_credentials로 토큰을 받는 기계 클라이언트), "
        "rotate-secret, members(일반 사용자 허용 켜기·끄기), "
        "webhook(user.deleted 웹훅 주소·서명 비밀), list. "
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
        machine = actions.add_parser(
            "create-machine",
            help="기계 클라이언트를 만든다(사람 없이 client_credentials로 토큰을 받는다)",
        )
        machine.add_argument("--name", required=True)
        machine.add_argument(
            "--resource", required=True, help="토큰의 aud가 될 등록된 리소스 URL 하나"
        )
        machine.add_argument(
            "--scope",
            dest="scopes",
            action="append",
            required=True,
            help="그 리소스의 스코프 이름. 여러 번 주거나 공백으로 나눠 줄 수 있다",
        )
        rotate = actions.add_parser(
            "rotate-secret",
            help="기밀·기계 클라이언트의 시크릿을 새로 발급한다(옛 것은 즉시 무효)",
        )
        rotate.add_argument("--client-id", required=True)
        members = actions.add_parser(
            "members", help="일반 사용자 허용 표시를 켜거나 끈다(ADR 0003)"
        )
        members.add_argument("--client-id", required=True)
        switch = members.add_mutually_exclusive_group(required=True)
        switch.add_argument("--allow", dest="allow", action="store_true")
        switch.add_argument("--deny", dest="allow", action="store_false")
        webhook = actions.add_parser(
            "webhook", help="user.deleted 웹훅 주소를 정하고 서명 비밀을 발급한다(ADR 0004)"
        )
        webhook.add_argument("--client-id", required=True)
        target = webhook.add_mutually_exclusive_group()
        target.add_argument("--url", help="https 주소. 처음 정하면 서명 비밀도 발급한다")
        target.add_argument("--remove", action="store_true", help="웹훅을 끈다(주소·비밀 삭제)")
        webhook.add_argument(
            "--rotate-secret",
            action="store_true",
            help="서명 비밀을 새로 발급한다(옛 것은 즉시 무효)",
        )
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
        elif action == "create-machine":
            scopes = options["scopes"]
            assert isinstance(scopes, list)
            try:
                issued = create_machine_client(
                    str(options["name"]),
                    str(options["resource"]),
                    [name for value in scopes for name in str(value).split()],
                    actor=ACTOR,
                )
            except MachineClientError as error:
                raise CommandError(str(error), returncode=1) from None
            self._print_secret("기계 클라이언트를 만들었습니다.", issued.client, issued.secret)
        elif action == "rotate-secret":
            client_id = str(options["client_id"])
            client = (
                Client.objects.filter(
                    client_id=client_id,
                    kind__in=[Client.Kind.CONFIDENTIAL, Client.Kind.MACHINE],
                ).first()
                if client_id.isascii()
                else None
            )
            if client is None:
                raise CommandError(f"기밀·기계 클라이언트가 없습니다: {client_id}", returncode=1)
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
        elif action == "webhook":
            self._webhook(options)
        else:
            for client in Client.objects.select_related("machine_resource").order_by("created_at"):
                state = "active" if client.active else "inactive"
                members = "members=on" if client.allows_members else "members=off"
                uris = " ".join(client.redirect_uris)
                if client.kind == Client.Kind.MACHINE and client.machine_resource is not None:
                    uris = (
                        f"resource={client.machine_resource.url} "
                        f"scope={' '.join(client.machine_scopes)}"
                    )
                self.stdout.write(
                    f"{client.client_id}\t{client.kind}\t{client.registered_via}\t{state}\t"
                    f"{client.name}\t{uris}\t{members}\twebhook={client.webhook_url or 'off'}"
                )

    def _webhook(self, options: dict[str, object]) -> None:
        client_id = str(options["client_id"])
        found = Client.objects.filter(client_id=client_id).first() if client_id.isascii() else None
        if found is None:
            raise CommandError(f"클라이언트가 없습니다: {client_id}", returncode=1)
        url = "" if options["remove"] else options["url"]
        rotate = bool(options["rotate_secret"])
        if url is None and not rotate:
            raise CommandError(
                "--url, --remove, --rotate-secret 중 하나가 필요합니다.", returncode=1
            )
        if rotate and url is None and not found.webhook_url:
            raise CommandError("웹훅 주소가 없습니다. --url 로 먼저 정하세요.", returncode=1)
        try:
            secret = set_webhook(
                found, url=None if url is None else str(url), rotate_secret=rotate, actor=ACTOR
            )
        except InvalidWebhookUrl as error:
            raise CommandError(f"https 주소가 아닙니다: {error}", returncode=1) from None
        if not found.webhook_url:
            self.stdout.write(f"{found.name}({found.client_id})의 웹훅을 껐습니다.")
            return
        self.stdout.write(f"{found.name}({found.client_id})의 웹훅: {found.webhook_url}")
        if secret is not None:
            self.stdout.write(
                f"webhook_secret: {secret}\n"
                "서명 비밀은 지금 한 번만 보입니다. 사이트의 웹훅 검증 설정에 바로 넣으세요"
                "(docs/resource-server-token-validation.md 11절)."
            )

    def _print_secret(self, headline: str, client: Client, secret: str) -> None:
        if client.kind == Client.Kind.MACHINE and client.machine_resource is not None:
            bound = (
                f"resource: {client.machine_resource.url}\n"
                f"scope: {' '.join(client.machine_scopes)}\n"
                "grant_type: client_credentials (client_secret_basic 또는 client_secret_post)\n"
            )
        else:
            bound = (
                f"redirect_uris: {' '.join(client.redirect_uris)}\n"
                f"allows_members: {'on' if client.allows_members else 'off'}\n"
            )
        self.stdout.write(
            f"{headline}\n"
            f"name: {client.name}\n"
            f"client_id: {client.client_id}\n"
            f"client_secret: {secret}\n"
            f"{bound}"
            "시크릿은 지금 한 번만 보입니다(저장된 것은 해시뿐). 사이트 설정에 바로 넣으세요."
        )
