from django.apps import AppConfig


class AccountsConfig(AppConfig):
    name = "accounts"
    verbose_name = "대표 계정"

    def ready(self) -> None:
        from accounts import signals  # noqa: F401  (connects the one-account guard)
