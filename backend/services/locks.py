"""The one lock order for an account's rows (#145, #151).

Every transaction that changes an account's consents, refresh token families or refresh
tokens, or its member row, takes the locks in this order:

    account (`auth_user` row) → member → consent → refresh token family → refresh token

and starts with `lock_account`. Taking a later row first deadlocks with a transaction that
holds the account: InnoDB also takes the account row (shared) when it checks the foreign key of
a row it inserts (a consent, a family, a token, a terms agreement), and a member merge deletes
the account with its tokens. Paths that follow it: a code exchange and the consent check
(`oauth.tokens.lock_live_consent`), a consent given or replaced (`oauth.views._grant_consent`),
a consent revoked (`services.consents.revoke_consent`, so also 「연결 끊기」 and admin), a
refresh token rotated (`oauth.grants`), a withdrawal and its purge, a merge, terms agreed, the
account email set and a social login removed. Rows outside an account (clients, their secrets,
webhook deliveries, signing keys, throttle counters) are locked on their own and never inside
these.
"""

from django.contrib.auth.models import User


def lock_account(*user_ids: int) -> None:
    """Lock the accounts' rows until the transaction ends (in primary key order, so two
    transactions locking the same accounts queue). Call it first inside `transaction.atomic`."""
    list(User.objects.select_for_update().filter(pk__in=user_ids).order_by("pk").values("pk"))
