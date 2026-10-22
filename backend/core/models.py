from django.db import models


class ThrottleCounter(models.Model):
    """Failures counted for one key (e.g. `login:user:farrar142`) in the current window.

    A row whose window and block have both passed is simply reused by the next hit.
    """

    key = models.CharField(max_length=255, unique=True)
    window_started_at = models.DateTimeField()
    count = models.PositiveIntegerField(default=0)
    blocked_until = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.key} ({self.count})"
