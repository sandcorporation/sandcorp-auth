from django.db import models


class AuditEvent(models.Model):
    """One security-relevant event. Written by `services.audit.record`, never edited.

    `kind` is a free string (constants in `services.audit`); `detail` never holds a secret
    (password, code, token).
    """

    at = models.DateTimeField(db_index=True)
    kind = models.CharField(max_length=64, db_index=True)
    actor = models.CharField(max_length=150, blank=True, db_index=True)
    client_id = models.CharField(max_length=255, blank=True)
    ip = models.CharField(max_length=45, blank=True)
    detail = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-at", "-id"]
        verbose_name = "감사 사건"
        verbose_name_plural = "감사 로그"

    def __str__(self) -> str:
        return f"{self.at:%Y-%m-%d %H:%M:%S} {self.kind} {self.actor}".rstrip()
