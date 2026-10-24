"""HTTP for outgoing webhooks (#39): one POST of a signed JSON body to a client's webhook URL.

The URL is set by the operator (admin, `clients webhook`), not by the client itself, so there is
no address pinning as in `http.py` (CIMD). It must be https; redirects are not followed (a 3xx
is a failed delivery). Any answer comes back as its status; only a failure to get one raises
FetchError.

`webhooks deliver` calls `get_webhook_http()`; tests install a fake with `set_webhook_http()`
(tests/conftest.py `fake_webhooks`, autouse, so no test ever reaches a real host).
"""

import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Final, Protocol

from adapters.http import FetchError

TIMEOUT_SECONDS: Final = 10.0
MAX_BYTES: Final = 4096


class WebhookHttp(Protocol):
    def post(self, url: str, body: bytes, *, headers: Mapping[str, str]) -> int:
        """POST `body` (JSON) to the https `url`; return the response status."""
        ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


class UrllibWebhookHttp:
    def __init__(self, *, timeout: float = TIMEOUT_SECONDS) -> None:
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect)

    def post(self, url: str, body: bytes, *, headers: Mapping[str, str]) -> int:
        if not url.startswith("https://"):
            raise FetchError(f"not an https URL: {url}")
        request_headers = {"Content-Type": "application/json", **headers}
        request = urllib.request.Request(url, data=body, headers=request_headers, method="POST")
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                response.read(MAX_BYTES)
                status: int = response.status
                return status
        except urllib.error.HTTPError as error:  # 4xx/5xx (and an unfollowed 3xx)
            return error.code
        except (OSError, ValueError) as error:  # URLError, timeout, TLS
            raise FetchError(str(error) or type(error).__name__) from error


_webhook_http: WebhookHttp = UrllibWebhookHttp()


def get_webhook_http() -> WebhookHttp:
    return _webhook_http


def set_webhook_http(client: WebhookHttp) -> WebhookHttp:
    """Install `client` and return the previous one so callers can restore it."""
    global _webhook_http
    previous, _webhook_http = _webhook_http, client
    return previous
