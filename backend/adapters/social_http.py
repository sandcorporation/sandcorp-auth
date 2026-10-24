"""HTTP to the social login providers (Google, Kakao): the token endpoint, Google's JWKS and
Kakao's user API. The hosts are fixed provider hosts, not caller-chosen URLs (unlike CIMD in
`http.py`), so there is no address pinning here.

Services call `get_provider_http()`; tests install a fake with `set_provider_http()`
(tests/conftest.py `fake_providers`, autouse, so no test ever reaches a real provider).
The real client never follows redirects and reads at most `MAX_BYTES`. A non-2xx answer comes
back as its status and body (providers explain errors in JSON); only a failure to get any
answer raises FetchError.
"""

import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Final, Protocol
from urllib.parse import urlencode

from adapters.http import FetchedDocument, FetchError

MAX_BYTES: Final = 1024 * 1024
TIMEOUT_SECONDS: Final = 10.0


class ProviderHttp(Protocol):
    def post_form(self, url: str, data: Mapping[str, str]) -> FetchedDocument:
        """POST `data` form-encoded to the https `url`."""
        ...

    def get(self, url: str, *, headers: Mapping[str, str]) -> FetchedDocument:
        """GET the https `url` with extra request `headers`."""
        ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


class UrllibProviderHttp:
    def __init__(self, *, timeout: float = TIMEOUT_SECONDS) -> None:
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _send(self, request: urllib.request.Request) -> FetchedDocument:
        if not request.full_url.startswith("https://"):
            raise FetchError(f"not an https URL: {request.full_url}")
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                headers = {k.lower(): v for k, v in response.getheaders()}
                return FetchedDocument(response.status, headers, response.read(MAX_BYTES))
        except urllib.error.HTTPError as error:  # 4xx/5xx (and an unfollowed 3xx)
            headers = {k.lower(): v for k, v in error.headers.items()}
            return FetchedDocument(error.code, headers, error.read(MAX_BYTES))
        except (OSError, ValueError) as error:  # URLError, timeout, TLS
            raise FetchError(str(error) or type(error).__name__) from error

    def post_form(self, url: str, data: Mapping[str, str]) -> FetchedDocument:
        body = urlencode(dict(data)).encode()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            "Accept": "application/json",
        }
        return self._send(urllib.request.Request(url, data=body, headers=headers, method="POST"))

    def get(self, url: str, *, headers: Mapping[str, str]) -> FetchedDocument:
        request_headers = {"Accept": "application/json", **headers}
        return self._send(urllib.request.Request(url, headers=request_headers, method="GET"))


_provider_http: ProviderHttp = UrllibProviderHttp()


def get_provider_http() -> ProviderHttp:
    return _provider_http


def set_provider_http(client: ProviderHttp) -> ProviderHttp:
    """Install `client` and return the previous one so callers can restore it."""
    global _provider_http
    previous, _provider_http = _provider_http, client
    return previous
