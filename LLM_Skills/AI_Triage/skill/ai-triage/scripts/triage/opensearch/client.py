"""A small HTTP client for OpenSearch. Every request is checked by the read policy first."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Callable
from urllib.parse import urlencode, urlsplit

from triage.config import OpenSearchCluster
from triage.opensearch.policy import Request, check_request, normalise_path

# (method, url, body, timeout_seconds, verify_tls, ca_bundle) -> (status, response text)
Transport = Callable[[str, str, "bytes | None", int, bool, "str | None"], "tuple[int, str]"]

TIMEOUT_MARGIN_SECONDS = 5
MAX_ERROR_CHARS = 300
MAX_RESPONSE_BYTES = 10_000_000


class OpenSearchError(Exception):
    """A failed call. status is the HTTP status, or None when the network failed."""

    def __init__(self, message: str, status: int | None = None):
        self.status = status
        super().__init__(message)


class NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: a cluster does not redirect, and a followed one skips the read policy."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise OpenSearchError(f"refused a redirect (HTTP {code}) to {urlsplit(newurl).netloc or newurl}")


def build_ssl_context(verify_tls: bool, ca_bundle: str | None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=ca_bundle)
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _read_whole(response: Any) -> str:
    """Read the response; raise rather than return a body that was cut short."""
    data = response.read(MAX_RESPONSE_BYTES + 1)
    if len(data) > MAX_RESPONSE_BYTES:
        raise OpenSearchError(f"response was too large (over {MAX_RESPONSE_BYTES} bytes)")
    return data.decode("utf-8", errors="replace")


def urllib_transport(
    method: str, url: str, body: bytes | None, timeout_seconds: int, verify_tls: bool, ca_bundle: str | None
) -> tuple[int, str]:
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        opener = urllib.request.build_opener(
            NoRedirects(), urllib.request.HTTPSHandler(context=build_ssl_context(verify_tls, ca_bundle))
        )
        with opener.open(request, timeout=timeout_seconds) as response:
            return response.status, _read_whole(response)
    except urllib.error.HTTPError as error:
        return error.code, _read_whole(error)
    except OpenSearchError:
        raise
    except (OSError, ValueError) as error:  # URLError, ssl.SSLError and timeouts are OSError
        raise OpenSearchError(f"network failure: {error}") from error


class OpenSearchClient:
    def __init__(self, cluster: OpenSearchCluster, limits: dict[str, int], transport: Transport = urllib_transport):
        self._cluster = cluster
        self._limits = limits
        self._transport = transport

    def _url(self, request: Request) -> str:
        url = f"{self._cluster.endpoint.rstrip('/')}/{normalise_path(request.path)}"
        return f"{url}?{urlencode(request.params)}" if request.params else url

    def request(self, request: Request) -> Any:
        """Check the request, send it, and return parsed JSON, or the text when it is not JSON."""
        check_request(request, self._cluster, self._limits)
        body = json.dumps(request.body).encode("utf-8") if request.body is not None else None
        timeout = self._limits["opensearch_timeout_seconds"] + TIMEOUT_MARGIN_SECONDS
        try:
            status, text = self._transport(
                request.method,
                self._url(request),
                body,
                timeout,
                getattr(self._cluster, "verify_tls", True),
                getattr(self._cluster, "ca_bundle", None),
            )
        except OSError as error:
            raise OpenSearchError(f"network failure: {error}") from error
        if status >= 400:
            raise OpenSearchError(f"HTTP {status}: {text[:MAX_ERROR_CHARS]}", status)
        try:
            return json.loads(text)
        except ValueError:
            return text
