"""HTTP access to the C++ API: a transport contract and the API client on top."""
import json
import logging
import ssl
from dataclasses import dataclass
from time import perf_counter
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


logger = logging.getLogger(__name__)
API_SCHEMA_VERSION = "2"
API_SCHEMA_VERSION_HEADER = "X-Archangel-Schema-Version"
REQUEST_ID_HEADER = "X-Request-ID"


@dataclass
class ApiResponse:
    status: int
    body: bytes
    content_type: str
    schema_version: str | None
    # The backend's identifier for the request, from X-Request-ID.
    request_id: str | None = None


class ApiConnectionError(Exception):
    pass


class ApiResponseError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class ApiTransport(Protocol):
    """Sends one HTTP request to the C++ API.

    Implementations return every HTTP response, including error statuses, and
    raise ApiConnectionError only when no response was received.
    """

    def send(self, method, url, headers, body, timeout):
        """Send a request.

        Returns:
            ApiResponse with the status, body, and relevant headers.

        Raises:
            ApiConnectionError: If the API could not be reached.
        """
        ...


class UrllibTransport:
    """Transport using urllib with certificate verification for HTTPS URLs."""

    def __init__(self, ssl_context):
        self._ssl_context = ssl_context

    def send(self, method, url, headers, body, timeout):
        """Send a request with urllib.

        Returns:
            ApiResponse for any HTTP status.

        Raises:
            ApiConnectionError: If the API could not be reached, including
                TLS certificate verification failures.
        """
        request = Request(url, data=body, headers=headers, method=method)
        try:
            with urlopen(request, timeout=timeout, context=self._ssl_context) as response:
                return _response_from(response.status, response.read(), response.headers)
        except HTTPError as error:
            return _response_from(error.code, error.read(), error.headers)
        except (URLError, TimeoutError, OSError) as error:
            detail = getattr(error, "reason", error)
            raise ApiConnectionError(f"The C++ API is unavailable: {detail}") from error


def _response_from(status, body, headers):
    """Build an ApiResponse from urllib response parts.

    Returns:
        ApiResponse carrying the content type, schema version, and request ID.
    """
    return ApiResponse(
        status,
        body,
        headers.get("Content-Type", "application/json"),
        headers.get(API_SCHEMA_VERSION_HEADER),
        headers.get(REQUEST_ID_HEADER),
    )


def create_ssl_context(ca_bundle=None):
    """Create the TLS context used to verify the C++ API certificate.

    The system trust store is always used; a private CA bundle adds to it.
    Hostname and certificate verification cannot be disabled.

    Returns:
        An ssl.SSLContext requiring TLS 1.2 or newer.

    Raises:
        OSError, ssl.SSLError: If the CA bundle cannot be read or parsed.
    """
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_bundle is not None:
        context.load_verify_locations(cafile=str(ca_bundle))
    return context


class ApiClient:
    """Calls the C++ API at a fixed base URL through a transport."""

    def __init__(self, base_url, transport):
        self.base_url = base_url
        self._transport = transport

    def request(
        self,
        path,
        timeout=10,
        schema_version=API_SCHEMA_VERSION,
        method="GET",
        body=None,
        bearer_token=None,
    ):
        """Perform a request without decoding its body.

        Returns:
            ApiResponse containing the status, response bytes, and headers.

        Raises:
            ApiConnectionError: If the API cannot be reached.
        """
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        if schema_version is not None:
            headers[API_SCHEMA_VERSION_HEADER] = schema_version
        started = perf_counter()
        # Paths are logged without query parameters to avoid leaking caller-supplied
        # values that could contain tokens or other sensitive information.
        safe_path = urlsplit(path).path
        try:
            result = self._transport.send(method, f"{self.base_url}{path}", headers, body, timeout)
        except ApiConnectionError as error:
            logger.warning(
                "backend_request_failed method=%s path=%s error_type=%s duration_ms=%.1f",
                method,
                safe_path,
                type(error.__cause__ or error).__name__,
                (perf_counter() - started) * 1000,
            )
            raise

        log_method = logger.info if 200 <= result.status < 400 else logger.warning
        log_method(
            "backend_request_completed method=%s path=%s status=%s duration_ms=%.1f backend_request_id=%s",
            method,
            safe_path,
            result.status,
            (perf_counter() - started) * 1000,
            result.request_id or "none",
        )
        return result

    def fetch_json(self, path, timeout=10, bearer_token=None):
        """Request an API resource and decode its successful JSON response.

        Returns:
            The decoded JSON value.

        Raises:
            ApiConnectionError: If the API cannot be reached.
            ApiResponseError: If the response is not valid JSON or has a non-2xx
                status.
        """
        response = self.request(path, timeout, bearer_token=bearer_token)
        if response.schema_version != API_SCHEMA_VERSION:
            logger.warning(
                "backend_schema_version_mismatch path=%s expected=%s actual=%s",
                urlsplit(path).path,
                API_SCHEMA_VERSION,
                response.schema_version or "missing",
            )
            raise ApiResponseError("The API returned an unsupported schema version.", status=response.status)
        try:
            payload = json.loads(response.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            logger.warning(
                "backend_response_invalid path=%s error_type=%s",
                urlsplit(path).path,
                type(error).__name__,
            )
            raise ApiResponseError("The API returned invalid JSON.", status=response.status) from error

        if not 200 <= response.status < 300:
            detail = None
            if isinstance(payload, dict):
                detail = payload.get("detail") or payload.get("error")
            logger.warning(
                "backend_response_rejected path=%s status=%s",
                urlsplit(path).path,
                response.status,
            )
            raise ApiResponseError(
                detail or f"The API returned HTTP {response.status}.",
                status=response.status,
            )
        return payload
