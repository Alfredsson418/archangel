import json
import logging
from dataclasses import dataclass
from time import perf_counter
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


logger = logging.getLogger(__name__)
API_SCHEMA_VERSION = "1"
API_SCHEMA_VERSION_HEADER = "X-Archangel-Schema-Version"


@dataclass
class ApiResponse:
    status: int
    body: bytes
    content_type: str
    schema_version: str | None


class ApiConnectionError(Exception):
    pass


class ApiResponseError(Exception):
    pass


def request_backend(
    api_url,
    path,
    timeout=10,
    schema_version=API_SCHEMA_VERSION,
    method="GET",
    body=None,
):
    """Perform an HTTP request to the C++ API without decoding its body.

    Returns:
        ApiResponse containing the status, response bytes, and content type.

    Raises:
        ApiConnectionError: If the API cannot be reached.
    """
    headers = {"Accept": "application/json"}
    if schema_version is not None:
        headers[API_SCHEMA_VERSION_HEADER] = schema_version
    request = Request(f"{api_url}{path}", data=body, headers=headers, method=method)
    started = perf_counter()
    # Paths are logged without query parameters to avoid leaking caller-supplied
    # values that could contain tokens or other sensitive information.
    safe_path = urlsplit(path).path
    try:
        with urlopen(request, timeout=timeout) as response:
            result = ApiResponse(
                response.status,
                response.read(),
                response.headers.get("Content-Type", "application/json"),
                response.headers.get(API_SCHEMA_VERSION_HEADER),
            )
    except HTTPError as error:
        result = ApiResponse(
            error.code,
            error.read(),
            error.headers.get("Content-Type", "application/json"),
            error.headers.get(API_SCHEMA_VERSION_HEADER),
        )
    except (URLError, TimeoutError, OSError) as error:
        duration_ms = (perf_counter() - started) * 1000
        logger.warning(
            "backend_request_failed method=%s path=%s error_type=%s duration_ms=%.1f",
            request.get_method(),
            safe_path,
            type(error).__name__,
            duration_ms,
        )
        detail = getattr(error, "reason", error)
        raise ApiConnectionError(f"The C++ API is unavailable: {detail}") from error

    duration_ms = (perf_counter() - started) * 1000
    log_method = logger.info if 200 <= result.status < 400 else logger.warning
    log_method(
        "backend_request_completed method=%s path=%s status=%s duration_ms=%.1f",
        request.get_method(),
        safe_path,
        result.status,
        duration_ms,
    )
    return result


def fetch_json(api_url, path, timeout=10):
    """Request an API resource and decode its successful JSON response.

    Returns:
        The decoded JSON value.

    Raises:
        ApiConnectionError: If the API cannot be reached.
        ApiResponseError: If the response is not valid JSON or has a non-2xx
            status.
    """
    response = request_backend(api_url, path, timeout)
    if response.schema_version != API_SCHEMA_VERSION:
        logger.warning(
            "backend_schema_version_mismatch path=%s expected=%s actual=%s",
            urlsplit(path).path,
            API_SCHEMA_VERSION,
            response.schema_version or "missing",
        )
        raise ApiResponseError("The API returned an unsupported schema version.")
    try:
        payload = json.loads(response.body)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        logger.warning(
            "backend_response_invalid path=%s error_type=%s",
            urlsplit(path).path,
            type(error).__name__,
        )
        raise ApiResponseError("The API returned invalid JSON.") from error

    if not 200 <= response.status < 300:
        detail = None
        if isinstance(payload, dict):
            detail = payload.get("detail") or payload.get("error")
        logger.warning(
            "backend_response_rejected path=%s status=%s",
            urlsplit(path).path,
            response.status,
        )
        raise ApiResponseError(detail or f"The API returned HTTP {response.status}.")
    return payload


def check_api_health(api_url):
    """Check whether the backend is online using its unauthenticated health route.

    Returns:
        A pair of (online, human-readable result).

    Raises:
        ApiConnectionError: If the API cannot be reached.
        ApiResponseError: If the health endpoint returns a non-success status.
    """
    response = request_backend(
        api_url, "/status/health", timeout=5, schema_version=None
    )
    if not 200 <= response.status < 300:
        raise ApiResponseError(
            f"The API health check returned HTTP {response.status}."
        )
    return True, "Health check successful. The API is online."


def test_api_connection(api_url):
    """Check API connectivity using the health route.

    Returns:
        A pair of (connected, human-readable result).
    """
    try:
        return check_api_health(api_url)
    except (ApiConnectionError, ApiResponseError) as error:
        return False, str(error)
