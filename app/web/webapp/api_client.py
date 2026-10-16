import json
import logging
from dataclasses import dataclass
from time import perf_counter
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


logger = logging.getLogger(__name__)


@dataclass
class ApiResponse:
    status: int
    body: bytes
    content_type: str


class ApiConnectionError(Exception):
    pass


class ApiResponseError(Exception):
    pass


def request_backend(api_url, path, timeout=10):
    """Perform an HTTP request to the C++ API without decoding its body.

    Returns:
        ApiResponse containing the status, response bytes, and content type.

    Raises:
        ApiConnectionError: If the API cannot be reached.
    """
    request = Request(f"{api_url}{path}", headers={"Accept": "application/json"})
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
            )
    except HTTPError as error:
        result = ApiResponse(
            error.code,
            error.read(),
            error.headers.get("Content-Type", "application/json"),
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


def test_api_connection(api_url):
    """Check API connectivity by requesting the active ruleset.

    Returns:
        A pair of (connected, human-readable result); expected connection and
        response errors are returned as a failed result rather than raised.
    """
    try:
        fetch_json(api_url, "/api/v1/rules", timeout=5)
        return True, "Connection successful. The API returned the active ruleset."
    except (ApiConnectionError, ApiResponseError) as error:
        return False, str(error)
