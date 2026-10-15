import json
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


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
    request = Request(f"{api_url}{path}", headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            return ApiResponse(
                response.status,
                response.read(),
                response.headers.get("Content-Type", "application/json"),
            )
    except HTTPError as error:
        return ApiResponse(
            error.code,
            error.read(),
            error.headers.get("Content-Type", "application/json"),
        )
    except (URLError, TimeoutError, OSError) as error:
        detail = getattr(error, "reason", error)
        raise ApiConnectionError(f"The C++ API is unavailable: {detail}") from error


def fetch_json(api_url, path, timeout=10):
    response = request_backend(api_url, path, timeout)
    try:
        payload = json.loads(response.body)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ApiResponseError("The API returned invalid JSON.") from error

    if not 200 <= response.status < 300:
        detail = None
        if isinstance(payload, dict):
            detail = payload.get("detail") or payload.get("error")
        raise ApiResponseError(detail or f"The API returned HTTP {response.status}.")
    return payload


def test_api_connection(api_url):
    try:
        fetch_json(api_url, "/api/v1/rules", timeout=5)
        return True, "Connection successful. The API returned the active ruleset."
    except (ApiConnectionError, ApiResponseError) as error:
        return False, str(error)
