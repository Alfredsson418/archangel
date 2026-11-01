from urllib.parse import urlsplit


DEFAULT_API_URL = "http://127.0.0.1:8080"


def valid_api_url(value):
    """Validate and normalize an HTTP(S) API base URL.

    Returns:
        The normalized URL, or None if the value is not an acceptable base URL.
    """
    if not isinstance(value, str):
        return None
    value = value.strip().rstrip("/")
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        return None
    if parsed.query or parsed.fragment:
        return None
    return value
