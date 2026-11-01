"""Deployment-fixed settings for reaching the C++ API."""
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


DEFAULT_API_URL = "http://127.0.0.1:8080"


@dataclass(frozen=True)
class ApiSettings:
    """Where and how the dashboard reaches the C++ API."""

    base_url: str
    # True when base_url came from ARCHANGEL_API_URL rather than the default.
    from_environment: bool
    # Optional private CA bundle trusted in addition to the system store.
    ca_bundle: Path | None


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


def load_api_settings(environ=os.environ):
    """Read the API settings fixed at deployment.

    Reads ARCHANGEL_API_URL (defaulting to DEFAULT_API_URL) and the optional
    ARCHANGEL_API_CA_BUNDLE. Browser users cannot change either value, so they
    cannot redirect the backend credentials the dashboard holds.

    Returns:
        A validated ApiSettings.

    Raises:
        RuntimeError: If the URL is invalid or the CA bundle is not a readable
            regular file.
    """
    configured_url = environ.get("ARCHANGEL_API_URL")
    base_url = valid_api_url(configured_url or DEFAULT_API_URL)
    if base_url is None:
        raise RuntimeError("ARCHANGEL_API_URL is invalid.")

    ca_bundle = None
    configured_bundle = environ.get("ARCHANGEL_API_CA_BUNDLE")
    if configured_bundle:
        ca_bundle = Path(configured_bundle)
        if not ca_bundle.is_file() or not os.access(ca_bundle, os.R_OK):
            raise RuntimeError("ARCHANGEL_API_CA_BUNDLE must name a readable PEM file.")
    return ApiSettings(base_url, bool(configured_url), ca_bundle)
