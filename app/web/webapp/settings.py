import json
import logging
import os
from pathlib import Path
from urllib.parse import urlsplit


logger = logging.getLogger(__name__)
DEFAULT_API_URL = os.getenv("ARCHANGEL_API_URL", "http://127.0.0.1:8080").rstrip("/")
CONFIG_PATH = Path(os.getenv(
    "ARCHANGEL_WEB_CONFIG",
    Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config")) / "archangel" / "web.json",
))


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


def load_api_url(path=CONFIG_PATH, default=DEFAULT_API_URL):
    """Load the saved API URL, falling back to a validated default.

    Returns:
        A valid API base URL; uses the built-in localhost URL if both settings
        are invalid.
    """
    saved = None
    try:
        config = json.loads(path.read_text())
    except FileNotFoundError:
        pass
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        logger.warning(
            "connection_setting_load_failed error_type=%s",
            type(error).__name__,
        )
    else:
        if isinstance(config, dict):
            saved = config.get("api_url")
            if "api_url" not in config:
                logger.warning("connection_setting_load_failed reason=missing_api_url")
            elif valid_api_url(saved) is None:
                logger.warning("connection_setting_rejected reason=invalid_saved_url")
        else:
            logger.warning("connection_setting_load_failed reason=invalid_format")

    api_url = valid_api_url(saved)
    if api_url is not None:
        return api_url

    # A missing or invalid saved value falls back to a validated configured
    # default so malformed local settings do not prevent dashboard startup.
    fallback = valid_api_url(default)
    if fallback is None:
        logger.error("default_connection_setting_invalid; using built_in_default")
        return "http://127.0.0.1:8080"
    return fallback


def save_api_url(path, api_url):
    """Persist the dashboard's API base URL as JSON.

    Returns:
        None.

    Raises:
        OSError: If the configuration directory or file cannot be written.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"api_url": api_url}) + "\n")
