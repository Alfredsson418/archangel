import json
import os
from pathlib import Path
from urllib.parse import urlsplit


DEFAULT_API_URL = os.getenv("ARCHANGEL_API_URL", "http://127.0.0.1:8080").rstrip("/")
CONFIG_PATH = Path(os.getenv(
    "ARCHANGEL_WEB_CONFIG",
    Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config")) / "archangel" / "web.json",
))


def valid_api_url(value):
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
    try:
        saved = json.loads(path.read_text()).get("api_url")
    except (OSError, json.JSONDecodeError, AttributeError):
        saved = None
    return valid_api_url(saved) or valid_api_url(default) or "http://127.0.0.1:8080"


def save_api_url(path, api_url):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"api_url": api_url}) + "\n")
