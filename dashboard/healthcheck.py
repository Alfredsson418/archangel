"""Container health probe for the dashboard listener.

Exits with status 0 when the dashboard answers /healthz on the configured
WEB_HOST and WEB_PORT, and non-zero otherwise.
"""
import os
import sys
from urllib.request import urlopen


def probe_url():
    """Build the health URL for the configured listener.

    Returns:
        An http URL string; wildcard binds are probed through loopback.
    """
    host = os.environ.get("WEB_HOST", "127.0.0.1")
    if host in ("", "0.0.0.0"):
        host = "127.0.0.1"
    elif host == "::":
        host = "::1"
    if ":" in host:
        host = f"[{host}]"
    # The image's ENV always sets WEB_PORT; repeating its default here would
    # let the two drift apart.
    return f"http://{host}:{os.environ['WEB_PORT']}/healthz"


if __name__ == "__main__":
    try:
        with urlopen(probe_url(), timeout=3) as response:
            sys.exit(0 if response.status == 204 else 1)
    except (KeyError, OSError):
        sys.exit(1)
