"""Loading C++ API resources for rendered pages with the session credential."""
from flask import current_app, session

from .api_client import ApiConnectionError, ApiResponseError, fetch_json


class BackendSessionExpired(Exception):
    """Raised when the backend rejects the dashboard's stored session."""


def fetch(path):
    """Fetch one API JSON resource with the browser session's credential.

    Returns:
        The decoded JSON payload.

    Raises:
        BackendSessionExpired: If the backend rejects the session; the browser
            session is cleared first.
        ApiConnectionError: If the backend cannot be reached.
        ApiResponseError: For other unsuccessful or invalid responses.
    """
    try:
        return fetch_json(
            current_app.config["API_URL"],
            path,
            bearer_token=session.get("access_token"),
        )
    except ApiResponseError as error:
        if error.status == 401:
            session.clear()
            raise BackendSessionExpired from error
        raise


def load(path):
    """Load one API JSON resource for a rendered page.

    Returns:
        A pair of (decoded payload, None) on success, or (None, error text) if
        the backend request fails.

    Raises:
        BackendSessionExpired: If the backend rejects the session.
    """
    try:
        return fetch(path), None
    except (ApiConnectionError, ApiResponseError) as error:
        return None, str(error)


def load_all(*paths):
    """Load several API resources, stopping once the backend is unreachable.

    Returns:
        A tuple of (payloads keyed by path, error messages, connected flag).
        Payloads are None for paths that failed or were skipped.

    Raises:
        BackendSessionExpired: If the backend rejects the session.
    """
    payloads = dict.fromkeys(paths)
    errors = []
    for path in paths:
        try:
            payloads[path] = fetch(path)
        except ApiConnectionError as error:
            # Later requests would wait for the same unreachable backend.
            errors.append(str(error))
            return payloads, errors, False
        except ApiResponseError as error:
            errors.append(str(error))
    return payloads, errors, True
