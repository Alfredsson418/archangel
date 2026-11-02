import os
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, abort, redirect, request, session, url_for

from .api_client import ApiClient, UrllibTransport, create_ssl_context
from .audit_log import configure_logging, install_audit_gate
from .server_sessions import SqliteSessionInterface
from .settings import load_api_settings
from .views import pages
from . import rule_views  # noqa: F401  Registers its routes on the pages blueprint.


def create_app():
    """Create and configure the Flask dashboard application.

    Returns:
        The configured Flask application instance.
    """
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    configure_logging(app)
    secret_key = os.getenv("FLASK_SECRET_KEY")
    if not secret_key:
        if os.getenv("ARCHANGEL_DEV_MODE", "").lower() != "true":
            raise RuntimeError(
                "FLASK_SECRET_KEY must be configured outside development mode."
            )
        secret_key = secrets.token_hex(32)
        app.logger.warning(
            "dashboard_session_key_ephemeral sessions_will_reset_on_restart"
        )
    api_settings = load_api_settings()
    if api_settings.unencrypted_remote:
        app.logger.warning(
            "api_transport_unencrypted reason=non_loopback_http "
            "detail=backend_credentials_cross_the_network_in_plaintext"
        )
    try:
        ssl_context = create_ssl_context(api_settings.ca_bundle)
    except (OSError, ValueError) as error:
        raise RuntimeError("ARCHANGEL_API_CA_BUNDLE could not be loaded as PEM certificates.") from error
    secure_cookie = os.getenv("ARCHANGEL_COOKIE_SECURE", "").lower()
    if secure_cookie not in ("", "true", "false"):
        raise RuntimeError("ARCHANGEL_COOKIE_SECURE must be true or false.")
    app.config.update(
        SECRET_KEY=secret_key,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=secure_cookie == "true",
        SESSION_COOKIE_NAME="archangel_session",
        SESSION_IDLE_TIMEOUT=15 * 60,
        SESSION_ABSOLUTE_TIMEOUT=8 * 60 * 60,
        SESSION_DATABASE=Path(
            os.getenv("ARCHANGEL_SESSION_DATABASE", "/data/sessions.db")
        ),
        API_URL=api_settings.base_url,
        API_URL_FROM_ENV=api_settings.from_environment,
        API_CLIENT=ApiClient(api_settings.base_url, UrllibTransport(ssl_context)),
    )
    app.session_interface = SqliteSessionInterface()

    @app.before_request
    def protect_state_changes():
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return None
        origin = request.headers.get("Origin")
        if origin:
            parsed_origin = urlsplit(origin)
            if (
                parsed_origin.scheme not in {"http", "https"}
                or not parsed_origin.netloc
                or parsed_origin.netloc.lower() != request.host.lower()
            ):
                abort(403)
        expected = session.get("_csrf_token")
        supplied = request.form.get("csrf_token") or request.headers.get(
            "X-CSRF-Token"
        )
        if (
            not isinstance(expected, str)
            or not isinstance(supplied, str)
            or not secrets.compare_digest(expected, supplied)
        ):
            abort(400, description="The request security token is missing or invalid.")
        return None

    @app.before_request
    def require_dashboard_login():
        if request.endpoint in ("static", "pages.healthz"):
            return None
        if request.endpoint == "pages.login":
            if session.get("access_token"):
                return redirect(url_for("pages.index"))
            return None
        if not isinstance(session.get("access_token"), str):
            target = request.full_path if request.query_string else request.path
            return redirect(url_for("pages.login", next=target))
        return None

    @app.context_processor
    def inject_template_security_context():
        token = session.get("_csrf_token")
        if not isinstance(token, str):
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return {"csrf_token": token}

    install_audit_gate(app)
    app.register_blueprint(pages)
    return app
