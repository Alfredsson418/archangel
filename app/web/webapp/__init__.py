import os
import secrets
from pathlib import Path

from flask import Flask

from .logging_config import configure_logging
from .settings import CONFIG_PATH, load_api_url
from .views import pages


def create_app():
    """Create and configure the Flask dashboard application.

    Returns:
        The configured Flask application instance.
    """
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    configure_logging(app)
    app.config.update(
        SECRET_KEY=os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        API_URL=load_api_url(),
        CONFIG_PATH=Path(os.getenv("ARCHANGEL_WEB_CONFIG", CONFIG_PATH)),
    )
    app.register_blueprint(pages)
    return app
