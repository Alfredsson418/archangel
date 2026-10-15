import logging
import os
import sys
from time import perf_counter

from flask import Flask, g, request


def configure_logging(app: Flask) -> None:
    level_name = os.getenv("WEB_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))

    app.logger.handlers.clear()
    app.logger.addHandler(handler)
    app.logger.setLevel(level)
    app.logger.propagate = False

    @app.before_request
    def log_request_start():
        g.request_started_at = perf_counter()
        app.logger.info("request_started method=%s path=%s", request.method, request.path)

    @app.after_request
    def log_request_complete(response):
        started_at = getattr(g, "request_started_at", perf_counter())
        duration_ms = (perf_counter() - started_at) * 1000
        app.logger.info(
            "request_completed method=%s path=%s status=%s duration_ms=%.1f",
            request.method,
            request.path,
            response.status_code,
            duration_ms,
        )
        return response
