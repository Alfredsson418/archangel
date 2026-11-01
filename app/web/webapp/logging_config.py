import json
import logging
import logging.handlers
import os
import re
import secrets
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

from flask import Flask, abort, g, has_request_context, request


DEFAULT_LOG_PATH = "/data/archangel-frontend.jsonl"
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_EVENT = re.compile(r"[a-z][a-z0-9_]*")
_FIELD = re.compile(r"([a-z][a-z0-9_]*)=(\S*)")


class RequestContextFilter(logging.Filter):
    """Adds the dashboard request ID and client address to records."""

    def filter(self, record):
        """Attach request_id and source_ip when inside a request.

        Returns:
            True, so the record is always emitted.
        """
        if has_request_context():
            record.request_id = getattr(g, "request_id", None)
            record.source_ip = request.remote_addr
        return True


class JsonlFormatter(logging.Formatter):
    """Formats records as one JSON object per line.

    A message written as an event name followed by key=value pairs becomes
    that event with those fields; any other message is recorded as event
    "message" with a message field.
    """

    def format(self, record):
        """Format one record.

        Returns:
            A JSON string with timestamp, level, service, category, event, and
            the record's fields.
        """
        line = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "service": "dashboard",
            "category": record.name,
        }
        message = record.getMessage()
        tokens = message.split()
        fields = [_FIELD.fullmatch(token) for token in tokens[1:]]
        if tokens and _EVENT.fullmatch(tokens[0]) and all(fields):
            line["event"] = tokens[0]
            for match in fields:
                line.setdefault(match.group(1), match.group(2))
        else:
            line["event"] = "message"
            line["message"] = message
        for key in ("request_id", "source_ip"):
            value = getattr(record, key, None)
            if value is not None:
                line.setdefault(key, value)
        return json.dumps(line, separators=(",", ":"))


def _prepare_log_file(path):
    """Create or check the owner-only audit log file.

    Returns:
        None.

    Raises:
        RuntimeError: If the directory or file is not owned by the service
            user or is accessible to group or others.
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.resolve(strict=True)
    parent_info = parent.stat()
    if parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) & 0o022:
        raise RuntimeError(
            "Dashboard log directory must be owned by the service user and "
            "not writable by group or others."
        )
    try:
        descriptor = os.open(
            path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError:
        pass
    else:
        os.close(descriptor)
    file_info = path.lstat()
    if (
        not stat.S_ISREG(file_info.st_mode)
        or file_info.st_uid != os.geteuid()
        or file_info.st_nlink != 1
        or stat.S_IMODE(file_info.st_mode) & 0o077
    ):
        raise RuntimeError(
            "Dashboard log file must be a regular file owned by the service "
            "user with no group or other permissions."
        )


class JsonlFileHandler(logging.handlers.WatchedFileHandler):
    """Appends JSONL records to an owner-only file.

    WatchedFileHandler reopens the file when it is renamed or removed, so the
    log can be rotated by the operating system without copytruncate.
    """

    def __init__(self, path):
        path = Path(path)
        _prepare_log_file(path)
        super().__init__(path, encoding="utf-8")
        self.setFormatter(JsonlFormatter())
        self.addFilter(RequestContextFilter())
        self._last_write_ok = True
        self._reported_failure = False

    def emit(self, record):
        """Write a record, remembering whether the write succeeded.

        Returns:
            None; failures are reported once on standard error.
        """
        self._last_write_ok = True
        super().emit(record)
        if self._last_write_ok and self._reported_failure:
            self._reported_failure = False
            sys.stderr.write("archangel-dashboard: log writes recovered\n")

    def handleError(self, record):
        """Record a failed write without echoing the record's content.

        Returns:
            None.
        """
        self._last_write_ok = False
        if not self._reported_failure:
            self._reported_failure = True
            sys.stderr.write("archangel-dashboard: log write failed\n")

    def write_audit(self, record):
        """Write an audit record that the caller must fail closed on.

        Returns:
            True when the record was written; False otherwise.
        """
        if not self.filter(record):
            return True
        self.acquire()
        try:
            self.emit(record)
            return self._last_write_ok
        finally:
            self.release()


def configure_logging(app: Flask) -> None:
    """Configure stdout and JSONL file logging and per-request events.

    Reads WEB_LOG_LEVEL and ARCHANGEL_WEB_LOG_PATH (default
    /data/archangel-frontend.jsonl).

    Returns:
        None. The Flask app is configured in place.

    Raises:
        RuntimeError: If the log file cannot be safely opened.
    """
    level_name = os.getenv("WEB_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    try:
        file_handler = JsonlFileHandler(os.getenv("ARCHANGEL_WEB_LOG_PATH", DEFAULT_LOG_PATH))
    except OSError as error:
        raise RuntimeError(f"Unable to open the dashboard log: {error.strerror or error}") from error

    app.logger.handlers.clear()
    app.logger.addHandler(stdout_handler)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(level)
    app.logger.propagate = False
    app.extensions["archangel_audit_log"] = file_handler

    @app.before_request
    def log_request_start():
        """Assign a request ID and record the start time and method/path."""
        g.request_id = secrets.token_hex(16)
        g.request_started_at = perf_counter()
        app.logger.info("request_started method=%s path=%s", request.method, request.path)

    @app.after_request
    def log_request_complete(response):
        """Log response status and elapsed time, then return the response."""
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


def install_audit_gate(app: Flask) -> None:
    """Refuse state-changing requests whose audit record cannot be written.

    Register after the CSRF and login checks so only requests that passed
    them are recorded.

    Returns:
        None. The Flask app is configured in place.
    """

    @app.before_request
    def record_state_change():
        if request.method not in STATE_CHANGING_METHODS:
            return None
        record = app.logger.makeRecord(
            app.logger.name,
            logging.INFO,
            __file__,
            0,
            "dashboard_request_authorized method=%s path=%s",
            (request.method, request.path),
            None,
        )
        if not app.extensions["archangel_audit_log"].write_audit(record):
            abort(503, description="Audit logging is unavailable; try again later.")
        return None
