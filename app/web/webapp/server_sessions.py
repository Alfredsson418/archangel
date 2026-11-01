import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import time
from pathlib import Path

from flask.sessions import SecureCookieSessionInterface, SessionMixin
from itsdangerous import BadSignature


_SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


class ServerSideSession(dict, SessionMixin):
    def __init__(self, initial=None, *, sid=None, new=False):
        super().__init__(initial or {})
        self.sid = sid or secrets.token_urlsafe(32)
        self.new = new
        self.modified = False
        self.rotate_id = False

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.modified = True

    def __delitem__(self, key):
        super().__delitem__(key)
        self.modified = True

    def clear(self):
        super().clear()
        self.modified = True

    def pop(self, key, default=None):
        if key in self:
            self.modified = True
        return super().pop(key, default)

    def update(self, *args, **kwargs):
        super().update(*args, **kwargs)
        self.modified = True

    def rotate(self):
        self.previous_sid = self.sid
        self.sid = secrets.token_urlsafe(32)
        self.rotate_id = True
        self.modified = True


class SqliteSessionInterface(SecureCookieSessionInterface):
    """Stores JSON session values in an owner-only SQLite database."""

    session_class = ServerSideSession

    def _connect(self, app):
        path = Path(app.config["SESSION_DATABASE"])
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = path.parent.resolve(strict=True)
        path = parent / path.name
        parent_info = parent.stat()
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != os.geteuid()
            or stat.S_IMODE(parent_info.st_mode) != 0o700
        ):
            raise RuntimeError(
                "Dashboard session directory must be owned by the service user "
                "and have mode 0700."
            )

        try:
            file_info = path.lstat()
        except FileNotFoundError:
            try:
                descriptor = os.open(
                    path,
                    os.O_CREAT
                    | os.O_EXCL
                    | os.O_RDWR
                    | getattr(os, "O_NOFOLLOW", 0),
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
            or stat.S_IMODE(file_info.st_mode) != 0o600
        ):
            raise RuntimeError(
                "Dashboard session database must be a regular file owned by "
                "the service user with mode 0600."
            )

        connection = sqlite3.connect(path, timeout=5)
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS web_sessions ("
            "session_hash TEXT PRIMARY KEY NOT NULL,"
            "payload TEXT NOT NULL,"
            "created_at INTEGER NOT NULL,"
            "last_used_at INTEGER NOT NULL,"
            "expires_at INTEGER NOT NULL)"
        )
        return connection

    @staticmethod
    def _hash(sid):
        return hashlib.sha256(sid.encode("ascii")).hexdigest()

    def open_session(self, app, request):
        cookie_value = request.cookies.get(self.get_cookie_name(app))
        serializer = self.get_signing_serializer(app)
        if not cookie_value or serializer is None:
            return self.session_class(new=True)
        try:
            sid = serializer.loads(
                cookie_value,
                max_age=int(app.config["SESSION_ABSOLUTE_TIMEOUT"]),
            )
        except BadSignature:
            return self.session_class(new=True)
        if not isinstance(sid, str) or not _SESSION_ID_PATTERN.fullmatch(sid):
            return self.session_class(new=True)

        now = int(time.time())
        idle_seconds = int(app.config["SESSION_IDLE_TIMEOUT"])
        connection = self._connect(app)
        try:
            connection.execute(
                "DELETE FROM web_sessions WHERE expires_at <= ? OR last_used_at <= ?",
                (now, now - idle_seconds),
            )
            connection.commit()
            row = connection.execute(
                "SELECT payload, created_at, last_used_at, expires_at "
                "FROM web_sessions WHERE session_hash = ?",
                (self._hash(sid),),
            ).fetchone()
            if row is None:
                return self.session_class(new=True)
            payload, created_at, _last_used_at, expires_at = row
            if expires_at <= now or now - created_at >= int(
                app.config["SESSION_ABSOLUTE_TIMEOUT"]
            ):
                connection.execute(
                    "DELETE FROM web_sessions WHERE session_hash = ?",
                    (self._hash(sid),),
                )
                connection.commit()
                return self.session_class(new=True)
            try:
                data = json.loads(payload)
            except json.JSONDecodeError as error:
                raise RuntimeError("Dashboard session data is invalid.") from error
            if not isinstance(data, dict):
                raise RuntimeError("Dashboard session data has an invalid shape.")
            connection.execute(
                "UPDATE web_sessions SET last_used_at = ? WHERE session_hash = ?",
                (now, self._hash(sid)),
            )
            connection.commit()
            return self.session_class(data, sid=sid)
        finally:
            connection.close()

    def save_session(self, app, session, response):
        cookie_name = self.get_cookie_name(app)
        connection = self._connect(app)
        try:
            if not session:
                connection.execute(
                    "DELETE FROM web_sessions WHERE session_hash = ?",
                    (self._hash(session.sid),),
                )
                if session.rotate_id:
                    connection.execute(
                        "DELETE FROM web_sessions WHERE session_hash = ?",
                        (self._hash(session.previous_sid),),
                    )
                connection.commit()
                response.delete_cookie(
                    cookie_name,
                    domain=self.get_cookie_domain(app),
                    path=self.get_cookie_path(app),
                    secure=self.get_cookie_secure(app),
                    httponly=self.get_cookie_httponly(app),
                    samesite=self.get_cookie_samesite(app),
                )
                return

            now = int(time.time())
            absolute_timeout = int(app.config["SESSION_ABSOLUTE_TIMEOUT"])
            expires_at = now + absolute_timeout
            payload = json.dumps(dict(session), separators=(",", ":"), allow_nan=False)
            connection.execute(
                "INSERT INTO web_sessions "
                "(session_hash, payload, created_at, last_used_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(session_hash) DO UPDATE SET "
                "payload = excluded.payload, last_used_at = excluded.last_used_at",
                (self._hash(session.sid), payload, now, now, expires_at),
            )
            if session.rotate_id:
                connection.execute(
                    "DELETE FROM web_sessions WHERE session_hash = ?",
                    (self._hash(session.previous_sid),),
                )
            connection.commit()
        finally:
            connection.close()

        serializer = self.get_signing_serializer(app)
        if serializer is None:
            raise RuntimeError("Dashboard session signing is not configured.")
        response.set_cookie(
            cookie_name,
            serializer.dumps(session.sid),
            max_age=absolute_timeout,
            httponly=self.get_cookie_httponly(app),
            secure=self.get_cookie_secure(app),
            samesite=self.get_cookie_samesite(app),
            domain=self.get_cookie_domain(app),
            path=self.get_cookie_path(app),
        )
