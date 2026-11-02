"""Per-user firewall changes that have been collected but not yet applied.

Kept in their own table, not the browser session, so that an expired sign-in
doesn't lose them. They authorize nothing: applying them needs a valid session
and passes through the API's own authorization.
"""
import json
import time

from flask import current_app


# Mirrors Config::Limits::MAX_FIREWALL_CHANGES; the backend is authoritative.
MAX_PENDING_CHANGES = 1000
PENDING_LIFETIME_SECONDS = 24 * 60 * 60


def _connect():
    """Open the owner-only dashboard store, creating the table if needed.

    Returns:
        An open sqlite3 connection, with expired entries removed.

    Raises:
        RuntimeError: If the store's file is unsafe.
    """
    connection = current_app.session_interface.connect(current_app)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS pending_changes ("
        "actor_id TEXT PRIMARY KEY NOT NULL,"
        "payload TEXT NOT NULL,"
        "expires_at INTEGER NOT NULL)"
    )
    connection.execute("DELETE FROM pending_changes WHERE expires_at <= ?", (int(time.time()),))
    connection.commit()
    return connection


def load(actor_id):
    """Load a user's pending changes.

    Returns:
        A dictionary with "changes", a list, and "revisions", the reviewed
        revision of each touched chain. Both are empty if nothing is pending.
    """
    connection = _connect()
    try:
        row = connection.execute(
            "SELECT payload FROM pending_changes WHERE actor_id = ?", (actor_id,)
        ).fetchone()
    finally:
        connection.close()
    return json.loads(row[0]) if row else {"changes": [], "revisions": {}}


def save(actor_id, pending):
    """Store a user's pending changes, restarting their expiry.

    Returns:
        None. Saving an empty list removes the user's entry.
    """
    connection = _connect()
    try:
        if pending["changes"]:
            connection.execute(
                "INSERT INTO pending_changes (actor_id, payload, expires_at) VALUES (?, ?, ?) "
                "ON CONFLICT(actor_id) DO UPDATE SET payload = excluded.payload, expires_at = excluded.expires_at",
                (
                    actor_id,
                    json.dumps(pending, separators=(",", ":"), allow_nan=False),
                    int(time.time()) + PENDING_LIFETIME_SECONDS,
                ),
            )
        else:
            connection.execute("DELETE FROM pending_changes WHERE actor_id = ?", (actor_id,))
        connection.commit()
    finally:
        connection.close()


def count(actor_id):
    """Count a user's pending changes without decoding them all in a template.

    Returns:
        The number of pending changes.
    """
    return len(load(actor_id)["changes"])
