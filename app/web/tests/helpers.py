import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("ARCHANGEL_DEV_MODE", "true")

from server import app
from webapp.api_client import API_SCHEMA_VERSION, API_SCHEMA_VERSION_HEADER


TEST_ACTOR_ID = "0b6e4f0a-8a51-4c3e-9d2b-7f1e3c5a9d10"


class DashboardTestCase(unittest.TestCase):
    def setUp(self):
        self.original_api_url = app.config["API_URL"]
        self.original_session_database = app.config["SESSION_DATABASE"]
        self.temp_dir = tempfile.TemporaryDirectory()
        app.config["API_URL"] = "http://127.0.0.1:8080"
        app.config["SESSION_DATABASE"] = Path(self.temp_dir.name) / "sessions.db"
        self.client = app.test_client()
        with self.client.session_transaction() as browser_session:
            browser_session["access_token"] = "test-api-access-token"
            browser_session["actor_id"] = TEST_ACTOR_ID
            browser_session["_csrf_token"] = "test-csrf-token"

    def tearDown(self):
        app.config["API_URL"] = self.original_api_url
        app.config["SESSION_DATABASE"] = self.original_session_database
        self.temp_dir.cleanup()

    def csrf_token(self):
        with self.client.session_transaction() as browser_session:
            return browser_session["_csrf_token"]


class UpstreamResponse:
    def __init__(self, payload=None, *, status=200, schema_version=API_SCHEMA_VERSION):
        self.status = status
        self.headers = {"Content-Type": "application/json"}
        if schema_version is not None:
            self.headers[API_SCHEMA_VERSION_HEADER] = schema_version
        self.body = (
            payload
            if isinstance(payload, bytes)
            else json.dumps(payload if payload is not None else {}).encode()
        )

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self):
        return self.body
