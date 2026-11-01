import json
import tempfile
import unittest
from pathlib import Path

from server import app
from webapp.api_client import API_SCHEMA_VERSION, API_SCHEMA_VERSION_HEADER


class DashboardTestCase(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.original_api_url = app.config["API_URL"]
        self.original_config_path = app.config["CONFIG_PATH"]
        self.temp_dir = tempfile.TemporaryDirectory()
        app.config["API_URL"] = "http://127.0.0.1:8080"
        app.config["CONFIG_PATH"] = Path(self.temp_dir.name) / "web.json"

    def tearDown(self):
        app.config["API_URL"] = self.original_api_url
        app.config["CONFIG_PATH"] = self.original_config_path
        self.temp_dir.cleanup()


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
