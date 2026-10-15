import json
import tempfile
import unittest
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlsplit
from unittest.mock import patch

from server import app


class DashboardTests(unittest.TestCase):
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

    @patch("webapp.api_client.urlopen")
    def test_dashboard_is_server_rendered(self, urlopen):
        class Upstream:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __init__(self, payload):
                self.body = json.dumps(payload).encode()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self):
                return self.body

        responses = {
            "/api/v1/rules": {"nftables": [
                {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 7, "expr": [{"accept": None}]}}
            ]},
            "/api/v1/stats": {
                "total_rules": 1,
                "total_tables": 1,
                "total_chains": 1,
                "rules_by_family": {"inet": 1},
                "rules_by_protocol": {"tcp": 1},
                "rules_by_verdict": {"accept": 1},
            },
            "/api/v1/system": {
                "hostname": "firewall",
                "cpu_cores": 6,
                "load_average": [0.12, 0.23, 0.34],
                "memory_used_bytes": 1024,
                "memory_total_bytes": 2048,
                "memory_usage_percent": 50,
                "disk_used_bytes": 1024,
                "disk_total_bytes": 4096,
                "disk_usage_percent": 25,
            },
        }
        urlopen.side_effect = lambda request, **kwargs: Upstream(responses[urlsplit(request.full_url).path])
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Network overview", response.data)
        self.assertIn(b"/static/styles.css", response.data)
        self.assertIn(b'href="/rules"', response.data)
        self.assertIn(b"API CONNECTED", response.data)
        self.assertIn(b"0.12 / 0.23 / 0.34", response.data)
        self.assertIn(b"6 online cores", response.data)
        self.assertIn(b"inet", response.data)
        self.assertNotIn(b"/static/app.js", response.data)
        self.assertEqual(urlopen.call_count, 3)
        response.close()

    @patch("webapp.api_client.urlopen")
    def test_rules_page_renders_backend_rules(self, urlopen):
        class Upstream:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self):
                return json.dumps({"nftables": [{"rule": {
                    "family": "inet",
                    "table": "filter",
                    "chain": "input",
                    "handle": 7,
                    "expr": [{"accept": None}],
                }}]}).encode()

        urlopen.return_value = Upstream()
        response = self.client.get("/rules")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Firewall rules", response.data)
        self.assertIn(b"filter", response.data)
        self.assertIn(b"input", response.data)
        self.assertIn(b"accept", response.data)
        self.assertNotIn(b"/static/app.js", response.data)
        urlopen.assert_called_once()
        response.close()

    @patch("webapp.api_client.urlopen", side_effect=URLError("connection refused"))
    def test_rules_page_renders_backend_failure(self, _urlopen):
        response = self.client.get("/rules")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"The C++ API is unavailable", response.data)
        self.assertIn(b"API UNAVAILABLE", response.data)
        response.close()

    def test_static_assets_are_served(self):
        response = self.client.get("/static/styles.css")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"--paper", response.data)
        response.close()

    def test_request_logging_omits_query_values(self):
        with self.assertLogs(app.logger, level="INFO") as captured:
            response = self.client.get("/config?token=do-not-log")
        self.assertEqual(response.status_code, 200)
        messages = "\n".join(captured.output)
        self.assertIn("request_started method=GET path=/config", messages)
        self.assertIn("request_completed method=GET path=/config status=200", messages)
        self.assertNotIn("do-not-log", messages)
        response.close()

    def test_configuration_page_is_rendered(self):
        response = self.client.get("/config")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"API base URL", response.data)
        self.assertIn(b'value="http://127.0.0.1:8080"', response.data)
        self.assertNotIn(b"config.js", response.data)
        response.close()

    def test_flask_does_not_expose_cpp_api_passthrough_routes(self):
        for path in ("/api/v1/rules", "/api/v1/stats", "/api/v1/system"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)

    def test_connection_settings_are_saved(self):
        response = self.client.post(
            "/config",
            data={"api_url": "http://10.0.0.5:8081/", "action": "save"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Connection saved.", response.data)
        self.assertEqual(app.config["API_URL"], "http://10.0.0.5:8081")
        self.assertEqual(json.loads(app.config["CONFIG_PATH"].read_text())["api_url"], app.config["API_URL"])

    def test_connection_settings_reject_invalid_urls(self):
        response = self.client.post("/config", data={"api_url": "file:///etc/passwd", "action": "save"})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Enter a valid HTTP or HTTPS API base URL", response.data)

    @patch("webapp.api_client.urlopen", side_effect=URLError("connection refused"))
    def test_connection_test_is_rendered_server_side(self, urlopen):
        response = self.client.post(
            "/config",
            data={"api_url": "http://10.0.0.5:8081", "action": "test"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"The C++ API is unavailable", response.data)
        self.assertEqual(app.config["API_URL"], "http://127.0.0.1:8080")
        urlopen.assert_called_once()

    def test_flask_does_not_expose_cpp_api_routes(self):
        for path in ("/api/v1/rules", "/api/v1/stats", "/api/v1/system"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)


if __name__ == "__main__":
    unittest.main()
