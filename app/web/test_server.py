import json
import tempfile
import unittest
from pathlib import Path
from urllib.error import URLError
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

    def test_dashboard_is_served(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Network overview", response.data)
        self.assertIn(b"/static/styles.css", response.data)
        self.assertIn(b'href="/rules"', response.data)
        self.assertNotIn(b'id="all-rules"', response.data)
        response.close()

    @patch("server.urlopen")
    def test_rules_page_renders_backend_rules(self, urlopen):
        class Upstream:
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

    @patch("server.urlopen", side_effect=URLError("connection refused"))
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

    def test_configuration_page_is_rendered(self):
        response = self.client.get("/config")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"API base URL", response.data)
        self.assertIn(b'value="http://127.0.0.1:8080"', response.data)
        self.assertNotIn(b"config.js", response.data)
        response.close()

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

    @patch("server.urlopen", side_effect=URLError("connection refused"))
    def test_saved_connection_is_used_by_proxy(self, urlopen):
        self.client.post("/config", data={"api_url": "http://10.0.0.5:8081", "action": "save"})
        response = self.client.get("/api/v1/rules")
        self.assertEqual(response.status_code, 502)
        self.assertEqual(urlopen.call_args.args[0].full_url, "http://10.0.0.5:8081/api/v1/rules")

    @patch("server.urlopen")
    def test_backend_statistics_are_proxied(self, urlopen):
        class Upstream:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self):
                return json.dumps({"total_rules": 4, "rules_by_verdict": {"accept": 3, "drop": 1}}).encode()

        urlopen.return_value = Upstream()
        response = self.client.get("/api/v1/stats")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["total_rules"], 4)
        self.assertEqual(response.json["rules_by_verdict"]["drop"], 1)
        self.assertEqual(urlopen.call_args.args[0].full_url, "http://127.0.0.1:8080/api/v1/stats")

    @patch("server.urlopen")
    def test_system_statistics_are_proxied(self, urlopen):
        class Upstream:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self):
                return json.dumps({"cpu_cores": 8, "memory_usage_percent": 50.0}).encode()

        urlopen.return_value = Upstream()
        response = self.client.get("/api/v1/system")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["cpu_cores"], 8)
        self.assertEqual(urlopen.call_args.args[0].full_url, "http://127.0.0.1:8080/api/v1/system")

    @patch("server.urlopen", side_effect=URLError("connection refused"))
    def test_connection_test_is_rendered_server_side(self, urlopen):
        response = self.client.post(
            "/config",
            data={"api_url": "http://10.0.0.5:8081", "action": "test"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"The API could not be reached", response.data)
        self.assertEqual(app.config["API_URL"], "http://127.0.0.1:8080")
        urlopen.assert_called_once()

    @patch("server.urlopen")
    def test_rules_are_proxied(self, urlopen):
        class Upstream:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self):
                return json.dumps({"nftables": []}).encode()

        urlopen.return_value = Upstream()
        response = self.client.get("/api/v1/rules")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"nftables": []})
        urlopen.assert_called_once()

    @patch("server.urlopen")
    def test_statistics_are_proxied(self, urlopen):
        class Upstream:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self):
                return json.dumps({"total_rules": 2, "rules_by_family": {"inet": 2}}).encode()

        urlopen.return_value = Upstream()
        response = self.client.get("/api/v1/stats")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["total_rules"], 2)
        self.assertEqual(urlopen.call_args.args[0].full_url, "http://127.0.0.1:8080/api/v1/stats")

    @patch("server.urlopen", side_effect=OSError("connection refused"))
    def test_unavailable_backend_returns_gateway_error(self, _urlopen):
        response = self.client.get("/api/v1/rules")
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json["error"], "C++ API is unavailable")


if __name__ == "__main__":
    unittest.main()
