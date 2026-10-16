import json
import io
import tempfile
import unittest
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlsplit
from unittest.mock import patch

from server import app
from webapp.api_client import (
    API_SCHEMA_VERSION,
    API_SCHEMA_VERSION_HEADER,
    ApiResponseError,
    check_api_health,
    fetch_json,
    request_backend,
)
from webapp.settings import load_api_url
from webapp.views import _firewall_status


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

    def test_firewall_status_requires_a_base_chain_hook(self):
        self.assertEqual(
            _firewall_status(
                {
                    "nftables": [
                        {"chain": {"name": "input"}},
                        {"chain": {"name": "forward", "hook": "forward"}},
                    ]
                }
            ),
            ("Active", 1),
        )
        self.assertEqual(_firewall_status({"nftables": []}), ("No active base chains", 0))
        self.assertEqual(_firewall_status(None), ("Unavailable", None))

    @patch("webapp.api_client.urlopen")
    def test_dashboard_is_server_rendered(self, urlopen):
        class Upstream:
            status = 200
            headers = {
                "Content-Type": "application/json",
                API_SCHEMA_VERSION_HEADER: API_SCHEMA_VERSION,
            }

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
                {"chain": {"family": "inet", "table": "filter", "name": "input", "hook": "input"}},
                {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 7, "expr": [{"accept": None}]}}
            ]},
            "/api/v1/system": {
                "hostname": "firewall",
                "cpu_cores": 6,
                "load_average": [0.12, 0.23, 0.34],
                "uptime_seconds": 93784,
                "memory_used_bytes": 1024,
                "memory_total_bytes": 2048,
                "memory_usage_percent": 50,
                "disk_used_bytes": 1024,
                "disk_total_bytes": 4096,
                "disk_usage_percent": 25,
            },
            "/status/info": {
                "status": "ok",
                "backend_version": "abc123",
                "api_version": "v1",
                "uptime_seconds": 120,
            },
            "/status/health": {},
        }
        urlopen.side_effect = lambda request, **kwargs: Upstream(responses[urlsplit(request.full_url).path])
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Server overview", response.data)
        self.assertIn(b"/static/styles.css", response.data)
        self.assertIn(b'href="/rules"', response.data)
        self.assertIn(b'href="/system"', response.data)
        self.assertIn(b"API CONNECTED", response.data)
        self.assertIn(b"0.12 / 0.23 / 0.34", response.data)
        self.assertIn(b"6 online cores", response.data)
        self.assertIn(b"Active", response.data)
        self.assertIn(b"abc123", response.data)
        self.assertIn(b"1d 2h 3m", response.data)
        self.assertNotIn(b"filter", response.data)
        self.assertNotIn(b"accept", response.data)
        self.assertNotIn(b"/static/app.js", response.data)
        self.assertEqual(urlopen.call_count, 4)
        self.assertEqual(
            urlopen.call_args_list[-1].args[0].full_url,
            "http://127.0.0.1:8080/status/health",
        )
        health_headers = {
            name.lower(): value
            for name, value in urlopen.call_args_list[-1].args[0].headers.items()
        }
        self.assertNotIn(API_SCHEMA_VERSION_HEADER.lower(), health_headers)
        self.assertTrue(
            all(
                {
                    name.lower(): value
                    for name, value in call.args[0].headers.items()
                }.get(API_SCHEMA_VERSION_HEADER.lower())
                == API_SCHEMA_VERSION
                for call in urlopen.call_args_list[:3]
            )
        )
        response.close()

    @patch("webapp.api_client.urlopen")
    def test_rules_page_renders_backend_rules(self, urlopen):
        class Upstream:
            status = 200
            headers = {
                "Content-Type": "application/json",
                API_SCHEMA_VERSION_HEADER: API_SCHEMA_VERSION,
            }

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
        self.assertIn(b"Firewall configuration", response.data)
        self.assertIn(b"filter", response.data)
        self.assertIn(b"input", response.data)
        self.assertIn(b"accept", response.data)
        self.assertNotIn(b"/static/app.js", response.data)
        urlopen.assert_called_once()
        response.close()

    @patch("webapp.api_client.urlopen")
    def test_rules_page_filters_sorts_and_disables_edit(self, urlopen):
        class Upstream:
            status = 200
            headers = {
                "Content-Type": "application/json",
                API_SCHEMA_VERSION_HEADER: API_SCHEMA_VERSION,
            }

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self):
                return json.dumps(
                    {
                        "nftables": [
                            {"rule": {"family": "ip", "table": "filter", "chain": "input", "handle": 9, "expr": [{"drop": None}]}},
                            {"rule": {"family": "inet", "table": "filter", "chain": "forward", "handle": 10, "expr": [{"accept": None}]}},
                        ]
                    }
                ).encode()

        urlopen.return_value = Upstream()
        response = self.client.get("/rules?sort=chain&direction=desc")
        self.assertEqual(response.status_code, 200)
        self.assertLess(
            response.data.index(b'<td class="code-cell">input</td>'),
            response.data.index(b'<td class="code-cell">forward</td>'),
        )
        self.assertIn(b"Edit", response.data)
        self.assertIn(b"disabled", response.data)
        self.assertIn(b"Search family, table, chain", response.data)
        self.assertIn(b"2 matching / 2 total", response.data)
        response.close()
        response = self.client.get("/rules?sort=handle&direction=asc")
        self.assertEqual(response.status_code, 200)
        self.assertLess(
            response.data.index(b'<td class="code-cell">9</td>'),
            response.data.index(b'<td class="code-cell">10</td>'),
        )
        response.close()
        response = self.client.get("/rules?q=forward&sort=chain&direction=desc")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'<td class="code-cell">forward</td>', response.data)
        self.assertNotIn(b'<td class="code-cell">input</td>', response.data)
        response.close()

    @patch("webapp.api_client.urlopen")
    def test_rules_page_reports_invalid_backend_ruleset_instead_of_empty_rules(self, urlopen):
        class Upstream:
            status = 200
            headers = {
                "Content-Type": "application/json",
                API_SCHEMA_VERSION_HEADER: API_SCHEMA_VERSION,
            }

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self):
                return b"{}"

        urlopen.return_value = Upstream()
        response = self.client.get("/rules")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"invalid firewall ruleset response", response.data)
        self.assertNotIn(b"The backend returned no rules", response.data)
        response.close()

    @patch("webapp.api_client.urlopen")
    def test_rules_export_contains_only_supported_portable_rules(self, urlopen):
        class Upstream:
            status = 200
            headers = {
                "Content-Type": "application/json",
                API_SCHEMA_VERSION_HEADER: API_SCHEMA_VERSION,
            }

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self):
                return json.dumps(
                    {
                        "nftables": [
                            {
                                "rule": {
                                    "family": "inet",
                                    "table": "filter",
                                    "chain": "input",
                                    "handle": 1,
                                    "expr": [
                                        {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}},
                                        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}},
                                        {"accept": None},
                                    ],
                                }
                            },
                            {
                                "rule": {
                                    "family": "inet",
                                    "table": "filter",
                                    "chain": "input",
                                    "handle": 2,
                                    "expr": [{"log": {"prefix": "custom"}}],
                                }
                            },
                        ]
                    }
                ).encode()

        urlopen.return_value = Upstream()
        response = self.client.get("/rules/export")
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment; filename=\"archangel-firewall-rules.json\"", response.headers["Content-Disposition"])
        self.assertEqual(response.headers["X-Archangel-Skipped-Rules"], "1")
        bundle = json.loads(response.data)
        self.assertEqual(bundle["format"], "archangel-firewall-rules")
        self.assertEqual(bundle["version"], 1)
        self.assertEqual(bundle["omitted_unsupported_rules"], 1)
        self.assertEqual(bundle["rules"], [{
            "family": "inet",
            "table": "filter",
            "chain": "input",
            "protocol": "tcp",
            "action": "accept",
            "destination_port": 443,
        }])
        response.close()

    @patch("webapp.api_client.urlopen")
    def test_rule_import_previews_then_adds_with_explicit_confirmation(self, urlopen):
        class Upstream:
            status = 201
            headers = {
                "Content-Type": "application/json",
                API_SCHEMA_VERSION_HEADER: API_SCHEMA_VERSION,
            }

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self):
                return b'{"status":"created"}'

        urlopen.return_value = Upstream()
        bundle = {
            "format": "archangel-firewall-rules",
            "version": 1,
            "rules": [{
                "family": "inet",
                "table": "filter",
                "chain": "input",
                "protocol": "tcp",
                "destination_port": 443,
                "action": "accept",
            }],
        }
        preview = self.client.post(
            "/rules/import",
            data={
                "action": "preview",
                "bundle_file": (io.BytesIO(json.dumps(bundle).encode()), "rules.json"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(preview.status_code, 200)
        self.assertIn(b"1 rules will be added", preview.data)
        self.assertIn(b"not atomic", preview.data)
        urlopen.assert_not_called()
        with self.client.session_transaction() as session:
            csrf_token = session["rules_import_csrf"]
        preview.close()

        imported = self.client.post(
            "/rules/import",
            data={
                "action": "apply",
                "confirm": "yes",
                "csrf_token": csrf_token,
                "bundle": json.dumps(bundle),
            },
        )
        self.assertEqual(imported.status_code, 200)
        self.assertIn(b"Successfully added 1 rules", imported.data)
        api_request = urlopen.call_args.args[0]
        self.assertEqual(api_request.get_method(), "POST")
        self.assertEqual(api_request.full_url, "http://127.0.0.1:8080/api/v1/rules")
        self.assertEqual(json.loads(api_request.data), bundle["rules"][0])
        imported.close()

    def test_rule_import_requires_a_valid_confirmation_token(self):
        response = self.client.post(
            "/rules/import",
            data={
                "action": "apply",
                "confirm": "yes",
                "csrf_token": "invalid",
                "bundle": "{}",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"confirmation expired or is invalid", response.data)
        response.close()

    @patch("webapp.api_client.urlopen")
    def test_system_management_page_is_read_only_and_shows_server_status(self, urlopen):
        class Upstream:
            status = 200
            headers = {
                "Content-Type": "application/json",
                API_SCHEMA_VERSION_HEADER: API_SCHEMA_VERSION,
            }

            def __init__(self, payload):
                self.body = json.dumps(payload).encode()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self):
                return self.body

        responses = {
            "/api/v1/system": {
                "hostname": "gateway-01",
                "cpu_cores": 4,
                "load_average": [0.1, 0.2, 0.3],
                "uptime_seconds": 90061,
                "memory_used_bytes": 1024,
                "memory_total_bytes": 2048,
                "memory_usage_percent": 50,
                "disk_used_bytes": 1024,
                "disk_total_bytes": 4096,
                "disk_usage_percent": 25,
            },
            "/status/info": {
                "status": "ok",
                "backend_version": "commit-42",
                "api_version": "v1",
                "uptime_seconds": 3661,
            },
            "/status/health": {},
        }
        urlopen.side_effect = lambda request, **kwargs: Upstream(
            responses[urlsplit(request.full_url).path]
        )
        response = self.client.get("/system")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"System management", response.data)
        self.assertIn(b"gateway-01", response.data)
        self.assertIn(b"1d 1h 1m", response.data)
        self.assertIn(b"1h 1m", response.data)
        self.assertIn(b"commit-42", response.data)
        self.assertIn(b"Restart Archangel", response.data)
        self.assertIn(b"disabled", response.data)
        self.assertIn(b"Restart controls are unavailable", response.data)
        response.close()

    @patch("webapp.api_client.urlopen")
    def test_system_logs_page_renders_sources_and_escapes_log_entries(self, urlopen):
        class Upstream:
            status = 200
            headers = {
                "Content-Type": "application/json",
                API_SCHEMA_VERSION_HEADER: API_SCHEMA_VERSION,
            }

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self):
                return json.dumps(
                    {
                        "sources": [
                            {
                                "id": "archangel",
                                "label": "Archangel application",
                                "available": True,
                                "detail": "Showing recent application events.",
                                "entries": [
                                    '[INFO:API] request_completed path=/status/info',
                                    "<script>alert(1)</script>",
                                ],
                            },
                            {
                                "id": "nftables",
                                "label": "nftables packet logs",
                                "available": False,
                                "detail": "No nftables log statements are configured.",
                                "entries": [],
                            },
                        ]
                    }
                ).encode()

        urlopen.return_value = Upstream()
        response = self.client.get("/system/logs")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Application logs", response.data)
        self.assertIn(b"Archangel application", response.data)
        self.assertIn(b"nftables packet logs", response.data)
        self.assertIn(b"No nftables log statements are configured.", response.data)
        self.assertIn(b"&lt;script&gt;", response.data)
        self.assertNotIn(b"<script>", response.data)
        self.assertIn(b'href="/system"', response.data)
        urlopen.assert_called_once()
        self.assertEqual(
            urlopen.call_args.args[0].full_url,
            "http://127.0.0.1:8080/api/v1/logs",
        )
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

    @patch("webapp.api_client.urlopen")
    def test_backend_request_logging_includes_outcome_without_query_values(
        self, urlopen
    ):
        class Upstream:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self):
                return b"{}"

        urlopen.return_value = Upstream()
        with self.assertLogs("webapp.api_client", level="INFO") as captured:
            response = request_backend(
                "http://127.0.0.1:8080",
                "/api/v1/rules?token=do-not-log",
            )
        self.assertEqual(response.status, 200)
        messages = "\n".join(captured.output)
        self.assertIn(
            "backend_request_completed method=GET path=/api/v1/rules status=200",
            messages,
        )
        self.assertNotIn("do-not-log", messages)

    @patch("webapp.api_client.urlopen")
    def test_health_check_uses_empty_unauthenticated_route(self, urlopen):
        class Upstream:
            status = 200
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self):
                return b""

        urlopen.return_value = Upstream()
        self.assertTrue(check_api_health("http://127.0.0.1:8080")[0])
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:8080/status/health")
        self.assertNotIn(
            API_SCHEMA_VERSION_HEADER.lower(),
            {name.lower() for name in request.headers},
        )

    @patch("webapp.api_client.urlopen")
    def test_json_request_rejects_mismatched_schema_version(self, urlopen):
        class Upstream:
            status = 200
            headers = {
                "Content-Type": "application/json",
                API_SCHEMA_VERSION_HEADER: "2",
            }

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self):
                return b'{"value": true}'

        urlopen.return_value = Upstream()
        with self.assertRaisesRegex(ApiResponseError, "unsupported schema version"):
            fetch_json("http://127.0.0.1:8080", "/api/v1/test")

    def test_configuration_page_is_rendered(self):
        response = self.client.get("/config")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"API base URL", response.data)
        self.assertIn(b'value="http://127.0.0.1:8080"', response.data)
        self.assertNotIn(b"config.js", response.data)
        response.close()

    def test_invalid_saved_api_configuration_is_logged_and_ignored(self):
        config_path = Path(self.temp_dir.name) / "invalid.json"
        config_path.write_text("{invalid")
        with self.assertLogs("webapp.settings", level="WARNING") as captured:
            api_url = load_api_url(config_path, "http://127.0.0.1:8081")
        self.assertEqual(api_url, "http://127.0.0.1:8081")
        self.assertIn("connection_setting_load_failed", "\n".join(captured.output))

    def test_flask_does_not_expose_cpp_api_passthrough_routes(self):
        for path in (
            "/api/v1/rules",
            "/api/v1/stats",
            "/api/v1/system",
            "/api/v1/logs",
        ):
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
        for path in (
            "/api/v1/rules",
            "/api/v1/stats",
            "/api/v1/system",
            "/api/v1/logs",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)


if __name__ == "__main__":
    unittest.main()
