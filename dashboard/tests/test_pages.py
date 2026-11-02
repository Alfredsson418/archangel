from urllib.parse import urlsplit
from unittest.mock import patch

from webapp.api_client import API_SCHEMA_VERSION

from .helpers import DashboardTestCase, UpstreamResponse


class DashboardPageTests(DashboardTestCase):
    def test_pages_load_nothing_from_other_sites(self):
        # Isolated networks can't reach them.
        response = self.client.get("/login")
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
        response.close()
        response = self.client.get("/login")
        self.assertNotIn(b"https://", response.data)
        self.assertNotIn(b"http://", response.data)
        response.close()

    def test_bundled_fonts_are_served(self):
        response = self.client.get("/static/styles.css")
        self.assertIn(b"vendor/fonts/manrope-latin-400-normal.woff2", response.data)
        response.close()
        for font in ("manrope-latin-400-normal.woff2", "dm-mono-latin-400-normal.woff2"):
            response = self.client.get(f"/static/vendor/fonts/{font}")
            self.assertEqual(response.status_code, 200)
            response.close()

    @patch("webapp.api_client.urlopen")
    def test_dashboard_renders_server_health_and_summary(self, urlopen):
        responses = {
            "/api/v1/rules": {
                "nftables": [
                    {"chain": {"family": "inet", "table": "filter", "name": "input", "hook": "input"}},
                    {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 7, "expr": [{"accept": None}]}},
                ]
            },
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
        }
        urlopen.side_effect = lambda request, **_kwargs: UpstreamResponse(
            responses[urlsplit(request.full_url).path]
        )

        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        for expected in (
            b"Server overview",
            b"/static/styles.css",
            b'href="/rules"',
            b'href="/system"',
            b"API CONNECTED",
            b"0.12 / 0.23 / 0.34",
            b"6 online cores",
            b"Active",
            b"abc123",
            b"1d 2h 3m",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, response.data)
        self.assertNotIn(b"filter", response.data)
        self.assertNotIn(b"accept", response.data)
        self.assertNotIn(b"/static/app.js", response.data)
        self.assertEqual(urlopen.call_count, 3)
        self.assertTrue(
            all(
                {
                    name.lower(): value
                    for name, value in call.args[0].headers.items()
                }.get("x-archangel-schema-version")
                == API_SCHEMA_VERSION
                for call in urlopen.call_args_list
            )
        )
        response.close()

    @patch("webapp.api_client.urlopen")
    def test_system_page_is_read_only_and_shows_server_status(self, urlopen):
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
        }
        urlopen.side_effect = lambda request, **_kwargs: UpstreamResponse(
            responses[urlsplit(request.full_url).path]
        )

        response = self.client.get("/system")
        self.assertEqual(response.status_code, 200)
        for expected in (
            b"System management",
            b"gateway-01",
            b"1d 1h 1m",
            b"1h 1m",
            b"commit-42",
            b"Restart Archangel",
            b"disabled",
            b"Restart controls are unavailable",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, response.data)
        response.close()

    @patch("webapp.api_client.urlopen")
    def test_system_logs_page_renders_sources_and_escapes_entries(self, urlopen):
        urlopen.return_value = UpstreamResponse(
            {
                "sources": [
                    {
                        "id": "archangel",
                        "label": "Archangel application",
                        "available": True,
                        "detail": "Showing recent application events.",
                        "entries": [
                            "[INFO:API] request_completed path=/status/info",
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
        )

        response = self.client.get("/system/logs")
        self.assertEqual(response.status_code, 200)
        for expected in (
            b"Application logs",
            b"Archangel application",
            b"nftables packet logs",
            b"No nftables log statements are configured.",
            b"&lt;script&gt;",
            b'href="/system"',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, response.data)
        self.assertNotIn(b"<script>", response.data)
        urlopen.assert_called_once()
        self.assertEqual(
            urlopen.call_args.args[0].full_url,
            "http://127.0.0.1:8080/api/v1/logs",
        )
        response.close()

    def test_static_assets_are_served(self):
        response = self.client.get("/static/styles.css")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"--paper", response.data)
        response.close()

    @patch("webapp.api_client.urlopen")
    def test_dashboard_displays_backend_failure(self, urlopen):
        urlopen.side_effect = OSError("connection refused")

        response = self.client.get("/rules")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"The C++ API is unavailable", response.data)
        self.assertIn(b"API UNAVAILABLE", response.data)
        response.close()

    @patch("webapp.api_client.urlopen")
    def test_overview_stops_requesting_after_backend_is_unreachable(self, urlopen):
        urlopen.side_effect = OSError("connection refused")

        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"API UNAVAILABLE", response.data)
        self.assertEqual(urlopen.call_count, 1)
        response.close()

    @patch("webapp.api_client.urlopen")
    def test_rejected_backend_session_redirects_to_login(self, urlopen):
        urlopen.return_value = UpstreamResponse(
            {"error": "A valid Bearer session is required", "code": "invalid_session"},
            status=401,
        )

        response = self.client.get("/system?view=full")

        self.assertEqual(response.status_code, 302)
        location = response.headers["Location"]
        self.assertIn("/login", location)
        self.assertIn("expired=1", location)
        self.assertIn("next=/system?view%3Dfull", location)
        response.close()
        with self.client.session_transaction() as browser_session:
            self.assertNotIn("access_token", browser_session)

    def test_health_endpoint_needs_no_login_or_session(self):
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 204)
        self.assertIsNone(response.headers.get("Set-Cookie"))
        response.close()
