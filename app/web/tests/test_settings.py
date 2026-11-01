from server import app
import tempfile
from pathlib import Path

from webapp.settings import load_api_settings, valid_api_url

from .helpers import DashboardTestCase


class SettingsPageTests(DashboardTestCase):
    def test_configuration_page_is_rendered(self):
        response = self.client.get("/api-connection")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"API base URL", response.data)
        self.assertIn(b"http://127.0.0.1:8080", response.data)
        self.assertIn(b"cannot change this address", response.data)
        self.assertNotIn(b"config.js", response.data)
        response.close()

    def test_api_url_validation_rejects_unsafe_destinations(self):
        self.assertEqual(valid_api_url(" http://10.0.0.5:8080/ "), "http://10.0.0.5:8080")
        for value in (
            "ftp://10.0.0.5",
            "http://user:secret@10.0.0.5",
            "http://10.0.0.5/?next=x",
            "http://10.0.0.5:notaport",
            None,
        ):
            with self.subTest(value=value):
                self.assertIsNone(valid_api_url(value))

    def test_api_settings_come_from_the_deployment_environment(self):
        settings = load_api_settings({})
        self.assertEqual(settings.base_url, "http://127.0.0.1:8080")
        self.assertFalse(settings.from_environment)
        self.assertIsNone(settings.ca_bundle)

        bundle = Path(tempfile.mkdtemp()) / "ca.pem"
        bundle.write_text("placeholder")
        settings = load_api_settings(
            {"ARCHANGEL_API_URL": "https://api.example:8443/", "ARCHANGEL_API_CA_BUNDLE": str(bundle)}
        )
        self.assertEqual(settings.base_url, "https://api.example:8443")
        self.assertTrue(settings.from_environment)
        self.assertEqual(settings.ca_bundle, bundle)

    def test_flags_plain_http_to_remote_hosts(self):
        for url, expected in (
            ("http://127.0.0.1:8080", False),
            ("http://localhost:8080", False),
            ("http://[::1]:8080", False),
            ("https://10.0.0.5:8443", False),
            ("http://10.0.0.5:8080", True),
            ("http://api.example:8080", True),
        ):
            with self.subTest(url=url):
                settings = load_api_settings({"ARCHANGEL_API_URL": url})
                self.assertEqual(settings.unencrypted_remote, expected)

    def test_api_settings_reject_invalid_values(self):
        with self.assertRaises(RuntimeError):
            load_api_settings({"ARCHANGEL_API_URL": "ftp://api.example"})
        with self.assertRaises(RuntimeError):
            load_api_settings({"ARCHANGEL_API_CA_BUNDLE": "/nonexistent/ca.pem"})

    def test_browser_cannot_change_backend_destination(self):
        response = self.client.post(
            "/api-connection",
            data={
                "api_url": "http://10.0.0.5:8081/",
                "action": "save",
                "csrf_token": self.csrf_token(),
            },
        )
        self.assertEqual(response.status_code, 405)
        self.assertEqual(app.config["API_URL"], "http://127.0.0.1:8080")
        response.close()

    def test_dashboard_does_not_expose_cpp_api_passthrough_routes(self):
        for path in (
            "/api/v1/rules",
            "/api/v1/stats",
            "/api/v1/system",
            "/api/v1/logs",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)
