from server import app
from webapp.settings import valid_api_url

from .helpers import DashboardTestCase


class SettingsPageTests(DashboardTestCase):
    def test_configuration_page_is_rendered(self):
        response = self.client.get("/config")
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

    def test_browser_cannot_change_backend_destination(self):
        response = self.client.post(
            "/config",
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
