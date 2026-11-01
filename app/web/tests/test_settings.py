from pathlib import Path

from server import app
from webapp.settings import load_api_url

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

    def test_invalid_saved_api_configuration_is_logged_and_ignored(self):
        config_path = Path(self.temp_dir.name) / "invalid.json"
        config_path.write_text("{invalid")

        with self.assertLogs("webapp.settings", level="WARNING") as captured:
            api_url = load_api_url(config_path, "http://127.0.0.1:8081")

        self.assertEqual(api_url, "http://127.0.0.1:8081")
        self.assertIn("connection_setting_load_failed", "\n".join(captured.output))

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
