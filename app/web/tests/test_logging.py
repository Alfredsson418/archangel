from unittest.mock import patch

from server import app
from webapp.api_client import request_backend

from .helpers import DashboardTestCase, UpstreamResponse


class LoggingTests(DashboardTestCase):
    def test_dashboard_request_logging_omits_query_values(self):
        with self.assertLogs(app.logger, level="INFO") as captured:
            response = self.client.get("/config?token=do-not-log")

        self.assertEqual(response.status_code, 200)
        messages = "\n".join(captured.output)
        self.assertIn("request_started method=GET path=/config", messages)
        self.assertIn("request_completed method=GET path=/config status=200", messages)
        self.assertNotIn("do-not-log", messages)
        response.close()

    @patch("webapp.api_client.urlopen")
    def test_backend_request_logs_outcome_without_query_values(self, urlopen):
        urlopen.return_value = UpstreamResponse({})

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
