import json
import logging
import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import patch

from server import app
from webapp.api_client import ApiClient, UrllibTransport, create_ssl_context
from webapp.logging_config import JsonlFileHandler

from .helpers import DashboardTestCase, UpstreamResponse


def read_records(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


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
        upstream = UpstreamResponse({})
        upstream.headers["X-Request-ID"] = "backend-request-1"
        urlopen.return_value = upstream
        client = ApiClient("http://127.0.0.1:8080", UrllibTransport(create_ssl_context()))

        with self.assertLogs("webapp.api_client", level="INFO") as captured:
            response = client.request("/api/v1/rules?token=do-not-log")

        self.assertEqual(response.status, 200)
        messages = "\n".join(captured.output)
        self.assertIn(
            "backend_request_completed method=GET path=/api/v1/rules status=200",
            messages,
        )
        self.assertIn("backend_request_id=backend-request-1", messages)
        self.assertNotIn("do-not-log", messages)

    def test_requests_are_recorded_as_owner_only_jsonl(self):
        log_path = Path(os.environ["ARCHANGEL_WEB_LOG_PATH"])
        response = self.client.get("/config?token=do-not-log")
        response.close()

        records = read_records(log_path)
        completed = [r for r in records if r["event"] == "request_completed"][-1]
        self.assertEqual(completed["service"], "dashboard")
        self.assertEqual(completed["path"], "/config")
        self.assertEqual(completed["status"], "200")
        self.assertEqual(len(completed["request_id"]), 32)
        self.assertIn("source_ip", completed)
        self.assertNotIn("do-not-log", log_path.read_text())
        self.assertEqual(stat.S_IMODE(log_path.stat().st_mode), 0o600)

    def test_state_changes_fail_closed_when_audit_log_is_unavailable(self):
        handler = app.extensions["archangel_audit_log"]
        with patch.object(handler, "write_audit", return_value=False):
            response = self.client.post("/logout", data={"csrf_token": self.csrf_token()})
        self.assertEqual(response.status_code, 503)
        response.close()

    def test_state_changes_are_audited_before_running(self):
        log_path = Path(os.environ["ARCHANGEL_WEB_LOG_PATH"])
        with patch("webapp.api_client.urlopen", return_value=UpstreamResponse(b"", status=204)):
            response = self.client.post("/logout", data={"csrf_token": self.csrf_token()})
        response.close()
        events = [r["event"] for r in read_records(log_path)]
        self.assertIn("dashboard_request_authorized", events)


class JsonlFileHandlerTests(DashboardTestCase):
    def setUp(self):
        super().setUp()
        self.directory = Path(tempfile.mkdtemp())

    def record(self, message):
        return logging.LogRecord("webapp", logging.INFO, __file__, 0, message, (), None)

    def test_reopens_after_rotation(self):
        path = self.directory / "web.jsonl"
        handler = JsonlFileHandler(path)
        handler.emit(self.record("before_rotation"))
        path.rename(self.directory / "web.jsonl.1")
        handler.emit(self.record("after_rotation"))
        handler.close()
        self.assertEqual(read_records(self.directory / "web.jsonl.1")[0]["event"], "before_rotation")
        self.assertEqual(read_records(path)[0]["event"], "after_rotation")

    def test_rejects_files_readable_by_others(self):
        path = self.directory / "shared.jsonl"
        path.write_text("")
        path.chmod(0o644)
        with self.assertRaises(RuntimeError):
            JsonlFileHandler(path)

    def test_non_event_messages_keep_their_text(self):
        path = self.directory / "web.jsonl"
        handler = JsonlFileHandler(path)
        self.assertTrue(handler.write_audit(self.record("Plain message with spaces")))
        handler.close()
        record = read_records(path)[0]
        self.assertEqual(record["event"], "message")
        self.assertEqual(record["message"], "Plain message with spaces")
