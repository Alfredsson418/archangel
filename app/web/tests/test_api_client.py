import unittest
from unittest.mock import patch

from webapp.api_client import (
    API_SCHEMA_VERSION,
    API_SCHEMA_VERSION_HEADER,
    ApiConnectionError,
    ApiResponseError,
    fetch_json,
    request_backend,
)

from .helpers import UpstreamResponse


class ApiClientTests(unittest.TestCase):
    @patch("webapp.api_client.urlopen")
    def test_json_request_rejects_mismatched_schema_version(self, urlopen):
        urlopen.return_value = UpstreamResponse({"value": True}, schema_version="2")

        with self.assertRaisesRegex(ApiResponseError, "unsupported schema version"):
            fetch_json("http://127.0.0.1:8080", "/api/v1/test")

    @patch("webapp.api_client.urlopen")
    def test_json_request_reports_non_success_status(self, urlopen):
        urlopen.return_value = UpstreamResponse(
            {"error": "Rule rejected", "code": "invalid_request"},
            status=400,
        )

        with self.assertRaisesRegex(ApiResponseError, "Rule rejected"):
            fetch_json("http://127.0.0.1:8080", "/api/v1/rules")

    @patch("webapp.api_client.urlopen", side_effect=OSError("connection refused"))
    def test_request_reports_unavailable_backend(self, _urlopen):
        with self.assertRaisesRegex(ApiConnectionError, "API is unavailable"):
            request_backend("http://127.0.0.1:8080", "/api/v1/rules")

    @patch("webapp.api_client.urlopen")
    def test_request_sets_schema_header_for_versioned_calls(self, urlopen):
        urlopen.return_value = UpstreamResponse({})

        fetch_json("http://127.0.0.1:8080", "/api/v1/test")

        request = urlopen.call_args.args[0]
        headers = {name.lower(): value for name, value in request.headers.items()}
        self.assertEqual(
            headers[API_SCHEMA_VERSION_HEADER.lower()],
            API_SCHEMA_VERSION,
        )
