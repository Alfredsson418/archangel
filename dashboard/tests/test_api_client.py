import ssl
import unittest
from unittest.mock import patch
from urllib.error import URLError

from webapp.api_client import (
    API_SCHEMA_VERSION,
    API_SCHEMA_VERSION_HEADER,
    ApiClient,
    ApiConnectionError,
    ApiResponse,
    ApiResponseError,
    UrllibTransport,
    create_ssl_context,
)

from .helpers import UpstreamResponse


class FakeTransport:
    """In-memory ApiTransport returning queued responses and recording calls."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def send(self, method, url, headers, body, timeout):
        self.calls.append((method, url, headers, body, timeout))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def json_response(body=b"{}", status=200, schema_version=API_SCHEMA_VERSION):
    return ApiResponse(status, body, "application/json", schema_version, "backend-id")


class ApiClientContractTests(unittest.TestCase):
    """ApiClient behavior, independent of any concrete transport."""

    def test_versioned_requests_send_schema_and_bearer_headers(self):
        transport = FakeTransport(json_response(b'{"value": true}'))
        client = ApiClient("https://api.example:8443", transport)

        self.assertEqual(client.fetch_json("/api/v1/test", bearer_token="token"), {"value": True})
        method, url, headers, body, _timeout = transport.calls[0]
        self.assertEqual((method, url, body), ("GET", "https://api.example:8443/api/v1/test", None))
        self.assertEqual(headers[API_SCHEMA_VERSION_HEADER], API_SCHEMA_VERSION)
        self.assertEqual(headers["Authorization"], "Bearer token")

    def test_rejects_mismatched_schema_version(self):
        client = ApiClient("http://127.0.0.1:8080", FakeTransport(json_response(schema_version="1")))
        with self.assertRaisesRegex(ApiResponseError, "unsupported schema version"):
            client.fetch_json("/api/v1/test")

    def test_reports_non_success_status_with_backend_detail(self):
        client = ApiClient(
            "http://127.0.0.1:8080",
            FakeTransport(json_response(b'{"error": "Rule rejected"}', status=400)),
        )
        with self.assertRaisesRegex(ApiResponseError, "Rule rejected") as raised:
            client.fetch_json("/api/v1/rules")
        self.assertEqual(raised.exception.status, 400)

    def test_rejects_invalid_json(self):
        client = ApiClient("http://127.0.0.1:8080", FakeTransport(json_response(b"not json")))
        with self.assertRaisesRegex(ApiResponseError, "invalid JSON"):
            client.fetch_json("/api/v1/test")

    def test_propagates_unreachable_backend(self):
        client = ApiClient(
            "http://127.0.0.1:8080",
            FakeTransport(ApiConnectionError("The C++ API is unavailable: refused")),
        )
        with self.assertRaisesRegex(ApiConnectionError, "unavailable"):
            client.request("/api/v1/rules")

    def test_unversioned_requests_omit_schema_header(self):
        transport = FakeTransport(json_response(b""))
        ApiClient("http://127.0.0.1:8080", transport).request("/status/health", schema_version=None)
        self.assertNotIn(API_SCHEMA_VERSION_HEADER, transport.calls[0][2])


class UrllibTransportTests(unittest.TestCase):
    @patch("webapp.api_client.urlopen")
    def test_passes_tls_context_and_returns_backend_request_id(self, urlopen):
        upstream = UpstreamResponse({})
        upstream.headers["X-Request-ID"] = "abc123"
        urlopen.return_value = upstream
        context = create_ssl_context()

        response = UrllibTransport(context).send("GET", "https://api.example/x", {}, None, 5)

        self.assertIs(urlopen.call_args.kwargs["context"], context)
        self.assertEqual(response.request_id, "abc123")

    @patch("webapp.api_client.urlopen", side_effect=URLError("certificate verify failed"))
    def test_maps_connection_and_certificate_failures(self, _urlopen):
        with self.assertRaisesRegex(ApiConnectionError, "certificate verify failed"):
            UrllibTransport(create_ssl_context()).send("GET", "https://api.example/x", {}, None, 5)

    def test_tls_context_verifies_and_requires_tls_1_2(self):
        context = create_ssl_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
