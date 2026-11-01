import io
import json
from unittest.mock import patch

from webapp.api_client import API_SCHEMA_VERSION_HEADER
from webapp.views import _firewall_status

from .helpers import DashboardTestCase, UpstreamResponse


class RulePageTests(DashboardTestCase):
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
    def test_rules_page_renders_backend_rules(self, urlopen):
        urlopen.return_value = UpstreamResponse(
            {
                "nftables": [
                    {
                        "rule": {
                            "family": "inet",
                            "table": "filter",
                            "chain": "input",
                            "handle": 7,
                            "expr": [{"accept": None}],
                        }
                    }
                ]
            }
        )

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
        urlopen.return_value = UpstreamResponse(
            {
                "nftables": [
                    {"rule": {"family": "ip", "table": "filter", "chain": "input", "handle": 9, "expr": [{"drop": None}]}},
                    {"rule": {"family": "inet", "table": "filter", "chain": "forward", "handle": 10, "expr": [{"accept": None}]}},
                ]
            }
        )

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
    def test_rules_page_reports_invalid_ruleset_instead_of_empty_rules(self, urlopen):
        urlopen.return_value = UpstreamResponse(b"{}")

        response = self.client.get("/rules")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"invalid firewall ruleset response", response.data)
        self.assertNotIn(b"The backend returned no rules", response.data)
        response.close()

    @patch("webapp.api_client.urlopen")
    def test_rules_export_includes_supported_rules_and_omission_count(self, urlopen):
        urlopen.return_value = UpstreamResponse(
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
        )

        response = self.client.get("/rules/export")
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            'attachment; filename="archangel-firewall-rules.json"',
            response.headers["Content-Disposition"],
        )
        self.assertEqual(response.headers["X-Archangel-Skipped-Rules"], "1")
        bundle = json.loads(response.data)
        self.assertEqual(bundle["format"], "archangel-firewall-rules")
        self.assertEqual(bundle["version"], 1)
        self.assertEqual(bundle["omitted_unsupported_rules"], 1)
        self.assertEqual(
            bundle["rules"],
            [
                {
                    "family": "inet",
                    "table": "filter",
                    "chain": "input",
                    "protocol": "tcp",
                    "action": "accept",
                    "destination_port": 443,
                }
            ],
        )
        response.close()

    @patch("webapp.api_client.urlopen")
    def test_rule_import_previews_then_applies_after_confirmation(self, urlopen):
        urlopen.return_value = UpstreamResponse(
            {"status": "created"},
            status=201,
        )
        bundle = {
            "format": "archangel-firewall-rules",
            "version": 1,
            "rules": [
                {
                    "family": "inet",
                    "table": "filter",
                    "chain": "input",
                    "protocol": "tcp",
                    "destination_port": 443,
                    "action": "accept",
                }
            ],
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
        headers = {name.lower(): value for name, value in api_request.headers.items()}
        self.assertEqual(headers[API_SCHEMA_VERSION_HEADER.lower()], "1")
        imported.close()

    def test_rule_import_requires_valid_confirmation_token(self):
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
