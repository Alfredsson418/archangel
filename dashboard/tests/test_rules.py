import io
import json
from unittest.mock import patch

from webapp.firewall_rules import firewall_status

from .helpers import DashboardTestCase, UpstreamResponse


class RulePageTests(DashboardTestCase):
    def test_firewall_status_requires_a_base_chain_hook(self):
        self.assertEqual(
            firewall_status(
                {
                    "nftables": [
                        {"chain": {"name": "input"}},
                        {"chain": {"name": "forward", "hook": "forward"}},
                    ]
                }
            ),
            ("Active", 1),
        )
        self.assertEqual(firewall_status({"nftables": []}), ("No active base chains", 0))
        self.assertEqual(firewall_status(None), ("Unavailable", None))

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
    def test_rules_page_groups_rules_and_filters_them(self, urlopen):
        urlopen.return_value = UpstreamResponse(
            {
                "nftables": [
                    {"rule": {"family": "ip", "table": "filter", "chain": "input", "handle": 9, "expr": [{"drop": None}]}},
                    {"rule": {"family": "inet", "table": "filter", "chain": "forward", "handle": 10, "expr": [{"accept": None}]}},
                ]
            }
        )

        response = self.client.get("/rules")
        self.assertEqual(response.status_code, 200)
        # inet comes before ip, whatever order nftables lists them in.
        self.assertLess(response.data.index(b'data-nav="family:inet"'), response.data.index(b'data-nav="family:ip"'))
        self.assertIn(b"Edit", response.data)
        self.assertIn(b"disabled", response.data)
        self.assertIn(b"Search family, table, chain", response.data)
        self.assertIn(b"2 matching / 2 total", response.data)
        response.close()

        response = self.client.get("/rules?q=forward")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'data-chain="inet filter forward"', response.data)
        self.assertNotIn(b'data-nav="family:ip"', response.data)
        self.assertIn(b"1 matching / 2 total", response.data)
        response.close()

        response = self.client.get("/rules?q=nothing-matches")
        self.assertIn(b"No rules match this filter", response.data)
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
        self.assertEqual(bundle["version"], 2)
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
    def test_rules_export_accepts_kernel_listing_shapes(self, urlopen):
        # nftables drops the l4proto match when a port implies it and lists the
        # protocol by number otherwise.
        address_match = {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "192.0.2.1"}}
        urlopen.return_value = UpstreamResponse(
            {
                "nftables": [
                    {
                        "rule": {
                            "family": "inet",
                            "table": "filter",
                            "chain": "input",
                            "handle": 3,
                            "expr": [
                                address_match,
                                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
                                {"accept": None},
                            ],
                        }
                    },
                    {
                        "rule": {
                            "family": "inet",
                            "table": "filter",
                            "chain": "input",
                            "handle": 4,
                            "expr": [
                                address_match,
                                {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": 17}},
                                {"drop": None},
                            ],
                        }
                    },
                ]
            }
        )

        response = self.client.get("/rules/export")

        self.assertEqual(response.status_code, 200)
        bundle = json.loads(response.data)
        self.assertEqual(bundle["omitted_unsupported_rules"], 0)
        self.assertEqual(
            bundle["rules"],
            [
                {"family": "inet", "table": "filter", "chain": "input", "protocol": "tcp", "action": "accept", "source_address": "192.0.2.1", "destination_port": 22},
                {"family": "inet", "table": "filter", "chain": "input", "protocol": "udp", "action": "drop", "source_address": "192.0.2.1"},
            ],
        )
        response.close()

    def test_rule_import_page_states_the_enforced_limits(self):
        response = self.client.get("/rules/import")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"maximum 512 KiB and 1000 rules", response.data)
        response.close()

    def test_rule_import_requires_valid_confirmation_token(self):
        response = self.client.post(
            "/rules/import",
            data={
                "action": "add",
                "csrf_token": "invalid",
                "bundle": "{}",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"request security token is missing or invalid", response.data)
        response.close()
