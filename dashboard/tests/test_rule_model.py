import unittest

from webapp.firewall_rules import (
    describe_rule,
    portable_bundle,
    portable_rule,
    validate_rule,
    validate_rule_bundle,
)


def match(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


def payload(protocol, field):
    return {"payload": {"protocol": protocol, "field": field}}


def meta(key):
    return {"meta": {"key": key}}


CT_STATE = {"ct": {"key": "state"}}
BASE = {"family": "inet", "table": "filter", "chain": "input"}


def listed(*statements, **fields):
    return {**BASE, "handle": 7, "expr": list(statements), **fields}


class PortableRuleTests(unittest.TestCase):
    """Shapes below were taken from real nftables 1.1.6 JSON listings."""

    def test_reads_each_default_reject_as_a_plain_reject(self):
        # nftables reports a plain reject with its family's default options.
        for family, reject_type in (("inet", "icmpx"), ("ip", "icmp"), ("ip6", "icmpv6")):
            rule = listed(
                match(payload("tcp", "dport"), 22),
                {"reject": {"type": reject_type, "expr": "port-unreachable"}},
                family=family,
            )
            self.assertEqual(portable_rule(rule)["action"], "reject", family)

    def test_an_address_match_narrows_the_default_reject_in_inet_tables(self):
        for address, length, field, reject_type in (
            ("10.0.0.0", 8, "ip", "icmp"),
            ("2001:db8::", 32, "ip6", "icmpv6"),
        ):
            rule = listed(
                match(payload(field, "saddr"), {"prefix": {"addr": address, "len": length}}),
                match(payload("udp", "dport"), 53),
                {"reject": {"type": reject_type, "expr": "port-unreachable"}},
            )
            self.assertEqual(portable_rule(rule)["action"], "reject", field)
        wrong = listed(
            match(payload("ip", "saddr"), "10.0.0.1"),
            {"reject": {"type": "icmpx", "expr": "port-unreachable"}},
        )
        self.assertIsNone(portable_rule(wrong))

    def test_does_not_read_other_reject_options_as_a_plain_reject(self):
        for options in (
            {"type": "tcp reset"},
            {"type": "icmpx", "expr": "admin-prohibited"},
            {"type": "icmp", "expr": "port-unreachable"},
        ):
            rule = listed(match(payload("tcp", "dport"), 22), {"reject": options})
            self.assertIsNone(portable_rule(rule), options)

    def test_reads_subnets_ranges_states_and_interfaces(self):
        rule = listed(
            match(meta("iifname"), "eth0"),
            match(meta("oifname"), "wg0"),
            match(CT_STATE, ["established", "new"], "in"),
            match(payload("ip", "saddr"), {"prefix": {"addr": "192.168.1.0", "len": 24}}),
            match(payload("ip", "daddr"), "192.0.2.1"),
            match(payload("tcp", "dport"), {"range": [8000, 8100]}),
            {"drop": None},
        )
        self.assertEqual(
            portable_rule(rule),
            {
                **BASE,
                "protocol": "tcp",
                "action": "drop",
                "input_interface": "eth0",
                "output_interface": "wg0",
                "connection_states": ["new", "established"],
                "source_address": "192.168.1.0/24",
                "destination_address": "192.0.2.1",
                "destination_port": 8000,
                "destination_port_end": 8100,
            },
        )

    def test_reads_one_connection_state_listed_as_a_string(self):
        rule = listed(match(CT_STATE, "invalid", "in"), {"drop": None})
        self.assertEqual(portable_rule(rule)["connection_states"], ["invalid"])

    def test_reads_rules_without_a_protocol_and_icmp(self):
        self.assertNotIn(
            "protocol",
            portable_rule(listed(match(payload("ip", "saddr"), "192.0.2.1"), {"accept": None})),
        )
        for right, protocol in (("icmp", "icmp"), ("ipv6-icmp", "icmpv6"), (1, "icmp"), (58, "icmpv6")):
            rule = listed(match(meta("l4proto"), right), {"accept": None})
            self.assertEqual(portable_rule(rule)["protocol"], protocol)

    def test_rejects_everything_the_form_cannot_represent(self):
        tcp_22 = match(payload("tcp", "dport"), 22)
        unsupported = {
            "negated": listed(match(payload("tcp", "dport"), 22, "!="), {"drop": None}),
            "port set": listed(match(payload("tcp", "dport"), {"set": [80, 443]}), {"accept": None}),
            "named set": listed(match(payload("tcp", "dport"), "@ports"), {"accept": None}),
            "source port": listed(match(payload("tcp", "sport"), 22), {"accept": None}),
            "counter": listed(tcp_22, {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}),
            "log": listed(tcp_22, {"log": {"prefix": "x"}}, {"accept": None}),
            "limit": listed(tcp_22, {"limit": {"rate": 5, "per": "minute"}}, {"accept": None}),
            "jump": listed(tcp_22, {"jump": {"target": "next"}}),
            "iif": listed(match(meta("iif"), "lo"), {"accept": None}),
            "ip protocol": listed(match(payload("ip", "protocol"), "icmp"), {"accept": None}),
            "no match": listed({"accept": None}),
            "no verdict": listed(tcp_22),
            "statement after verdict": listed({"accept": None}, tcp_22),
            "two verdicts": listed(tcp_22, {"accept": None}, {"drop": None}),
            "other family": listed(tcp_22, {"accept": None}, family="bridge"),
            "name the API refuses": listed(tcp_22, {"accept": None}, chain="bad name"),
            "reversed range": listed(match(payload("tcp", "dport"), {"range": [9, 1]}), {"accept": None}),
            "protocol mismatch": listed(match(meta("l4proto"), "udp"), tcp_22, {"accept": None}),
            "mixed addresses": listed(
                match(payload("ip", "saddr"), "192.0.2.1"),
                match(payload("ip6", "daddr"), "2001:db8::1"),
                {"accept": None},
            ),
        }
        for name, rule in unsupported.items():
            self.assertIsNone(portable_rule(rule), name)

    def test_export_counts_only_what_it_omits(self):
        bundle, skipped = portable_bundle(
            {
                "nftables": [
                    {"rule": listed(match(payload("tcp", "dport"), 22), {"reject": {"type": "icmpx", "expr": "port-unreachable"}})},
                    {"rule": listed(match(meta("iif"), "lo"), {"accept": None})},
                ]
            }
        )
        self.assertEqual(skipped, 1)
        self.assertEqual(bundle["rules"][0]["action"], "reject")

    def test_exported_rules_validate_when_imported(self):
        rule = portable_rule(
            listed(
                match(CT_STATE, ["established", "related"], "in"),
                match(payload("ip", "saddr"), {"prefix": {"addr": "10.0.0.0", "len": 8}}),
                {"accept": None},
            )
        )
        bundle = {"format": "archangel-firewall-rules", "version": 2, "rules": [rule]}
        self.assertEqual(validate_rule_bundle(bundle), [rule])


class ValidationTests(unittest.TestCase):
    def rule(self, **fields):
        return {**BASE, "action": "accept", "protocol": "tcp", **fields}

    def test_accepts_and_normalizes_valid_values(self):
        normalized = validate_rule(
            self.rule(
                source_address="192.0.2.1/32",
                destination_port=80,
                destination_port_end=80,
                connection_states=["related", "new"],
            ),
            "Rule",
        )
        self.assertEqual(normalized["source_address"], "192.0.2.1")
        self.assertNotIn("destination_port_end", normalized)
        self.assertEqual(normalized["connection_states"], ["new", "related"])

    def test_rejects_invalid_values(self):
        invalid = {
            "host bits": {"source_address": "192.168.1.5/24"},
            "bad prefix": {"source_address": "192.168.1.0/33"},
            "mixed versions": {"source_address": "192.0.2.1", "destination_address": "2001:db8::1"},
            "family mismatch": {"family": "ip", "source_address": "2001:db8::1"},
            "icmp in ip6": {"family": "ip6", "protocol": "icmp"},
            "icmpv6 in ip": {"family": "ip", "protocol": "icmpv6"},
            "icmp with v6": {"protocol": "icmp", "source_address": "2001:db8::1"},
            "port with icmp": {"protocol": "icmp", "destination_port": 22},
            "port with no protocol": {"protocol": None, "destination_port": 22},
            "reversed range": {"destination_port": 9, "destination_port_end": 1},
            "end without start": {"destination_port_end": 1},
            "bad interface": {"input_interface": "has space"},
            "long interface": {"output_interface": "x" * 16},
            "bad state": {"connection_states": ["untracked"]},
            "state not list": {"connection_states": "new"},
            "unknown field": {"source_ports": [1]},
            "no match": {"protocol": None},
        }
        for name, fields in invalid.items():
            with self.assertRaises(ValueError, msg=name):
                validate_rule(self.rule(**fields), "Rule")

    def test_version_1_bundles_keep_their_original_rules(self):
        def bundle(**fields):
            return {
                "format": "archangel-firewall-rules",
                "version": 1,
                "rules": [self.rule(destination_port=443, **fields)],
            }

        self.assertEqual(validate_rule_bundle(bundle())[0]["destination_port"], 443)
        for fields in (
            {"input_interface": "lo"},
            {"connection_states": ["new"]},
            {"destination_port_end": 500},
            {"source_address": "192.0.2.0/24"},
            {"protocol": "icmp"},
        ):
            with self.assertRaises(ValueError, msg=fields):
                validate_rule_bundle(bundle(**fields))

    def test_rejects_unknown_bundle_versions(self):
        for version in (0, 3, True, "2", None):
            with self.assertRaises(ValueError, msg=version):
                validate_rule_bundle({"format": "archangel-firewall-rules", "version": version, "rules": []})


class DescriptionTests(unittest.TestCase):
    def test_describes_rules_in_plain_language(self):
        rule = {**BASE, "action": "accept", "protocol": "tcp", "destination_port": 443, "source_address": "192.0.2.10"}
        self.assertEqual(describe_rule(rule), "Accept TCP traffic to port 443 from 192.0.2.10")
        self.assertEqual(
            describe_rule({**BASE, "action": "accept", "connection_states": ["established", "related"]}),
            "Accept established/related all traffic",
        )
        self.assertEqual(
            describe_rule(
                {
                    **BASE,
                    "action": "drop",
                    "protocol": "udp",
                    "destination_port": 53,
                    "destination_port_end": 60,
                    "destination_address": "10.0.0.0/8",
                    "input_interface": "eth0",
                    "output_interface": "wg0",
                }
            ),
            "Drop UDP traffic to ports 53-60 going to 10.0.0.0/8 arriving on eth0 leaving on wg0",
        )


if __name__ == "__main__":
    unittest.main()
