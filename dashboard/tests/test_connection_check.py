import unittest

from webapp.connection_check import (
    COULD_BLOCK,
    NO_CHANGE,
    UNKNOWN_CONNECTION,
    WILL_BLOCK,
    Connection,
    browser_crosses_firewall,
    check_connection,
    connection_from_status,
)


REMOTE = Connection("192.0.2.20", 8080)
LOOPBACK = Connection("127.0.0.1", 8080)
EMPTY = {"nftables": []}


def match(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


def dport(right, op="=="):
    return match({"payload": {"protocol": "tcp", "field": "dport"}}, right, op)


def saddr(right, op="=="):
    return match({"payload": {"protocol": "ip", "field": "saddr"}}, right, op)


def ruleset(*rules, policy="accept", hook="input", family="inet", kind="filter", flags=None):
    table = {"family": family, "name": "t"}
    if flags:
        table["flags"] = flags
    entries = [
        {"table": table},
        {"chain": {"family": family, "table": "t", "name": "c", "type": kind, "hook": hook, "prio": 0, "policy": policy}},
        {"chain": {"family": family, "table": "t", "name": "sub"}},
    ]
    for handle, rule in enumerate(rules, start=1):
        chain, expression = rule if isinstance(rule, tuple) else ("c", rule)
        entries.append({"rule": {"family": family, "table": "t", "chain": chain, "handle": handle, "expr": expression}})
    return {"nftables": entries}


class CheckConnectionTests(unittest.TestCase):
    def status(self, *rules, connection=REMOTE, **chain):
        return check_connection(EMPTY, ruleset(*rules, **chain), connection).status

    def test_definite_blocks_name_their_cause(self):
        check = check_connection(EMPTY, ruleset([dport(8080), {"drop": None}]), REMOTE)
        self.assertEqual(check.status, WILL_BLOCK)
        self.assertEqual(check.causes, ("rule 1 in inet t c",))

        check = check_connection(EMPTY, ruleset(policy="drop"), REMOTE)
        self.assertEqual(check.status, WILL_BLOCK)
        self.assertEqual(check.causes, ("the drop policy of inet t c",))

    def test_rules_for_other_traffic_change_nothing(self):
        self.assertEqual(self.status([dport(9000), {"drop": None}]), NO_CHANGE)
        self.assertEqual(self.status([saddr("198.51.100.1"), {"drop": None}]), NO_CHANGE)
        self.assertEqual(self.status([saddr({"prefix": {"addr": "198.51.100.0", "len": 24}}), {"drop": None}]), NO_CHANGE)
        self.assertEqual(self.status([dport({"range": [1, 100]}), {"drop": None}]), NO_CHANGE)

    def test_order_decides_the_result(self):
        accept, drop = [dport(8080), {"accept": None}], [dport(8080), {"drop": None}]
        self.assertEqual(self.status(accept, drop), NO_CHANGE)
        self.assertEqual(self.status(drop, accept), WILL_BLOCK)

    def test_negated_address_set_and_range_matches(self):
        self.assertEqual(self.status([saddr("192.0.2.20", "!="), {"drop": None}]), NO_CHANGE)
        self.assertEqual(self.status([saddr("198.51.100.1", "!="), {"drop": None}]), WILL_BLOCK)
        self.assertEqual(self.status([dport({"set": [80, 8080]}), {"drop": None}]), WILL_BLOCK)
        self.assertEqual(self.status([dport({"range": [8000, 8100]}), {"drop": None}]), WILL_BLOCK)

    def test_what_cannot_be_evaluated_counts_as_could_block(self):
        unknowable = {
            "named set": [dport("@ports"), {"drop": None}],
            "limit": [dport(8080), {"limit": {"rate": 5, "per": "minute"}}, {"drop": None}],
            "server address": [match({"payload": {"protocol": "ip", "field": "daddr"}}, "192.0.2.1"), {"drop": None}],
            "interface": [match({"meta": {"key": "iifname"}}, "eth0"), {"drop": None}],
            "other meta": [match({"meta": {"key": "mark"}}, 1), {"drop": None}],
            "unknown statement": [dport(8080), {"queue": {"num": 1}}],
            "vmap": [{"vmap": {"key": 1, "data": []}}],
        }
        for name, rule in unknowable.items():
            self.assertEqual(self.status(rule), COULD_BLOCK, name)

    def test_jump_returns_but_goto_does_not(self):
        accept = [dport(8080), {"accept": None}]
        inner = ("sub", [dport(1), {"drop": None}])
        self.assertEqual(self.status([{"jump": {"target": "sub"}}], accept, inner, policy="drop"), NO_CHANGE)
        self.assertEqual(self.status([{"goto": {"target": "sub"}}], accept, inner, policy="drop"), WILL_BLOCK)
        self.assertEqual(self.status([{"jump": {"target": "sub"}}], ("sub", [dport(8080), {"drop": None}])), WILL_BLOCK)

    def test_explicit_return_continues_in_the_calling_chain(self):
        jump = [{"jump": {"target": "sub"}}]
        drop = [dport(8080), {"drop": None}]
        self.assertEqual(self.status(jump, drop, ("sub", [{"return": None}])), WILL_BLOCK)
        self.assertEqual(
            self.status(jump, ("sub", [{"return": None}]), ("sub", drop)),
            NO_CHANGE,
        )

    def test_jump_problems_count_as_could_block(self):
        self.assertEqual(self.status([{"jump": {"target": "missing"}}]), COULD_BLOCK)
        self.assertEqual(self.status([{"jump": {"target": "sub"}}], ("sub", [{"jump": {"target": "sub"}}])), COULD_BLOCK)

    def test_tables_and_hooks_that_do_not_see_the_connection(self):
        self.assertEqual(self.status(policy="drop", family="ip6"), NO_CHANGE)
        self.assertEqual(self.status(policy="drop", hook="forward"), NO_CHANGE)
        self.assertEqual(self.status(policy="drop", flags=["dormant"]), NO_CHANGE)
        self.assertEqual(self.status(policy="drop", flags="dormant"), NO_CHANGE)
        self.assertEqual(self.status(policy="drop", family="ip"), WILL_BLOCK)

    def test_all_base_chains_must_let_the_connection_through(self):
        ruleset_with_two = ruleset([{"accept": None}], policy="accept")
        ruleset_with_two["nftables"].append(
            {"chain": {"family": "inet", "table": "t", "name": "later", "type": "filter", "hook": "input", "prio": 10, "policy": "drop"}}
        )
        check = check_connection(EMPTY, ruleset_with_two, REMOTE)
        self.assertEqual(check.status, WILL_BLOCK)
        self.assertEqual(check.causes, ("the drop policy of inet t later",))

    def test_replies_must_get_out_on_the_output_hook(self):
        reply = match({"payload": {"protocol": "tcp", "field": "sport"}}, 8080)
        self.assertEqual(self.status([reply, {"drop": None}], hook="output"), WILL_BLOCK)
        self.assertEqual(self.status(policy="drop", hook="output"), WILL_BLOCK)

    def test_new_connections_must_be_allowed_not_only_established_ones(self):
        established = [match({"ct": {"key": "state"}}, ["established", "related"], "in"), {"accept": None}]
        self.assertEqual(self.status(established, policy="drop"), WILL_BLOCK)
        self.assertEqual(self.status(established, [dport(8080), {"accept": None}], policy="drop"), NO_CHANGE)
        new_only = [match({"ct": {"key": "state"}}, "new", "in"), {"drop": None}]
        self.assertEqual(self.status(new_only), WILL_BLOCK)

    def test_loopback_replies_pass_the_input_hook_on_a_temporary_port(self):
        allow_api = [dport(8080), {"accept": None}]
        self.assertEqual(self.status(allow_api, policy="drop", connection=REMOTE), NO_CHANGE)
        self.assertEqual(self.status(allow_api, policy="drop", connection=LOOPBACK), WILL_BLOCK)

    def test_a_temporary_port_is_only_uncertain_for_high_ports(self):
        self.assertEqual(self.status([dport(40000), {"drop": None}], connection=LOOPBACK), COULD_BLOCK)
        self.assertEqual(self.status([dport(9000), {"drop": None}], connection=LOOPBACK), NO_CHANGE)

    def test_interfaces_are_known_only_for_loopback(self):
        lo = match({"meta": {"key": "iifname"}}, "lo")
        self.assertEqual(self.status([lo, {"drop": None}], connection=REMOTE), NO_CHANGE)
        self.assertEqual(self.status([lo, {"drop": None}], connection=LOOPBACK), WILL_BLOCK)
        other = match({"meta": {"key": "iifname"}}, "eth0")
        self.assertEqual(self.status([other, {"drop": None}], connection=LOOPBACK), NO_CHANGE)
        output = match({"meta": {"key": "oifname"}}, "lo")
        self.assertEqual(self.status([output, {"drop": None}], connection=LOOPBACK), NO_CHANGE)

    def test_redirecting_the_connection_counts_as_blocking_it(self):
        redirect = [dport(8080), {"redirect": {"port": 9000}}]
        self.assertEqual(self.status(redirect, hook="prerouting", kind="nat"), WILL_BLOCK)
        self.assertEqual(self.status(redirect, hook="prerouting", kind="nat", connection=LOOPBACK), NO_CHANGE)
        self.assertEqual(self.status(redirect, hook="output", kind="nat", connection=LOOPBACK), WILL_BLOCK)

    def test_source_nat_does_not_block(self):
        self.assertEqual(self.status([{"masquerade": None}], hook="postrouting", kind="nat"), NO_CHANGE)

    def test_counters_and_logs_do_not_stop_a_rule(self):
        rule = [dport(8080), {"counter": None}, {"log": {"prefix": "x"}}, {"drop": None}]
        self.assertEqual(self.status(rule), WILL_BLOCK)

    def test_chains_it_cannot_model_count_as_could_block(self):
        rules = ruleset()
        rules["nftables"].append({"chain": {"family": "netdev", "table": "n", "name": "i", "hook": "ingress", "prio": 0}})
        self.assertEqual(check_connection(EMPTY, rules, REMOTE).status, COULD_BLOCK)

    def test_an_unreadable_ruleset_counts_as_could_block(self):
        for rules in (None, {}, {"nftables": "x"}):
            self.assertEqual(check_connection(EMPTY, rules, REMOTE).status, COULD_BLOCK)
        rule = {"nftables": ruleset()["nftables"] + [{"rule": {"family": "inet", "table": "t", "chain": "c", "handle": 1}}]}
        self.assertEqual(check_connection(EMPTY, rule, REMOTE).status, COULD_BLOCK)

    def test_compares_with_the_current_ruleset(self):
        blocked = ruleset(policy="drop")
        uncertain = ruleset([dport("@ports"), {"drop": None}])
        self.assertEqual(check_connection(blocked, blocked, REMOTE).status, NO_CHANGE)
        self.assertEqual(check_connection(uncertain, uncertain, REMOTE).status, NO_CHANGE)
        self.assertEqual(check_connection(uncertain, blocked, REMOTE).status, WILL_BLOCK)
        self.assertEqual(check_connection(blocked, EMPTY, REMOTE).status, NO_CHANGE)

    def test_unknown_connection_details(self):
        self.assertEqual(check_connection(EMPTY, EMPTY, None).status, UNKNOWN_CONNECTION)
        self.assertEqual(check_connection(EMPTY, EMPTY, Connection("nonsense", 8080)).status, UNKNOWN_CONNECTION)

    def test_ipv6_connections(self):
        connection = Connection("2001:db8::20", 8080)
        ipv6 = match({"payload": {"protocol": "ip6", "field": "saddr"}}, {"prefix": {"addr": "2001:db8::", "len": 32}})
        self.assertEqual(self.status([ipv6, {"drop": None}], connection=connection), WILL_BLOCK)
        self.assertEqual(self.status([saddr("192.0.2.20"), {"drop": None}], connection=connection), NO_CHANGE)
        self.assertEqual(self.status(policy="drop", family="ip", connection=connection), NO_CHANGE)


class ConnectionDetailsTests(unittest.TestCase):
    def test_reads_details_from_status(self):
        self.assertEqual(connection_from_status({"client_address": "192.0.2.20", "api_port": 8080}), REMOTE)

    def test_unwraps_ipv4_reported_in_ipv6_form(self):
        self.assertEqual(connection_from_status({"client_address": "::ffff:192.0.2.20", "api_port": 8080}), REMOTE)

    def test_rejects_missing_or_invalid_details(self):
        for status in (
            None,
            {},
            {"client_address": "192.0.2.20"},
            {"api_port": 8080},
            {"client_address": "nonsense", "api_port": 8080},
            {"client_address": "192.0.2.20", "api_port": 0},
            {"client_address": "192.0.2.20", "api_port": 70000},
            {"client_address": "192.0.2.20", "api_port": True},
            {"client_address": 7, "api_port": 8080},
        ):
            self.assertIsNone(connection_from_status(status), status)


class BrowserCrossesFirewallTests(unittest.TestCase):
    def test_only_a_remote_browser_with_a_loopback_api(self):
        self.assertTrue(browser_crosses_firewall(LOOPBACK, "192.0.2.50"))
        self.assertFalse(browser_crosses_firewall(LOOPBACK, "127.0.0.1"))
        self.assertFalse(browser_crosses_firewall(LOOPBACK, "::1"))
        self.assertFalse(browser_crosses_firewall(REMOTE, "192.0.2.50"))
        self.assertFalse(browser_crosses_firewall(None, "192.0.2.50"))
        self.assertFalse(browser_crosses_firewall(LOOPBACK, None))


if __name__ == "__main__":
    unittest.main()
