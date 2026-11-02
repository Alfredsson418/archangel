import io
import json
import logging
import time
from unittest.mock import patch
from urllib.error import URLError
from urllib.parse import urlsplit

from server import app
from webapp import pending_changes
from webapp.api_client import API_SCHEMA_VERSION_HEADER
from webapp.connection_check import Connection
from webapp.firewall_changes import (
    ADD_RULE,
    DELETE_RULE,
    apply_to_ruleset,
    change_warnings,
    management_risk,
    rule_statements,
    stale_changes,
    verify_applied,
)

from .helpers import TEST_ACTOR_ID, DashboardTestCase, UpstreamResponse


def input_chain(policy="accept", hook="input"):
    return {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter", "hook": hook, "prio": 0, "policy": policy}}


def listed_rule(handle, *statements, comment="archangel-managed"):
    rule = {"family": "inet", "table": "filter", "chain": "input", "handle": handle, "expr": list(statements)}
    if comment:
        rule["comment"] = comment
    return {"rule": rule}


def port_match(port):
    return {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": port}}


RULE = {"family": "inet", "table": "filter", "chain": "input", "protocol": "tcp", "destination_port": 443, "action": "accept"}
FORM = {"chain": "inet filter input", "protocol": "tcp", "destination_port": "443", "action": "accept"}


class FakeApi:
    """Answers API calls by path, and records every change list it receives."""

    def __init__(self, entries=None, *, applies=None):
        self.ruleset = {"nftables": entries if entries is not None else [input_chain(), listed_rule(7, port_match(22), {"accept": None})]}
        self.revision = "rev1"
        self.applied = []
        self.checked = []
        self.apply_response = applies
        self.check_response = None
        self.status_info = {"status": "ok", "client_address": "192.0.2.20", "api_port": 8080}
        self.interfaces = ["lo", "eth0"]

    def __call__(self, request, **_kwargs):
        path = urlsplit(request.full_url).path
        if path == "/api/v1/rules":
            return UpstreamResponse(self.ruleset)
        if path == "/status/info":
            return UpstreamResponse(self.status_info)
        if path == "/api/v1/system":
            return UpstreamResponse({"network_interfaces": self.interfaces})
        if path == "/api/v1/firewall/revisions":
            return UpstreamResponse({"chains": [{"family": "inet", "table": "filter", "chain": "input", "revision": self.revision}]})
        body = json.loads(request.data)
        if path == "/api/v1/firewall/changes/check":
            self.checked.append(body)
            return self.check_response or UpstreamResponse({"status": "valid", "changes": len(body["changes"])})
        if path == "/api/v1/firewall/changes":
            self.applied.append(body)
            if isinstance(self.apply_response, Exception):
                raise self.apply_response
            if self.apply_response:
                return self.apply_response
            self._apply(body)
            return UpstreamResponse({"status": "applied", "changes": len(body["changes"])})
        raise AssertionError(f"Unexpected API path {path}")

    def _apply(self, body):
        for change in body["changes"]:
            if change["type"] == ADD_RULE:
                self.ruleset = apply_to_ruleset(self.ruleset, [{"type": ADD_RULE, "rule": change["rule"]}])
            else:
                self.ruleset = apply_to_ruleset(self.ruleset, [change])


class ChangeFlowTestCase(DashboardTestCase):
    def setUp(self):
        super().setUp()
        self.api = FakeApi()
        patcher = patch("webapp.api_client.urlopen", side_effect=self._respond)
        self.urlopen = patcher.start()
        self.addCleanup(patcher.stop)

    def _respond(self, request, **kwargs):
        return self.api(request, **kwargs)

    def post(self, path, **data):
        return self.client.post(path, data={"csrf_token": self.csrf_token(), **data})

    def pending(self, actor=TEST_ACTOR_ID):
        with app.app_context():
            return pending_changes.load(actor)["changes"]

    def add_rule(self, **fields):
        return self.post("/rules/new", form_action="add", **{**FORM, **fields})

    def delete_rule(self, handle=7):
        return self.post("/rules/delete", family="inet", table="filter", chain="input", handle=str(handle))

    def apply(self, **fields):
        return self.post("/changes/apply", confirm="yes", **fields)


class RuleFormTests(ChangeFlowTestCase):
    def test_form_offers_chains_and_fields(self):
        response = self.client.get("/rules/new")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"inet filter input", response.data)
        self.assertIn(b"input hook", response.data)
        for field in (b"destination_port", b"source_address", b"input_interface", b"connection_states"):
            self.assertIn(field, response.data)
        response.close()

    def test_form_explains_when_there_are_no_chains(self):
        self.api.ruleset = {"nftables": []}
        response = self.client.get("/rules/new")
        self.assertIn(b"nowhere to add a rule", response.data)
        response.close()

    def test_preview_describes_the_rule_and_changes_nothing(self):
        response = self.post("/rules/new", form_action="preview", **FORM)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Accept TCP traffic to port 443", response.data)
        self.assertIn(b"end of its chain", response.data)
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.api.applied, [])
        response.close()

    def test_adding_stores_a_pending_change_without_touching_the_firewall(self):
        response = self.add_rule()
        self.assertEqual(response.status_code, 302)
        self.assertIn("/changes", response.headers["Location"])
        changes = self.pending()
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["rule"], RULE)
        self.assertEqual(self.api.applied, [])

    def test_invalid_input_keeps_values_and_stores_nothing(self):
        invalid = {
            "subnet with host bits": ({"source_address": "192.168.1.5/24"}, b"host bits"),
            "port word": ({"destination_port": "ssh"}, b"Destination port must be"),
            "reversed range": ({"destination_port": "9-1"}, b"port range"),
            "port with ICMP": ({"protocol": "icmp"}, b"needs TCP or UDP"),
            "no match": ({"protocol": "", "destination_port": ""}, b"at least one match"),
            "bad interface": ({"input_interface": "has space"}, b"input_interface"),
            "bad chain": ({"chain": "nonsense"}, b"Choose a chain"),
            "unsupported action": ({"action": "queue"}, b"unsupported"),
        }
        for name, (fields, message) in invalid.items():
            response = self.add_rule(**fields)
            self.assertEqual(response.status_code, 400, name)
            self.assertIn(message, response.data, name)
            self.assertEqual(self.pending(), [], name)
            response.close()
        response = self.add_rule(source_address="192.168.1.5/24")
        self.assertIn(b'value="192.168.1.5/24"', response.data)
        response.close()

    def test_a_chain_that_disappeared_is_not_added(self):
        self.api.revision = "rev1"
        with patch.object(self.api, "ruleset", {"nftables": [input_chain()]}):
            response = self.add_rule(chain="inet filter gone")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.pending(), [])
        response.close()

    def test_pending_changes_are_limited(self):
        with app.app_context():
            pending_changes.save(
                TEST_ACTOR_ID,
                {
                    "changes": [{"id": str(index), "type": ADD_RULE, "rule": RULE} for index in range(pending_changes.MAX_PENDING_CHANGES)],
                    "revisions": {"inet filter input": "rev1"},
                },
            )
        response = self.add_rule()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(len(self.pending()), pending_changes.MAX_PENDING_CHANGES)
        response.close()

    def test_rendering_escapes_rule_content(self):
        hostile = "<script>x</script>"
        self.api.ruleset = {"nftables": [input_chain(), listed_rule(7, {"log": {"prefix": hostile}}, {"accept": None}, comment=None)]}
        self.delete_rule()
        response = self.client.get("/changes")
        self.assertNotIn(b"<script>x", response.data)
        self.assertIn(b"&lt;script&gt;x", response.data)
        response.close()


class ReviewTests(ChangeFlowTestCase):
    def review(self):
        response = self.client.get("/changes")
        self.addCleanup(response.close)
        return response

    def test_every_page_shows_the_pending_notice(self):
        self.add_rule()
        for path in ("/rules", "/changes", "/system"):
            response = self.client.get(path)
            self.assertIn(b"1 pending change: not applied yet", response.data, path)
            response.close()

    def test_lists_changes_as_before_and_new(self):
        self.add_rule()
        self.delete_rule()
        data = self.review().data
        self.assertIn(b"2 changes: 0 MANAGEMENT RISK, 2 other", data)
        self.assertIn(b"(none)", data)
        self.assertIn(b"Accept TCP traffic to port 443", data)
        self.assertIn(b"Accept TCP traffic to port 22", data)
        self.assertIn(b"(deleted)", data)
        self.assertIn(b"-&gt;", data)
        self.assertIn(b"inet filter input, handle 7", data)

    def test_empty_review_says_nothing_is_pending(self):
        self.assertIn(b"Nothing is pending", self.review().data)

    def test_checks_the_whole_list_with_the_backend(self):
        self.add_rule()
        self.delete_rule()
        self.review()
        body = self.api.checked[-1]
        self.assertEqual(body["expected_revisions"], [{"family": "inet", "table": "filter", "chain": "input", "revision": "rev1"}])
        self.assertEqual(body["changes"][0], {"type": "add_rule", "rule": RULE})
        self.assertEqual(body["changes"][1], {"type": "delete_rule", "family": "inet", "table": "filter", "chain": "input", "handle": 7})

    def test_names_the_change_the_backend_rejects(self):
        self.add_rule()
        self.api.check_response = UpstreamResponse({"error": "x", "code": "change_rejected", "change_index": 0}, status=422)
        data = self.review().data
        self.assertIn(b"The firewall rejected this change", data)
        self.assertIn(b"disabled", data)

    def test_flags_only_the_change_that_blocks_the_api(self):
        self.add_rule(destination_port="8080", action="drop")
        self.add_rule(destination_port="9000", action="drop")
        data = self.review().data
        self.assertIn(b"2 changes: 1 MANAGEMENT RISK, 1 other", data)
        self.assertIn(b"will block the dashboard's connection to the API", data)
        self.assertIn(b"console access", data)
        self.assertIn(b"Could disrupt the connection", data)
        self.assertLess(data.index(b"to port 8080"), data.index(b"to port 9000"))

    def test_a_deletion_that_removes_the_api_rule_is_flagged(self):
        self.api.ruleset = {"nftables": [input_chain("drop"), listed_rule(7, port_match(8080), {"accept": None})]}
        self.delete_rule()
        data = self.review().data
        self.assertIn(b"1 MANAGEMENT RISK", data)
        self.assertIn(b"drop policy", data)

    def test_an_unrelated_deletion_is_not_flagged(self):
        self.delete_rule()
        self.assertIn(b"0 MANAGEMENT RISK", self.review().data)

    def test_warns_when_a_change_could_block_the_api(self):
        self.add_rule(protocol="", destination_port="", input_interface="eth0", action="drop")
        data = self.review().data
        self.assertIn(b"could block the dashboard's connection", data)
        self.assertIn(b"MANAGEMENT RISK</span>", data)

    def test_warns_when_the_connection_is_unknown(self):
        self.api.status_info = {"status": "ok"}
        self.add_rule()
        self.assertIn(b"can't determine how the dashboard reaches the API", self.review().data)

    def test_same_host_notice(self):
        self.api.status_info = {"client_address": "127.0.0.1", "api_port": 8080}
        self.add_rule()
        response = self.client.get("/changes", environ_base={"REMOTE_ADDR": "192.0.2.50"})
        self.assertIn(b"from another computer, through the firewall", response.data)
        response.close()
        response = self.client.get("/changes", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        self.assertNotIn(b"from another computer", response.data)
        response.close()

    def test_same_host_notice_needs_a_change_to_incoming_traffic(self):
        self.api.status_info = {"client_address": "127.0.0.1", "api_port": 8080}
        self.api.ruleset = {"nftables": [input_chain(hook="output")]}
        self.add_rule()
        response = self.client.get("/changes", environ_base={"REMOTE_ADDR": "192.0.2.50"})
        self.assertNotIn(b"from another computer", response.data)
        response.close()

    def test_remove_and_discard(self):
        self.add_rule()
        self.add_rule(destination_port="444")
        first = self.pending()[0]["id"]
        self.post("/changes/remove", id=first).close()
        self.assertEqual([change["rule"]["destination_port"] for change in self.pending()], [444])
        response = self.post("/changes/discard")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.api.applied, [])

    def test_a_changed_chain_is_marked_and_can_be_reviewed_again(self):
        self.add_rule()
        self.api.revision = "rev2"
        data = self.review().data
        self.assertIn(b"This chain has changed", data)
        self.assertIn(b"Review against the current firewall", data)
        self.assertIn(b"disabled", data)
        self.post("/changes/refresh").close()
        self.assertNotIn(b"This chain has changed", self.client.get("/changes").data)
        self.assertEqual(len(self.pending()), 1)

    def test_a_deleted_rule_that_changed_stays_stale_after_refreshing(self):
        self.delete_rule()
        self.api.ruleset = {"nftables": [input_chain(), listed_rule(7, port_match(23), {"drop": None})]}
        self.api.revision = "rev2"
        self.post("/changes/refresh").close()
        data = self.review().data
        self.assertIn(b"changed or no longer exists", data)
        self.assertIn(b"disabled", data)

    def test_counter_values_do_not_make_a_deletion_stale(self):
        counted = lambda packets: {"nftables": [input_chain(), listed_rule(7, {"counter": {"packets": packets, "bytes": 1}}, {"accept": None})]}
        self.api.ruleset = counted(1)
        self.delete_rule()
        self.api.ruleset = counted(999)
        self.assertNotIn(b"no longer exists", self.review().data)

    def test_an_unavailable_backend_blocks_review_but_keeps_changes(self):
        self.add_rule()
        self.urlopen.side_effect = URLError("refused")
        data = self.review().data
        self.assertIn(b"can&#39;t be reviewed", data)
        self.assertIn(b"disabled", data)
        self.assertEqual(len(self.pending()), 1)


class ApplyTests(ChangeFlowTestCase):
    def test_applies_after_confirmation_and_clears_pending(self):
        self.add_rule()
        self.delete_rule()
        response = self.apply()
        self.assertEqual(response.status_code, 302)
        self.assertIn("/rules", response.headers["Location"])
        self.assertEqual(len(self.api.applied), 1)
        self.assertEqual(self.pending(), [])
        page = self.client.get("/rules")
        self.assertIn(b"Applied 2 changes", page.data)
        page.close()

    def test_the_result_appears_only_once(self):
        self.add_rule()
        self.apply().close()
        self.client.get("/rules").close()
        page = self.client.get("/rules")
        self.assertNotIn(b"Applied 1 change", page.data)
        page.close()

    def test_sends_the_schema_header_and_credential(self):
        self.add_rule()
        self.apply().close()
        request = [call.args[0] for call in self.urlopen.call_args_list if call.args[0].full_url.endswith("/firewall/changes")][0]
        headers = {name.lower(): value for name, value in request.headers.items()}
        self.assertIn(API_SCHEMA_VERSION_HEADER.lower(), headers)
        self.assertEqual(headers["authorization"], "Bearer test-api-access-token")

    def test_requires_confirmation(self):
        self.add_rule()
        response = self.post("/changes/apply")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Nothing was changed", response.data)
        self.assertEqual(self.api.applied, [])
        self.assertEqual(len(self.pending()), 1)
        response.close()

    def test_a_management_risk_needs_the_second_confirmation(self):
        self.add_rule(destination_port="8080", action="drop")
        response = self.apply()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.api.applied, [])
        response.close()
        self.apply(confirm_risk="yes").close()
        self.assertEqual(len(self.api.applied), 1)

    def test_an_unmanaged_rule_needs_the_second_confirmation(self):
        self.api.ruleset = {"nftables": [input_chain(), listed_rule(7, port_match(22), {"accept": None}, comment=None)]}
        self.delete_rule()
        page = self.client.get("/changes")
        self.assertIn(b"Archangel doesn&#39;t manage this rule", page.data)
        self.assertIn(b"confirm_risk", page.data)
        page.close()
        response = self.apply()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.api.applied, [])
        response.close()
        self.apply(confirm_risk="yes").close()
        self.assertEqual(len(self.api.applied), 1)

    def test_a_managed_rule_needs_only_the_normal_confirmation(self):
        self.delete_rule()
        self.apply().close()
        self.assertEqual(len(self.api.applied), 1)

    def test_rechecks_rather_than_trusting_the_earlier_review(self):
        self.add_rule()
        self.api.revision = "rev2"
        response = self.apply()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.api.applied, [])
        response.close()

    def test_failures_keep_the_changes_and_say_nothing_changed(self):
        cases = {
            "conflict": (UpstreamResponse({"error": "x", "code": "firewall_changed"}, status=409), 409, b"has changed since you reviewed"),
            "viewer": (UpstreamResponse({"error": "x"}, status=403), 403, b"account can&#39;t make this change"),
            "rejected": (UpstreamResponse({"error": "The firewall rejected this", "code": "change_rejected", "change_index": 0}, status=422), 422, b"The firewall rejected this change"),
        }
        for name, (upstream, status, message) in cases.items():
            self.api.apply_response = upstream
            self.add_rule()
            response = self.apply()
            self.assertEqual(response.status_code, status, name)
            self.assertIn(message, response.data, name)
            self.assertIn(b"othing was changed", response.data, name)
            self.assertTrue(self.pending(), name)
            response.close()
            self.post("/changes/discard").close()

    def test_rate_limits_say_how_long_to_wait(self):
        upstream = UpstreamResponse({"error": "x"}, status=429)
        upstream.headers["Retry-After"] = "30"
        self.api.apply_response = upstream
        self.add_rule()
        response = self.apply()
        self.assertEqual(response.status_code, 429)
        self.assertIn(b"Wait 30 seconds", response.data)
        response.close()

    def test_an_unknown_outcome_says_so_and_keeps_the_changes(self):
        self.api.apply_response = URLError("timed out")
        self.add_rule()
        response = self.apply()
        self.assertEqual(response.status_code, 502)
        self.assertIn(b"may or may not have been applied", response.data)
        self.assertEqual(len(self.pending()), 1)
        response.close()

    def test_a_server_failure_is_an_unknown_outcome(self):
        self.api.apply_response = UpstreamResponse({"error": "x"}, status=500)
        self.add_rule()
        response = self.apply()
        self.assertEqual(response.status_code, 502)
        self.assertIn(b"may or may not have been applied", response.data)
        self.assertNotIn(b"Nothing was changed", response.data)
        response.close()

    def test_an_expired_session_returns_to_sign_in(self):
        self.api.apply_response = UpstreamResponse({"error": "x"}, status=401)
        self.add_rule()
        response = self.apply()
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        self.assertEqual(self.api.applied[0:1] != [], True)
        self.assertEqual(len(self.pending()), 1)

    def test_a_result_it_cannot_confirm_says_so(self):
        original = self.api._apply
        self.api._apply = lambda _body: None
        self.add_rule()
        self.apply().close()
        self.api._apply = original
        page = self.client.get("/rules")
        self.assertIn(b"couldn&#39;t be confirmed", page.data)
        page.close()

    def test_requires_a_csrf_token(self):
        self.add_rule()
        response = self.client.post("/changes/apply", data={"confirm": "yes"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.api.applied, [])
        response.close()

    def test_logs_summaries_without_rule_contents(self):
        with self.assertLogs(app.logger, level=logging.INFO) as logs:
            self.add_rule(source_address="198.51.100.77", destination_port="4471")
            self.apply().close()
        joined = "\n".join(logs.output)
        self.assertIn("firewall_change_added", joined)
        self.assertIn("firewall_changes_applied count=1", joined)
        self.assertNotIn("198.51.100.77", joined)
        self.assertNotIn("4471", joined)


class EditTests(ChangeFlowTestCase):
    def setUp(self):
        super().setUp()
        self.api.ruleset = {"nftables": [input_chain(), listed_rule(7, port_match(22), {"accept": None})]}

    TARGET = {"family": "inet", "table": "filter", "chain": "input", "handle": "7"}

    def edit(self, **fields):
        return self.post("/rules/edit", form_action="add", **self.TARGET, **{"protocol": "tcp", "destination_port": "2222", "action": "accept", **fields})

    def test_edit_is_offered_only_for_rules_the_form_can_represent(self):
        page = self.client.get("/rules")
        self.assertIn(b"/rules/edit?", page.data)
        page.close()
        self.api.ruleset = {"nftables": [input_chain(), listed_rule(7, {"log": {"prefix": "x"}}, {"accept": None})]}
        page = self.client.get("/rules")
        self.assertNotIn(b"/rules/edit?", page.data)
        self.assertIn(b"can't represent", page.data)
        page.close()

    def test_the_form_starts_with_the_current_values_and_a_fixed_chain(self):
        response = self.client.get("/rules/edit?family=inet&table=filter&chain=input&handle=7")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'value="22"', response.data)
        self.assertIn(b"Edit rule", response.data)
        self.assertIn(b"keeps its position", response.data)
        self.assertIn(b'id="rule-chain" disabled', response.data)
        response.close()

    def test_preview_shows_before_and_new_and_changes_nothing(self):
        response = self.post("/rules/edit", form_action="preview", **self.TARGET, protocol="tcp", destination_port="2222", action="accept")
        self.assertIn(b"to port 22.", response.data.replace(b"to port 22</", b"to port 22.</").replace(b"to port 22<", b"to port 22.<"))
        self.assertIn(b"to port 2222", response.data)
        self.assertEqual(self.pending(), [])
        response.close()

    def test_an_edit_is_collected_then_applied_in_place(self):
        response = self.edit()
        self.assertEqual(response.status_code, 302)
        change = self.pending()[0]
        self.assertEqual(change["type"], "replace_rule")
        self.assertEqual(change["handle"], 7)
        page = self.client.get("/changes")
        self.assertIn(b"Edited rule", page.data)
        self.assertIn(b"inet filter input, handle 7", page.data)
        self.assertIn(b"Accept TCP traffic to port 22 ", page.data)
        self.assertIn(b"Accept TCP traffic to port 2222", page.data)
        page.close()
        self.apply().close()
        self.assertEqual(
            self.api.applied[0]["changes"],
            [{"type": "replace_rule", "handle": 7, "rule": {"family": "inet", "table": "filter", "chain": "input", "protocol": "tcp", "destination_port": 2222, "action": "accept"}}],
        )

    def test_an_edit_cannot_move_a_rule_to_another_chain(self):
        response = self.post("/rules/edit", form_action="add", family="inet", table="filter", chain="input", handle="7", protocol="tcp", destination_port="2222", action="accept")
        self.assertEqual(self.pending()[0]["rule"]["chain"], "input")
        response.close()

    def test_invalid_edits_are_rejected(self):
        response = self.edit(source_address="192.168.1.5/24")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"host bits", response.data)
        self.assertEqual(self.pending(), [])
        response.close()

    def test_a_missing_or_unrepresentable_rule_cannot_be_edited(self):
        for target in ({**self.TARGET, "handle": "99"}, {**self.TARGET, "handle": "x"}):
            response = self.post("/rules/edit", form_action="add", **target, protocol="tcp", action="accept")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(self.pending(), [])
        self.api.ruleset = {"nftables": [input_chain(), listed_rule(7, {"log": {"prefix": "x"}}, {"accept": None})]}
        response = self.edit()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.pending(), [])
        page = self.client.get("/rules")
        self.assertIn(b"can&#39;t be edited here", page.data)
        page.close()

    def test_a_rule_can_have_only_one_pending_change(self):
        self.edit()
        self.edit(destination_port="3333")
        self.delete_rule()
        self.assertEqual(len(self.pending()), 1)
        page = self.client.get("/rules")
        self.assertIn(b"already has a pending change", page.data)
        page.close()

    def test_an_edit_that_blocks_the_api_is_flagged(self):
        self.edit(destination_port="8080", action="drop")
        page = self.client.get("/changes")
        self.assertIn(b"1 MANAGEMENT RISK", page.data)
        page.close()

    def test_an_edit_that_removes_api_access_is_flagged(self):
        self.api.ruleset = {"nftables": [input_chain("drop"), listed_rule(7, port_match(8080), {"accept": None})]}
        self.edit(destination_port="8081")
        page = self.client.get("/changes")
        self.assertIn(b"1 MANAGEMENT RISK", page.data)
        page.close()

    def test_editing_an_unmanaged_rule_needs_the_second_confirmation(self):
        self.api.ruleset = {"nftables": [input_chain(), listed_rule(7, port_match(22), {"accept": None}, comment=None)]}
        self.edit()
        response = self.apply()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.api.applied, [])
        response.close()
        self.apply(confirm_risk="yes").close()
        self.assertEqual(len(self.api.applied), 1)

    def test_an_edit_goes_stale_if_the_rule_changed(self):
        self.edit()
        self.api.ruleset = {"nftables": [input_chain(), listed_rule(7, port_match(23), {"drop": None})]}
        self.api.revision = "rev2"
        self.post("/changes/refresh").close()
        page = self.client.get("/changes")
        self.assertIn(b"changed or no longer exists", page.data)
        page.close()
        response = self.apply()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.api.applied, [])
        response.close()


class BulkInputTests(ChangeFlowTestCase):
    def bundle(self, *rules, version=2):
        return {"format": "archangel-firewall-rules", "version": version, "rules": list(rules)}

    def test_add_and_create_another_keeps_the_values(self):
        response = self.post("/rules/new", form_action="add_another", source_address="192.0.2.0/24", **FORM)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Added to pending changes", response.data)
        self.assertIn(b'value="192.0.2.0/24"', response.data)
        self.assertIn(b'value="443"', response.data)
        response.close()
        self.assertEqual(len(self.pending()), 1)

    def test_many_rules_can_be_added_in_a_row(self):
        for port in range(1000, 1020):
            self.post("/rules/new", form_action="add_another", **{**FORM, "destination_port": str(port)}).close()
        self.assertEqual(len(self.pending()), 20)
        self.apply().close()
        self.assertEqual(len(self.api.applied), 1)
        self.assertEqual(len(self.api.applied[0]["changes"]), 20)

    def test_duplicate_starts_from_an_existing_rule(self):
        self.api.ruleset = {
            "nftables": [
                input_chain(),
                listed_rule(
                    7,
                    {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "192.0.2.0", "len": 24}}}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"range": [8000, 8100]}}},
                    {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["new", "established"]}},
                    {"drop": None},
                ),
            ]
        }
        page = self.client.get("/rules")
        self.assertIn(b"Duplicate", page.data)
        page.close()
        response = self.client.get("/rules/new?family=inet&table=filter&chain=input&handle=7")
        self.assertIn(b'value="192.0.2.0/24"', response.data)
        self.assertIn(b'value="8000-8100"', response.data)
        self.assertIn(b'value="established" checked', response.data)
        self.assertIn(b'value="invalid" >', response.data.replace(b'value="invalid"  >', b'value="invalid" >'))
        self.assertIn(b'value="drop" selected', response.data)
        response.close()
        self.assertEqual(self.pending(), [])

    def test_duplicate_is_not_offered_for_rules_the_form_cannot_represent(self):
        self.api.ruleset = {"nftables": [input_chain(), listed_rule(7, {"log": {"prefix": "x"}}, {"accept": None})]}
        page = self.client.get("/rules")
        self.assertNotIn(b"Duplicate", page.data)
        page.close()
        response = self.client.get("/rules/new?family=inet&table=filter&chain=input&handle=7")
        self.assertIn(b'value="accept" selected', response.data)
        response.close()

    def preview(self, bundle):
        return self.client.post(
            "/rules/import",
            data={
                "action": "preview",
                "csrf_token": self.csrf_token(),
                "bundle_file": (io.BytesIO(json.dumps(bundle).encode()), "rules.json"),
            },
            content_type="multipart/form-data",
        )

    def test_import_previews_without_changing_anything(self):
        response = self.preview(self.bundle(RULE))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Accept TCP traffic to port 443", response.data)
        self.assertIn(b"Add to pending changes", response.data)
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.api.applied, [])
        response.close()

    def test_import_adds_every_rule_to_pending_changes(self):
        rules = [{**RULE, "destination_port": port} for port in (1, 2, 3)]
        response = self.post("/rules/import", action="add", bundle=json.dumps(self.bundle(*rules)))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/changes", response.headers["Location"])
        self.assertEqual([change["rule"] for change in self.pending()], rules)
        self.assertEqual(self.api.applied, [])

    def test_imported_rules_apply_together(self):
        rules = [{**RULE, "destination_port": port} for port in (1, 2, 3)]
        self.post("/rules/import", action="add", bundle=json.dumps(self.bundle(*rules))).close()
        self.apply().close()
        self.assertEqual(len(self.api.applied), 1)
        self.assertEqual(len(self.api.applied[0]["changes"]), 3)

    def test_version_1_bundles_still_import(self):
        response = self.post("/rules/import", action="add", bundle=json.dumps(self.bundle(RULE, version=1)))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(self.pending()), 1)

    def test_import_is_all_or_none_when_a_chain_is_missing(self):
        response = self.post(
            "/rules/import",
            action="add",
            bundle=json.dumps(self.bundle(RULE, {**RULE, "chain": "gone"})),
        )
        self.assertEqual(response.status_code, 409)
        self.assertIn(b"inet filter gone", response.data)
        self.assertEqual(self.pending(), [])
        response.close()

    def test_import_rejects_invalid_or_oversized_bundles(self):
        response = self.post("/rules/import", action="add", bundle="not json")
        self.assertEqual(response.status_code, 400)
        response.close()
        response = self.post("/rules/import", action="add", bundle=json.dumps(self.bundle({**RULE, "source_address": "192.0.2.5/24"})))
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"host bits", response.data)
        response.close()
        response = self.post("/rules/import", action="add", bundle="x" * (512 * 1024 + 1))
        self.assertEqual(response.status_code, 413)
        response.close()
        self.assertEqual(self.pending(), [])

    def test_import_with_no_rules_adds_nothing(self):
        response = self.post("/rules/import", action="add", bundle=json.dumps(self.bundle()))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"nothing was added", response.data)
        response.close()

    def test_import_respects_the_pending_limit(self):
        rules = [{**RULE, "destination_port": 1 + index % 60000} for index in range(pending_changes.MAX_PENDING_CHANGES)]
        self.add_rule()
        response = self.post("/rules/import", action="add", bundle=json.dumps(self.bundle(*rules)))
        self.assertEqual(response.status_code, 409)
        self.assertEqual(len(self.pending()), 1)
        response.close()


class PendingStoreTests(ChangeFlowTestCase):
    def test_changes_survive_a_new_sign_in(self):
        self.add_rule()
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
            browser_session["access_token"] = "a-new-token"
            browser_session["actor_id"] = TEST_ACTOR_ID
            browser_session["_csrf_token"] = "test-csrf-token"
        self.assertEqual(len(self.pending()), 1)
        page = self.client.get("/changes")
        self.assertIn(b"Accept TCP traffic to port 443", page.data)
        page.close()

    def test_changes_are_separate_between_users(self):
        self.add_rule()
        self.assertEqual(self.pending("another-user"), [])
        with self.client.session_transaction() as browser_session:
            browser_session["actor_id"] = "another-user"
        page = self.client.get("/changes")
        self.assertIn(b"Nothing is pending", page.data)
        page.close()

    def test_changes_expire_after_a_day(self):
        self.add_rule()
        self.assertEqual(len(self.pending()), 1)
        with patch("webapp.pending_changes.time") as clock:
            clock.time.return_value = time.time() + pending_changes.PENDING_LIFETIME_SECONDS + 1
            self.assertEqual(self.pending(), [])

    def test_adding_restarts_the_expiry(self):
        self.add_rule()
        later = time.time() + pending_changes.PENDING_LIFETIME_SECONDS - 10
        with patch("webapp.pending_changes.time") as clock:
            clock.time.return_value = later
            self.add_rule(destination_port="444")
            clock.time.return_value = later + 60
            self.assertEqual(len(self.pending()), 2)


class ChangeLogicTests(DashboardTestCase):
    def test_rule_statements_match_what_the_backend_builds(self):
        # Keep in step with buildsExactlyTheStatementsNftablesExpects in
        # backend/tests/test_nft_rule.cpp.
        rule = {
            "family": "inet",
            "table": "filter",
            "chain": "input",
            "action": "drop",
            "input_interface": "eth0",
            "output_interface": "lo",
            "connection_states": ["new", "related"],
            "source_address": "192.168.1.0/24",
            "destination_address": "192.0.2.1",
            "protocol": "tcp",
            "destination_port": 8000,
            "destination_port_end": 8100,
        }
        expected = json.loads(
            """[
            {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},
            {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"lo"}},
            {"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["new","related"]}},
            {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"192.168.1.0","len":24}}}},
            {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"192.0.2.1"}},
            {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"range":[8000,8100]}}},
            {"drop":null}
        ]"""
        )
        self.assertEqual(rule_statements(rule), expected)

    def warnings(self, entries, hook="input", interfaces=None, **rule):
        ruleset = {"nftables": [input_chain(hook=hook)] + entries}
        change = {"id": "a", "type": ADD_RULE, "rule": {**RULE, **rule}}
        return " ".join(change_warnings(ruleset, apply_to_ruleset(ruleset, [change]), change, interfaces))

    def test_rule_warnings(self):
        self.assertIn("other access", self.warnings([], action="drop"))
        self.assertIn("other access", self.warnings([], action="reject"))
        self.assertNotIn("other access", self.warnings([]))
        self.assertIn("every address", self.warnings([]))
        self.assertNotIn("every address", self.warnings([], source_address="192.0.2.1"))
        self.assertIn("every address", self.warnings([], source_address="0.0.0.0/0"))
        self.assertIn("can never match", self.warnings([], hook="output", input_interface="lo"))
        self.assertIn("can never match", self.warnings([], output_interface="lo"))
        self.assertNotIn("can never match", self.warnings([], input_interface="lo"))
        self.assertIn("doesn't exist", self.warnings([], interfaces=["lo"], input_interface="wg0"))
        self.assertNotIn("doesn't exist", self.warnings([], interfaces=["lo"], input_interface="lo"))
        self.assertNotIn("doesn't exist", self.warnings([], interfaces=None, input_interface="wg0"))

    def test_warns_about_a_rule_that_can_never_apply(self):
        always = listed_rule(1, {"drop": None})
        self.assertIn("may never take effect", self.warnings([always]))
        conditional = listed_rule(1, port_match(1), {"drop": None})
        self.assertNotIn("may never take effect", self.warnings([conditional]))

    def test_warns_about_duplicates(self):
        same = listed_rule(1, port_match(443), {"accept": None})
        self.assertIn("duplicate", self.warnings([same]))
        self.assertNotIn("duplicate", self.warnings([]))

    def test_deletion_warnings(self):
        rule = listed_rule(7, port_match(22), {"accept": None}, comment=None)
        ruleset = {"nftables": [input_chain(), rule]}
        change = {"id": "a", "type": DELETE_RULE, "family": "inet", "table": "filter", "chain": "input", "handle": 7, "before": rule["rule"]}
        warnings = " ".join(change_warnings(ruleset, apply_to_ruleset(ruleset, [change]), change))
        self.assertIn("currently allowed", warnings)
        self.assertIn("doesn't manage", warnings)

    def test_two_changes_that_each_block_are_both_flagged(self):
        ruleset = {"nftables": [input_chain()]}
        block = lambda change_id: {"id": change_id, "type": ADD_RULE, "rule": {**RULE, "destination_port": 8080, "action": "drop"}}
        check, flagged = management_risk(ruleset, [block("a"), block("b")], Connection("192.0.2.20", 8080))
        self.assertEqual(check.status, "will_block")
        self.assertEqual(flagged, {"a", "b"})

    def test_stale_changes_finds_missing_chains_and_rules(self):
        ruleset = {"nftables": [input_chain(), listed_rule(7, {"accept": None})]}
        gone_chain = {"id": "a", "type": ADD_RULE, "rule": {**RULE, "chain": "gone"}}
        gone_rule = {"id": "b", "type": DELETE_RULE, "family": "inet", "table": "filter", "chain": "input", "handle": 99, "before": {"expr": []}}
        fine = {"id": "c", "type": DELETE_RULE, "family": "inet", "table": "filter", "chain": "input", "handle": 7, "before": listed_rule(7, {"accept": None})["rule"]}
        self.assertEqual(stale_changes(ruleset, [gone_chain, gone_rule, fine]), {"a", "b"})

    def test_verify_applied_requires_every_change_to_be_visible(self):
        added = {"id": "a", "type": ADD_RULE, "rule": RULE}
        deleted = {"id": "b", "type": DELETE_RULE, "family": "inet", "table": "filter", "chain": "input", "handle": 7, "before": {}}
        before = {"nftables": [input_chain(), listed_rule(7, {"accept": None})]}
        self.assertFalse(verify_applied(before, [added]))
        self.assertFalse(verify_applied(before, [deleted]))
        self.assertTrue(verify_applied(apply_to_ruleset(before, [added, deleted]), [added, deleted]))
