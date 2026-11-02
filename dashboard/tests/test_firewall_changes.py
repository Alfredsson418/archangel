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
            chains = [entry["chain"] for entry in self.ruleset["nftables"] if isinstance(entry, dict) and "chain" in entry]
            return UpstreamResponse(
                {"chains": [{"family": chain["family"], "table": chain["table"], "chain": chain["name"], "revision": self.revision} for chain in chains]}
            )
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
        for path in ("/rules", "/system"):
            response = self.client.get(path)
            self.assertIn(b"1 pending change: not applied yet", response.data, path)
            response.close()
        # The review page is where the notice links to, so it doesn't repeat it.
        response = self.client.get("/changes")
        self.assertNotIn(b"not applied yet", response.data)
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

    def test_applied_rules_are_marked_on_the_rules_page_once(self):
        self.add_rule()
        self.apply().close()
        page = self.client.get("/rules")
        self.assertEqual(page.data.count(b"JUST APPLIED</span>"), 1)
        self.assertLess(page.data.index(b"JUST APPLIED</span>"), page.data.index(b"443"))
        page.close()
        page = self.client.get("/rules")
        self.assertNotIn(b"JUST APPLIED</span>", page.data)
        page.close()

    def test_edited_rules_are_marked_too(self):
        self.post("/rules/edit", form_action="add", family="inet", table="filter", chain="input", handle="7", protocol="tcp", destination_port="2222", action="accept").close()
        self.apply().close()
        page = self.client.get("/rules")
        self.assertIn(b"JUST APPLIED</span>", page.data)
        page.close()

    def test_a_retry_after_an_unknown_outcome_does_not_apply_twice(self):
        # The request reached the backend and applied, but the reply was lost.

        original_call = self.api.__call__
        self.add_rule()

        def lose_reply(request, **kwargs):
            if request.full_url.endswith("/api/v1/firewall/changes"):
                self.api._apply(json.loads(request.data))
                self.api.revision = "rev2"
                self.api.applied.append(json.loads(request.data))
                raise URLError("timed out")
            return original_call(request, **kwargs)

        self.urlopen.side_effect = lose_reply
        response = self.apply()
        self.assertEqual(response.status_code, 502)
        self.assertEqual(len(self.pending()), 1)
        response.close()

        self.urlopen.side_effect = self._respond
        response = self.client.get("/changes")
        self.assertEqual(response.status_code, 302)
        response.close()
        self.assertEqual(self.pending(), [])
        self.assertEqual(len(self.api.applied), 1)
        page = self.client.get("/rules")
        self.assertIn(b"did apply these 1 change", page.data)
        page.close()

    def test_a_list_that_did_not_apply_stays_pending_after_an_unknown_outcome(self):
        self.api.apply_response = URLError("timed out")
        self.add_rule()
        self.apply().close()
        self.api.apply_response = None
        self.assertEqual(len(self.pending()), 1)
        page = self.client.get("/changes")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Accept TCP traffic to port 443", page.data)
        page.close()
        self.apply().close()
        self.assertEqual(self.pending(), [])
        self.assertEqual(len(self.api.applied), 2)

    def test_an_identical_existing_rule_is_not_mistaken_for_an_applied_list(self):
        self.api.ruleset = {"nftables": [input_chain(), listed_rule(7, port_match(443), {"accept": None})]}
        self.api.apply_response = URLError("timed out")
        self.add_rule()
        self.apply().close()
        self.api.apply_response = None
        page = self.client.get("/changes")
        self.assertEqual(page.status_code, 200)
        page.close()
        self.assertEqual(len(self.pending()), 1)

    def test_an_unknown_outcome_stays_unresolved_while_the_backend_is_down(self):
        self.api.apply_response = URLError("timed out")
        self.add_rule()
        self.apply().close()
        self.urlopen.side_effect = URLError("refused")
        page = self.client.get("/changes")
        self.assertIn(b"can't be reviewed", page.data.replace(b"&#39;", b"'"))
        page.close()
        with app.app_context():
            self.assertTrue(pending_changes.load(TEST_ACTOR_ID).get("outcome_unknown"))

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

    def test_adding_a_rule_makes_as_few_api_calls_as_possible(self):
        self.add_rule()
        first = self.urlopen.call_count
        self.add_rule(destination_port="444")
        self.assertEqual(self.urlopen.call_count, first, "a second rule on the same chain needs no API calls")

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


class OrganizeTests(ChangeFlowTestCase):
    CHAIN = "inet filter input"

    def setUp(self):
        super().setUp()
        self.api.ruleset = {
            "nftables": [
                input_chain(),
                listed_rule(1, port_match(1), {"accept": None}),
                listed_rule(2, port_match(2), {"accept": None}),
                listed_rule(3, port_match(3), {"drop": None}, comment=None),
            ]
        }

    def organize(self, *order):
        return self.client.post(
            "/rules/organize",
            data={"csrf_token": self.csrf_token(), "chain": self.CHAIN, "order": list(order)},
        )

    def page(self):
        response = self.client.get("/rules/organize", query_string={"chain": self.CHAIN})
        self.addCleanup(response.close)
        return response

    def test_lists_rules_in_true_order_without_changing_anything(self):
        data = self.page().data
        self.assertLess(data.index(b"to port 1"), data.index(b"to port 2"))
        self.assertLess(data.index(b"to port 2"), data.index(b"to port 3"))
        self.assertIn(b'value="handle:2"', data)
        self.assertEqual(self.pending(), [])

    def test_the_page_offers_the_script_and_a_form_that_works_without_it(self):
        data = self.page().data
        self.assertIn(b"rule_order.js", data)
        self.assertIn(b"sortable-1.15.6.min.js", data)
        self.assertIn(b'name="move_position"', data)
        self.assertNotIn(b"cdn", data)

    def test_the_script_and_library_are_served_locally(self):
        for path in ("/static/rule_order.js", "/static/vendor/sortable-1.15.6.min.js"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            response.close()

    def test_a_missing_chain_returns_to_the_rules_page(self):
        response = self.client.get("/rules/organize", query_string={"chain": "inet filter gone"})
        self.assertEqual(response.status_code, 302)
        response.close()

    def test_a_chain_without_rules_says_so(self):
        self.api.ruleset = {"nftables": [input_chain()]}
        self.assertIn(b"no rules to organize", self.page().data)

    def test_saving_an_order_adds_a_pending_change(self):
        response = self.organize("handle:2", "handle:1", "handle:3")
        self.assertEqual(response.status_code, 302)
        change = self.pending()[0]
        self.assertEqual(change["type"], "set_rule_order")
        self.assertEqual(change["order"], [2, 1, 3])

    def test_the_review_shows_old_and_new_positions(self):
        self.organize("handle:2", "handle:1", "handle:3").close()
        response = self.client.get("/changes")
        self.assertIn(b"Rule order", response.data)
        self.assertIn(b"to port 2: position 2 -&gt; position 1", response.data)
        self.assertIn(b"to port 1: position 1 -&gt; position 2", response.data)
        self.assertNotIn(b"to port 3: position", response.data)
        self.assertIn(b"Full new order", response.data)
        response.close()

    def test_applying_sends_one_order_change(self):
        self.organize("handle:2", "handle:1", "handle:3").close()
        self.apply().close()
        self.assertEqual(
            self.api.applied[0]["changes"],
            [{"type": "set_rule_order", "family": "inet", "table": "filter", "chain": "input", "order": [2, 1, 3]}],
        )

    def test_a_tampered_or_outdated_order_is_refused(self):
        for order in (("handle:1", "handle:2"), ("handle:1", "handle:2", "handle:3", "handle:9"), ("handle:1", "handle:1", "handle:2"), ("nope",)):
            response = self.organize(*order)
            self.assertEqual(response.status_code, 409, order)
            self.assertEqual(self.pending(), [], order)
            response.close()

    def test_the_same_order_adds_nothing(self):
        response = self.organize("handle:1", "handle:2", "handle:3")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.pending(), [])

    def test_saving_again_replaces_the_pending_order(self):
        self.organize("handle:2", "handle:1", "handle:3").close()
        self.organize("handle:3", "handle:1", "handle:2").close()
        changes = self.pending()
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["order"], [3, 1, 2])
        self.assertLess(self.page().data.index(b"to port 3"), self.page().data.index(b"to port 1"))

    def test_returning_to_the_original_order_removes_the_pending_order(self):
        self.organize("handle:2", "handle:1", "handle:3").close()
        self.organize("handle:1", "handle:2", "handle:3").close()
        self.assertEqual(self.pending(), [])

    def test_the_form_without_javascript_moves_one_rule(self):
        response = self.client.post(
            "/rules/organize",
            data={"csrf_token": self.csrf_token(), "chain": self.CHAIN, "form_action": "move", "move_rule": "handle:3", "move_position": "1"},
        )
        self.assertEqual(response.status_code, 302)
        response.close()
        self.assertEqual(self.pending()[0]["order"], [3, 1, 2])

    def test_the_form_without_javascript_rejects_bad_positions(self):
        for position in ("0", "4", "x", ""):
            response = self.client.post(
                "/rules/organize",
                data={"csrf_token": self.csrf_token(), "chain": self.CHAIN, "form_action": "move", "move_rule": "handle:3", "move_position": position},
            )
            self.assertEqual(response.status_code, 400, position)
            response.close()
        self.assertEqual(self.pending(), [])

    def test_pending_new_rules_can_be_placed_among_existing_ones(self):
        self.add_rule(destination_port="99")
        new_id = self.pending()[0]["id"]
        data = self.page().data
        self.assertIn(b"PENDING NEW RULE", data)
        self.organize(f"new:{new_id}", "handle:1", "handle:2", "handle:3").close()
        changes = self.pending()
        self.assertEqual(changes[1]["order"], [new_id, 1, 2, 3])
        self.client.get("/changes").close()
        body = self.api.checked[-1]
        self.assertEqual(body["changes"][0]["id"], new_id)
        self.assertEqual(body["changes"][1]["order"], [new_id, 1, 2, 3])

    def test_rules_added_without_an_order_send_no_id(self):
        self.add_rule(destination_port="99")
        self.client.get("/changes").close()
        self.assertNotIn("id", self.api.checked[-1]["changes"][0])

    def test_pending_deletions_are_reflected_in_the_order(self):
        self.delete_rule(1)
        data = self.page().data
        self.assertNotIn(b'value="handle:1"', data)
        self.organize("handle:3", "handle:2").close()
        self.assertEqual(self.pending()[1]["order"], [3, 2])

    def test_removing_a_new_rule_also_removes_it_from_the_order(self):
        self.add_rule(destination_port="99")
        new_id = self.pending()[0]["id"]
        self.organize(f"new:{new_id}", "handle:1", "handle:2", "handle:3").close()
        self.post("/changes/remove", id=new_id).close()
        changes = self.pending()
        self.assertEqual(changes[0]["order"], [1, 2, 3])
        self.assertEqual([row["key"] for row in changes[0]["new_order"]], [1, 2, 3])

    def test_removing_a_deletion_makes_the_order_stale(self):
        self.delete_rule(1)
        deletion = self.pending()[0]["id"]
        self.organize("handle:3", "handle:2").close()
        self.post("/changes/remove", id=deletion).close()
        response = self.client.get("/changes")
        self.assertIn(b"organize them again", response.data)
        self.assertIn(b"disabled", response.data)
        response.close()

    def test_a_move_that_blocks_the_api_is_flagged(self):
        self.api.ruleset = {
            "nftables": [
                input_chain(),
                listed_rule(1, port_match(8080), {"accept": None}),
                listed_rule(2, port_match(8080), {"drop": None}),
            ]
        }
        self.organize("handle:2", "handle:1").close()
        response = self.client.get("/changes")
        self.assertIn(b"1 MANAGEMENT RISK", response.data)
        response.close()

    def test_a_harmless_move_is_not_flagged(self):
        self.organize("handle:2", "handle:1", "handle:3").close()
        response = self.client.get("/changes")
        self.assertIn(b"0 MANAGEMENT RISK", response.data)
        response.close()

    def test_moving_an_unmanaged_rule_needs_the_second_confirmation(self):
        self.organize("handle:3", "handle:1", "handle:2").close()
        response = self.client.get("/changes")
        self.assertIn(b"moves rules Archangel doesn&#39;t manage", response.data)
        response.close()
        response = self.apply()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.api.applied, [])
        response.close()
        self.apply(confirm_risk="yes").close()
        self.assertEqual(len(self.api.applied), 1)

    def test_moving_only_managed_rules_needs_the_normal_confirmation(self):
        self.organize("handle:2", "handle:1", "handle:3").close()
        self.apply().close()
        self.assertEqual(len(self.api.applied), 1)

    def test_warns_when_rules_are_placed_below_one_that_always_applies(self):
        self.api.ruleset = {
            "nftables": [
                input_chain(),
                listed_rule(1, port_match(1), {"accept": None}),
                listed_rule(2, {"accept": None}),
            ]
        }
        self.organize("handle:2", "handle:1").close()
        response = self.client.get("/changes")
        self.assertIn(b"may never take effect", response.data)
        response.close()

    def test_rendering_escapes_rule_content(self):
        self.api.ruleset = {"nftables": [input_chain(), listed_rule(1, {"log": {"prefix": "<script>x</script>"}}, {"accept": None})]}
        data = self.page().data
        self.assertNotIn(b"<script>x", data)
        self.assertIn(b"&lt;script&gt;x", data)


class StructureTests(ChangeFlowTestCase):
    def setUp(self):
        super().setUp()
        self.api.ruleset = {
            "nftables": [
                {"table": {"family": "inet", "name": "filter"}},
                input_chain(),
                {"chain": {"family": "inet", "table": "filter", "name": "helper"}},
                listed_rule(7, port_match(22), {"accept": None}),
            ]
        }

    def act(self, action, **fields):
        return self.post("/firewall/structure", structure_action=action, family="inet", **fields)

    def review(self):
        response = self.client.get("/changes")
        self.addCleanup(response.close)
        return response.get_data(as_text=True).replace("&#39;", "'").replace("&gt;", ">")

    def test_the_page_lists_tables_chains_and_restrictions(self):
        response = self.client.get("/rules")
        text = response.get_data(as_text=True)
        response.close()
        self.assertIn('data-nav="table:inet filter"', text)
        self.assertIn("helper", text)
        self.assertIn("regular chain", text)
        self.assertIn("a table can't be renamed", text)
        self.assertIn("hook and priority can't be changed", text)

    def test_other_families_are_read_only(self):
        self.api.ruleset["nftables"].append({"table": {"family": "netdev", "name": "edge"}})
        response = self.client.get("/rules?family=netdev&table=edge")
        self.assertIn(b"can't be managed here", response.data)
        response.close()
        result = self.post("/firewall/structure", structure_action="delete_table", family="netdev", name="edge")
        self.assertEqual(result.status_code, 400)
        self.assertEqual(self.pending(), [])
        result.close()

    def test_no_change_touches_the_firewall_until_applied(self):
        self.act("create_table", name="fresh").close()
        self.act("create_chain", table="filter", name="fresh").close()
        self.act("rename_chain", table="filter", name="helper", new_name="better").close()
        self.assertEqual(len(self.pending()), 3)
        self.assertEqual(self.api.applied, [])

    def test_creating_a_table_and_chain_and_rule_in_one_list(self):
        self.act("create_table", name="fresh").close()
        self.act("create_chain", table="fresh", name="c").close()
        self.add_rule(chain="inet fresh c").close()
        text = self.review()
        self.assertIn("New table", text)
        self.assertIn("New chain", text)
        self.apply().close()
        changes = self.api.applied[0]["changes"]
        self.assertEqual(changes[0], {"type": "create_table", "family": "inet", "name": "fresh"})
        self.assertEqual(changes[1], {"type": "create_chain", "family": "inet", "table": "fresh", "name": "c"})
        self.assertEqual(changes[2]["rule"]["chain"], "c")
        self.assertEqual(self.api.applied[0]["expected_revisions"], [])

    def test_a_pending_chain_can_be_chosen_in_the_rule_form(self):
        self.act("create_chain", table="filter", name="fresh").close()
        response = self.client.get("/rules/new")
        self.assertIn(b"inet filter fresh", response.data)
        response.close()

    def test_creating_a_base_chain(self):
        self.act("create_chain", table="filter", name="fw", hook="forward", priority="-10", policy="drop").close()
        self.assertEqual(self.pending()[0]["base"], {"type": "filter", "hook": "forward", "priority": -10, "policy": "drop"})
        self.assertIn("forward hook, priority -10, policy drop", self.review())

    def test_rejects_invalid_names_and_definitions(self):
        for action, fields in (
            ("create_table", {"name": "bad name"}),
            ("create_table", {"name": "1bad"}),
            ("create_chain", {"table": "filter", "name": "bad;name"}),
            ("create_chain", {"table": "filter", "name": "c", "hook": "ingress", "policy": "drop"}),
            ("create_chain", {"table": "filter", "name": "c", "hook": "input", "priority": "99999", "policy": "drop"}),
            ("create_chain", {"table": "filter", "name": "c", "hook": "input", "priority": "x", "policy": "drop"}),
            ("create_chain", {"table": "filter", "name": "c", "hook": "input", "priority": "0", "policy": "reject"}),
            ("rename_chain", {"table": "filter", "name": "helper", "new_name": "bad name"}),
            ("set_chain_policy", {"table": "filter", "name": "input", "policy": "reject"}),
            ("set_chain_policy", {"table": "filter", "name": "helper", "policy": "drop"}),
            ("set_chain_policy", {"table": "filter", "name": "input", "policy": "accept"}),
            ("flush_everything", {"table": "filter", "name": "input"}),
        ):
            response = self.act(action, **fields)
            self.assertEqual(response.status_code, 400, (action, fields))
            self.assertEqual(self.pending(), [], (action, fields))
            response.close()

    def test_renaming_shows_before_and_new(self):
        self.act("rename_chain", table="filter", name="helper", new_name="better").close()
        text = self.review()
        self.assertIn("Renamed chain", text)
        self.assertIn("helper", text)
        self.assertIn("better", text)
        self.apply().close()
        self.assertEqual(
            self.api.applied[0]["changes"][0],
            {"type": "rename_chain", "family": "inet", "table": "filter", "name": "helper", "new_name": "better"},
        )

    def test_a_chains_rules_cannot_change_after_it_is_renamed(self):
        self.act("rename_chain", table="filter", name="input", new_name="renamed").close()
        for response in (
            self.add_rule(chain="inet filter renamed"),
            self.add_rule(chain="inet filter input"),
        ):
            self.assertEqual(response.status_code, 409)
            self.assertIn(b"pending rename or deletion", response.data)
            response.close()
        self.delete_rule(7).close()
        self.post("/rules/edit", form_action="add", family="inet", table="filter", chain="input", handle="7", protocol="tcp", destination_port="23", action="accept").close()
        response = self.client.get("/rules/organize", query_string={"chain": "inet filter input"})
        self.assertEqual(response.status_code, 302)
        response.close()
        self.assertEqual(len(self.pending()), 1)

    def test_renamed_chains_leave_the_rule_form(self):
        self.act("rename_chain", table="filter", name="helper", new_name="better").close()
        response = self.client.get("/rules/new")
        self.assertNotIn(b"inet filter helper", response.data)
        self.assertNotIn(b"inet filter better", response.data)
        response.close()

    def test_a_chain_with_a_pending_order_cannot_be_renamed_or_deleted(self):
        self.api.ruleset["nftables"].append(listed_rule(8, port_match(23), {"accept": None}))
        self.client.post("/rules/organize", data={"csrf_token": self.csrf_token(), "chain": "inet filter input", "order": ["handle:8", "handle:7"]}).close()
        for action, fields in (("rename_chain", {"new_name": "x"}), ("delete_chain", {})):
            response = self.act(action, table="filter", name="input", **fields)
            self.assertEqual(response.status_code, 400)
            self.assertIn(b"pending rule order", response.data)
            response.close()
        response = self.act("delete_table", name="filter")
        self.assertEqual(response.status_code, 400)
        response.close()

    def test_changing_a_policy_to_drop_warns_and_flags_the_api(self):
        self.act("set_chain_policy", table="filter", name="input", policy="drop").close()
        text = self.review()
        self.assertIn("accept <span", text.replace("</div>", ""))
        self.assertIn("1 MANAGEMENT RISK", text)
        self.assertIn("will block the dashboard's connection", text)
        self.assertIn("other access to this server", text)
        self.assertEqual(self.pending()[0]["old_policy"], "accept")

    def test_a_policy_change_sends_only_what_the_api_accepts(self):
        self.api.ruleset["nftables"].append(listed_rule(9, port_match(8080), {"accept": None}))
        self.act("set_chain_policy", table="filter", name="input", policy="drop").close()
        self.apply(confirm_risk="yes").close()
        self.assertEqual(
            self.api.applied[0]["changes"][0],
            {"type": "set_chain_policy", "family": "inet", "table": "filter", "name": "input", "policy": "drop"},
        )

    def test_deleting_an_empty_chain_needs_no_typed_name(self):
        self.act("delete_chain", table="filter", name="helper").close()
        text = self.review()
        self.assertIn("0 rules", text)
        self.assertNotIn("confirm_name_", text)
        self.apply().close()
        self.assertEqual(len(self.api.applied), 1)

    def test_deleting_a_chain_with_rules_needs_its_name_typed(self):
        self.act("delete_chain", table="filter", name="input").close()
        change_id = self.pending()[0]["id"]
        text = self.review()
        self.assertIn("1 rule ", text)
        self.assertIn(f"confirm_name_{change_id}", text)
        self.assertIn("deletes this chain's rules with it", text)
        for typed in ({}, {f"confirm_name_{change_id}": "wrong"}):
            response = self.apply(**typed)
            self.assertEqual(response.status_code, 400)
            self.assertEqual(self.api.applied, [])
            response.close()
        self.apply(**{f"confirm_name_{change_id}": "input"}).close()
        self.assertEqual(len(self.api.applied), 1)

    def test_a_chain_other_rules_jump_to_cannot_be_deleted(self):
        self.api.ruleset["nftables"].append(listed_rule(9, {"jump": {"target": "helper"}}))
        self.act("delete_chain", table="filter", name="helper").close()
        text = self.review()
        self.assertIn("Other rules jump to this chain (handles 9)", text)
        self.assertIn("disabled", text)
        response = self.apply()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.api.applied, [])
        response.close()

    def test_removing_the_jump_in_the_same_list_allows_deleting_the_chain(self):
        self.api.ruleset["nftables"].append(listed_rule(9, {"jump": {"target": "helper"}}))
        self.delete_rule(9).close()
        self.act("delete_chain", table="filter", name="helper").close()
        self.assertNotIn("Other rules jump", self.review())

    def test_deleting_a_table_needs_its_name_typed_and_lists_its_contents(self):
        self.api.ruleset["nftables"].append({"set": {"family": "inet", "table": "filter", "name": "ports"}})
        self.act("delete_table", name="filter").close()
        change = self.pending()[0]
        text = self.review()
        self.assertIn("2 chains, 1 rule, 1 other object", text)
        self.assertIn(f"confirm_name_{change['id']}", text)
        response = self.apply(confirm_risk="yes")
        self.assertEqual(response.status_code, 400)
        response.close()
        self.apply(confirm_risk="yes", **{f"confirm_name_{change['id']}": "filter"}).close()
        self.assertEqual(self.api.applied[0]["changes"][0], {"type": "delete_table", "family": "inet", "name": "filter"})
        self.assertEqual(sorted(entry["chain"] for entry in self.api.applied[0]["expected_revisions"]), ["helper", "input"])

    def test_turning_a_table_off_needs_its_name_typed_and_warns(self):
        self.act("disable_table", name="filter").close()
        change = self.pending()[0]
        text = self.review()
        self.assertIn("Table enforcement", text)
        self.assertIn("stops being enforced", text)
        self.assertIn(f"confirm_name_{change['id']}", text)
        response = self.apply()
        self.assertEqual(response.status_code, 400)
        response.close()
        self.apply(**{f"confirm_name_{change['id']}": "filter"}).close()
        self.assertEqual(self.api.applied[0]["changes"][0], {"type": "set_table_enabled", "family": "inet", "name": "filter", "enabled": False})

    def test_a_table_that_is_off_is_reported_everywhere(self):
        self.api.ruleset["nftables"][0]["table"]["flags"] = ["dormant"]
        response = self.client.get("/rules")
        self.assertIn(b"Enforcement is off", response.data)
        self.assertIn(b"ENFORCEMENT OFF", response.data)
        self.assertIn(b"Turn enforcement on", response.data)
        response.close()

    def test_turning_a_table_on_needs_no_typed_name(self):
        self.api.ruleset["nftables"][0]["table"]["flags"] = ["dormant"]
        self.act("enable_table", name="filter").close()
        self.assertNotIn("confirm_name_", self.review())
        self.apply().close()
        self.assertTrue(self.api.applied[0]["changes"][0]["enabled"])


    def test_deleting_the_table_that_allows_the_api_is_not_a_risk_on_its_own(self):
        # With no other table, deleting it leaves everything allowed.
        self.act("delete_table", name="filter").close()
        self.assertIn("0 MANAGEMENT RISK", self.review())

    def test_unmanaged_contents_need_the_second_confirmation(self):
        self.api.ruleset["nftables"].append(listed_rule(9, port_match(9), {"accept": None}, comment=None))
        self.act("rename_chain", table="filter", name="input", new_name="renamed").close()
        text = self.review()
        self.assertIn("rules Archangel doesn't manage", text)
        response = self.apply()
        self.assertEqual(response.status_code, 400)
        response.close()
        self.apply(confirm_risk="yes").close()
        self.assertEqual(len(self.api.applied), 1)

    def test_a_chain_changed_after_adding_a_table_change_goes_stale(self):
        self.act("disable_table", name="filter").close()
        self.api.ruleset["nftables"].append({"chain": {"family": "inet", "table": "filter", "name": "added"}})
        text = self.review()
        self.assertIn("changed or no longer exists", text)
        self.assertIn("disabled", text)

    def test_results_are_read_back(self):
        self.act("create_table", name="fresh").close()
        self.act("create_chain", table="filter", name="made").close()
        self.act("rename_chain", table="filter", name="helper", new_name="better").close()
        self.apply().close()
        page = self.client.get("/rules")
        self.assertIn(b"Applied 3 changes", page.data)
        page.close()

    def test_a_structure_change_that_did_not_show_is_reported(self):
        original = self.api._apply
        self.api._apply = lambda _body: None
        self.act("create_table", name="fresh").close()
        self.apply().close()
        self.api._apply = original
        page = self.client.get("/rules")
        self.assertIn(b"couldn&#39;t be confirmed", page.data)
        page.close()

    def test_rendering_escapes_names(self):
        self.api.ruleset["nftables"].append({"chain": {"family": "inet", "table": "filter", "name": "<script>x"}})
        response = self.client.get("/rules")
        self.assertNotIn(b"<script>x", response.data)
        response.close()


class RuleTreeTests(ChangeFlowTestCase):
    def setUp(self):
        super().setUp()
        self.api.ruleset = {
            "nftables": [
                {"table": {"family": "ip", "name": "nat"}},
                {"table": {"family": "inet", "name": "filter"}},
                {"table": {"family": "inet", "name": "other"}},
                {"table": {"family": "bridge", "name": "edge"}},
                input_chain(),
                {"chain": {"family": "inet", "table": "filter", "name": "empty"}},
                {"chain": {"family": "inet", "table": "other", "name": "side"}},
                {"chain": {"family": "ip", "table": "nat", "name": "post", "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}},
                listed_rule(1, port_match(1), {"accept": None}),
                listed_rule(2, port_match(2), {"drop": None}, comment=None),
                {"rule": {"family": "ip", "table": "nat", "chain": "post", "handle": 5, "expr": [{"masquerade": None}]}},
            ]
        }

    def page(self, path="/rules"):
        response = self.client.get(path)
        self.addCleanup(response.close)
        return response.get_data(as_text=True).replace("&#39;", "'")

    def test_the_tree_lists_every_family_and_table(self):
        text = self.page()
        positions = [
            text.index(marker)
            for marker in (
                'data-nav="family:inet"',
                'data-nav="table:inet filter"',
                'data-nav="table:inet other"',
                'data-nav="family:ip"',
                'data-nav="table:ip nat"',
                'data-nav="family:bridge"',
                'data-nav="table:bridge edge"',
            )
        ]
        self.assertEqual(positions, sorted(positions))

    def test_the_first_table_is_selected_at_first(self):
        text = self.page()
        self.assertIn('data-chain="inet filter input"', text)
        self.assertNotIn('data-chain="ip nat post"', text)

    def test_selecting_a_table_opens_its_chains_in_the_tree_and_beside_it(self):
        text = self.page("/rules?family=ip&table=nat")
        self.assertIn('data-branch="table:ip nat" data-selected open', text)
        self.assertNotIn('data-branch="table:inet filter" data-selected', text)
        self.assertIn('data-chain="ip nat post"', text)
        self.assertNotIn('data-chain="inet filter input"', text)
        self.assertIn('aria-current="page"', text)

    def test_selecting_a_chain_shows_only_that_chain(self):
        text = self.page("/rules?family=inet&table=filter&chain=empty")
        self.assertIn('data-chain="inet filter empty"', text)
        self.assertNotIn('data-chain="inet filter input"', text)
        self.assertIn('data-nav="chain:inet filter input"', text)
        self.assertIn("This chain has no rules", text)

    def test_the_selected_chain_can_go_back_to_its_table(self):
        text = self.page("/rules?family=inet&table=filter&chain=empty")
        self.assertIn('class="detail-path"', text)
        self.assertIn('href="/rules?family=inet&amp;table=filter"', text)

    def test_an_unknown_selection_falls_back(self):
        self.assertIn('data-chain="inet filter input"', self.page("/rules?family=ip&table=gone"))
        text = self.page("/rules?family=inet&table=filter&chain=gone")
        self.assertIn('data-chain="inet filter input"', text)
        self.assertIn('data-chain="inet filter empty"', text)

    def test_the_selection_is_remembered(self):
        self.page("/rules?family=ip&table=nat")
        self.assertIn('data-chain="ip nat post"', self.page())

    def test_the_result_of_a_change_is_shown_after_applying(self):
        self.page("/rules?family=ip&table=nat")
        self.add_rule(destination_port="8443")
        self.apply().close()
        text = self.page()
        self.assertIn('data-chain="inet filter input"', text)
        self.assertIn("JUST APPLIED</span>", text)

    def test_a_table_with_no_chains_says_so(self):
        self.api.ruleset["nftables"].append({"table": {"family": "ip6", "name": "bare"}})
        text = self.page("/rules?family=ip6&table=bare")
        self.assertIn("This table has no chains", text)
        self.assertIn("Manage table", text)

    def test_with_no_tables_every_family_offers_creating_one(self):
        self.api.ruleset = {"nftables": []}
        text = self.page()
        for family in ("inet", "ip", "ip6"):
            self.assertIn(f'data-new-table="{family}"', text)

    def test_new_entries_come_last_in_their_lists(self):
        text = self.page()
        self.assertLess(text.index('data-nav="chain:inet filter empty"'), text.index('data-new-chain="inet filter"'))
        self.assertLess(text.index('data-new-chain="inet filter"'), text.index('data-nav="table:inet other"'))
        self.assertLess(text.index('data-new-chain="inet other"'), text.index('data-new-table="inet"'))
        self.assertLess(text.index('data-new-table="inet"'), text.index('data-nav="family:ip"'))

    def test_new_entries_create_in_the_right_place(self):
        self.post("/firewall/structure", structure_action="create_chain", family="inet", table="other", name="fresh").close()
        self.post("/firewall/structure", structure_action="create_table", family="ip", name="fresh").close()
        changes = self.pending()
        self.assertEqual((changes[0]["table"], changes[0]["name"]), ("other", "fresh"))
        self.assertEqual((changes[1]["family"], changes[1]["name"]), ("ip", "fresh"))

    def test_only_manageable_families_offer_new_entries(self):
        text = self.page()
        self.assertNotIn('data-new-table="bridge"', text)
        self.assertNotIn('data-new-chain="bridge edge"', text)

    def test_a_family_with_no_tables_can_get_its_first(self):
        self.assertIn('data-new-table="ip6"', self.page())

    def test_a_filter_hides_new_entries(self):
        text = self.page("/rules?q=dport")
        self.assertNotIn("data-new-table", text)
        self.assertNotIn("data-new-chain", text)

    def test_every_table_chains_are_in_the_tree_for_expanding(self):
        text = self.page()
        self.assertIn('data-nav="chain:ip nat post"', text)
        self.assertIn('data-tree-all="open"', text)
        self.assertIn('data-tree-all="close"', text)
        self.assertIn("file_tree.js", text)

    def test_summaries_describe_each_chain(self):
        text = self.page()
        self.assertIn("input hook, priority 0, policy accept", text)
        self.assertIn("regular chain", text)
        self.assertIn("This chain has no rules", text)

    def test_every_chain_offers_adding_a_rule_to_it(self):
        text = self.page()
        self.assertIn("/rules/new?chain=inet+filter+input", text)
        response = self.client.get("/rules/new?chain=inet+filter+input")
        self.assertIn(b'value="inet filter input" selected', response.data)
        response.close()

    def test_the_main_add_button_uses_the_selected_chain(self):
        self.assertIn('href="/rules/new?chain=inet+filter+empty"', self.page("/rules?family=inet&table=filter&chain=empty"))

    def test_a_chain_with_rules_can_be_dragged_in_place(self):
        text = self.page()
        self.assertIn("data-order-list", text)
        self.assertIn('value="handle:1" form="order-inet-filter-input"', text)
        self.assertIn("data-drag-handle", text)
        self.assertIn("rule_order.js", text)

    def test_dragging_in_place_submits_the_same_way_as_the_page(self):
        response = self.client.post(
            "/rules/organize",
            data={"csrf_token": self.csrf_token(), "chain": "inet filter input", "order": ["handle:2", "handle:1"]},
        )
        self.assertEqual(response.status_code, 302)
        response.close()
        self.assertEqual(self.pending()[0]["order"], [2, 1])

    def test_a_chain_with_one_rule_has_nothing_to_drag(self):
        self.assertNotIn('form="order-ip-nat-post"', self.page("/rules?family=ip&table=nat"))

    def test_a_filter_narrows_the_tree_and_leaves_out_dragging(self):
        text = self.page("/rules?q=dport")
        self.assertNotIn('data-nav="table:ip nat"', text)
        self.assertNotIn("data-order-list", text)
        self.assertIn("Reorder rules", text)
        self.assertIn('q=dport', text)

    def test_a_filter_with_no_matches_says_so(self):
        self.assertIn("No rules match this filter", self.page("/rules?q=nothing-matches"))

    def test_a_filter_keeps_true_positions(self):
        text = self.page("/rules?q=drop")
        self.assertNotIn("to port 1", text)
        self.assertIn("data-order-position>2<", text)

    def test_pending_rule_changes_send_dragging_to_the_organize_page(self):
        self.add_rule(destination_port="99")
        text = self.page()
        self.assertNotIn('form="order-inet-filter-input"', text)
        self.assertIn("/rules/organize?chain=inet+filter+input", text)

    def test_a_pending_order_does_not_stop_dragging_again(self):
        self.client.post("/rules/organize", data={"csrf_token": self.csrf_token(), "chain": "inet filter input", "order": ["handle:2", "handle:1"]}).close()
        self.assertIn('form="order-inet-filter-input"', self.page())

    def test_a_renamed_chain_offers_no_reordering(self):
        self.post("/firewall/structure", structure_action="rename_chain", family="inet", table="filter", name="input", new_name="x").close()
        text = self.page()
        self.assertNotIn('form="order-inet-filter-input"', text)
        self.assertNotIn("/rules/organize?chain=inet+filter+input", text)

    def test_other_families_offer_no_actions(self):
        text = self.page("/rules?family=bridge&table=edge")
        self.assertIn("Tables in the bridge family can't be managed here", text)
        self.assertNotIn("Manage table", text)

    def test_unmanaged_rules_are_labelled(self):
        self.assertEqual(self.page().count("NOT MANAGED</span>"), 1)

    def test_manage_controls_are_on_the_page(self):
        text = self.page()
        for label in ("Manage chain", "Manage table", "Rename", "Set policy to drop", "Delete chain", "New chain", "Turn enforcement off", "Delete table", "New table"):
            self.assertIn(label, text)
        self.assertIn("can't be changed later", text)

    def test_managing_a_table_is_only_offered_at_table_level(self):
        self.assertNotIn("Manage table", self.page("/rules?family=inet&table=filter&chain=input"))

    def test_a_rejected_form_shows_the_problem_beside_the_tree(self):
        response = self.post("/firewall/structure", structure_action="create_table", family="inet", name="bad name")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Names must use", response.data)
        self.assertIn(b'data-nav="table:inet filter"', response.data)
        response.close()

    def test_small_tables_start_open_and_large_ones_start_collapsed(self):
        self.assertIn('data-chain="inet filter input" open', self.page())
        self.api.ruleset["nftables"].extend(listed_rule(100 + index, port_match(1000 + index), {"accept": None}) for index in range(40))
        self.assertNotIn('data-chain="inet filter input" open', self.page())
        self.assertIn('data-chain="inet filter input" open', self.page("/rules?q=input"))
        self.assertIn('data-chain="inet filter input" open', self.page("/rules?family=inet&table=filter&chain=input"))

    def test_a_chain_with_just_applied_rules_opens(self):
        self.api.ruleset["nftables"].extend(listed_rule(100 + index, port_match(1000 + index), {"accept": None}) for index in range(40))
        self.add_rule(destination_port="8443")
        self.apply().close()
        self.assertIn('data-chain="inet filter input" open', self.page())

    def test_the_old_structure_page_is_gone(self):
        response = self.client.get("/firewall/structure")
        self.assertEqual(response.status_code, 405)
        response.close()
