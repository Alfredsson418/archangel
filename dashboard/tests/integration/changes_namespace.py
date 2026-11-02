"""Exercise the real dashboard, API, and nftables together in a namespace.

Mocks can't prove the two services and nftables agree, so this starts the real
backend, signs in through the real dashboard code, and changes a real ruleset.
It never touches the host's firewall, but only run it through the isolating
command in docs/test.md:

    unshare -rn dashboard/.venv/bin/python dashboard/tests/integration/changes_namespace.py

Requires a debug build at bin/archangel. The script refuses to run unless it is
root inside a new user namespace.
"""
import json
import os
import pty
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen

REPOSITORY = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPOSITORY / "dashboard"))

BINARY = REPOSITORY / "bin" / "archangel"
PORT = 18080
USERNAME = "admin"
PASSWORD = "correct-horse-battery-staple-9"
BASE = "inet filter "


class Failures(list):
    def check(self, condition, message):
        print(f"{'ok  ' if condition else 'FAIL'} {message}")
        if not condition:
            self.append(message)


def nft(*commands):
    for command in commands:
        subprocess.run(["nft"] + command.split(" "), check=True, capture_output=True)


def listed():
    output = subprocess.run(["nft", "-a", "list", "ruleset"], check=True, capture_output=True, text=True).stdout
    return output


def require_isolation():
    uid_map = Path("/proc/self/uid_map").read_text().split()
    if os.geteuid() != 0 or uid_map[:3] == ["0", "0", "4294967295"]:
        sys.exit("Run this through unshare -rn, as described in docs/test.md.")


def bootstrap(config):
    """Create the first administrator, answering the terminal password prompts."""
    pid, descriptor = pty.fork()
    if pid == 0:
        os.execv(str(BINARY), [str(BINARY), "--config", str(config), "user", "bootstrap-admin", "--username", USERNAME])
    output = b""
    answered = 0
    while True:
        try:
            data = os.read(descriptor, 4096)
        except OSError:
            break
        if not data:
            break
        output += data
        if output.lower().count(b"password") > answered:
            os.write(descriptor, f"{PASSWORD}\n".encode())
            answered += 1
    if os.waitpid(pid, 0)[1] != 0:
        sys.exit(f"Bootstrap failed: {output!r}")


def start_backend(directory):
    data, logs = directory / "data", directory / "logs"
    data.mkdir(mode=0o700)
    logs.mkdir(mode=0o700)
    config = directory / "config.json"
    subprocess.run([str(BINARY), "config", "generate", "--output", str(config)], check=True, capture_output=True)
    settings = json.loads(config.read_text())
    settings["logging"]["path"] = str(logs / "backend.jsonl")
    settings["auth"]["database_path"] = str(data / "auth.db")
    settings["server"].update(port=PORT, bind_address="127.0.0.1")
    # This script makes far more requests than a person would.
    settings["rate_limits"]["firewall_mutations_per_minute"] = 10000
    settings["rate_limits"]["api_requests_per_minute"] = 100000
    config.write_text(json.dumps(settings))
    config.chmod(0o600)
    bootstrap(config)
    process = subprocess.Popen([str(BINARY), "--config", str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            with urlopen(f"http://127.0.0.1:{PORT}/status/health", timeout=1):
                return process
        except OSError:
            time.sleep(0.1)
    process.terminate()
    sys.exit("The backend did not start.")


def create_dashboard(directory):
    os.environ.update(
        ARCHANGEL_DEV_MODE="true",
        ARCHANGEL_API_URL=f"http://127.0.0.1:{PORT}",
        ARCHANGEL_SESSION_DATABASE=str(directory / "sessions.db"),
        ARCHANGEL_WEB_LOG_PATH=str(directory / "dashboard.jsonl"),
    )
    from server import app

    app.config["SESSION_DATABASE"] = directory / "sessions.db"
    return app.test_client()


def csrf(client):
    client.get("/login").close()
    with client.session_transaction() as session:
        return session["_csrf_token"]


class Dashboard:
    def __init__(self, client):
        self.client = client

    def token(self):
        with self.client.session_transaction() as session:
            return session["_csrf_token"]

    def post(self, path, **data):
        response = self.client.post(path, data={"csrf_token": self.token(), **data})
        response.close()
        return response

    def page(self, path):
        response = self.client.get(path)
        text = response.get_data(as_text=True)
        response.close()
        return text

    def add(self, **fields):
        return self.post("/rules/new", form_action="add", **fields)

    def apply(self, **fields):
        return self.post("/changes/apply", confirm="yes", **fields)


def main():
    require_isolation()
    if not BINARY.exists():
        sys.exit("Build the backend first with make debug.")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    directory = Path(tempfile.mkdtemp(prefix="archangel-integration-"))
    directory.chmod(0o700)
    failures = Failures()
    backend = start_backend(directory)
    try:
        client = create_dashboard(directory)
        token = csrf(client)
        client.post("/login", data={"csrf_token": token, "username": USERNAME, "password": PASSWORD}).close()
        # Signing in rotates the session, and rendering a page issues a new token.
        client.get("/rules").close()
        dashboard = Dashboard(client)
        # Rules in a chain with no hook can't affect the connection under test.
        nft("add table inet filter", "add chain inet filter work")
        chain = BASE + "work"

        print("-- collecting changes doesn't touch the firewall")
        dashboard.add(chain=chain, protocol="tcp", destination_port="443", source_address="192.0.2.0/24", action="accept")
        dashboard.add(chain=chain, connection_states=["established", "related"], action="accept")
        dashboard.add(chain=chain, protocol="tcp", destination_port="8000-8100", action="reject")
        dashboard.add(chain=chain, input_interface="lo", protocol="icmp", action="accept")
        failures.check("dport 443" not in listed(), "pending changes are not applied")
        review = dashboard.page("/changes")
        failures.check("4 changes: 0 MANAGEMENT RISK, 4 other" in review, "the review page lists every change")
        failures.check("to ports 8000-8100" in review, "the review page describes rules in plain language")

        print("-- applying everything in one transaction")
        result = dashboard.apply()
        failures.check(result.status_code == 302, "applying succeeds")
        rules = listed()
        for expected in ("ip saddr 192.0.2.0/24 tcp dport 443 accept", "ct state established,related accept", "tcp dport 8000-8100 reject", 'iifname "lo" meta l4proto icmp accept'):
            failures.check(expected in rules, f"nftables has: {expected}")
        failures.check("Applied 4 changes" in dashboard.page("/rules"), "the rules page confirms the result")

        print("-- a change made outside Archangel is detected")
        dashboard.add(chain=chain, protocol="udp", destination_port="53", action="drop")
        nft("add rule inet filter work tcp dport 7777 drop")
        failures.check("This chain has changed" in dashboard.page("/changes"), "the review page reports the conflict")
        result = dashboard.apply()
        failures.check(result.status_code == 409, "applying is refused")
        failures.check("udp dport 53" not in listed(), "nothing was applied")
        dashboard.post("/changes/refresh")
        result = dashboard.apply()
        failures.check(result.status_code == 302 and "udp dport 53" in listed(), "it applies after reviewing the current firewall")

        print("-- a failure partway through applies nothing")
        dashboard.add(chain=chain, protocol="tcp", destination_port="1001", action="accept")
        dashboard.add(chain=chain, protocol="tcp", destination_port="1002", action="accept")
        dashboard.add(chain=BASE + "work", protocol="tcp", destination_port="1003", action="accept")
        with client.application.app_context():
            from webapp import pending_changes

            with client.session_transaction() as session:
                actor = session["actor_id"]
            pending = pending_changes.load(actor)
            # A chain that vanishes between review and apply makes the last change fail.
            pending["changes"][-1]["rule"]["chain"] = "missing"
            pending["revisions"]["inet filter missing"] = "x"
            pending_changes.save(actor, pending)
        failures.check("changed or no longer exists" in dashboard.page("/changes"), "the review page reports the missing chain")
        result = dashboard.apply()
        failures.check(result.status_code == 409, "applying is refused")
        rules = listed()
        failures.check("dport 1001" not in rules and "dport 1002" not in rules, "no change in the list was applied")
        dashboard.post("/changes/discard")

        print("-- the API's own transaction is all or nothing, and names the change")
        from webapp.api_client import ApiClient, UrllibTransport, create_ssl_context

        api = ApiClient(f"http://127.0.0.1:{PORT}", UrllibTransport(create_ssl_context()))
        with client.session_transaction() as session:
            access_token = session["access_token"]

        def call(path, payload):
            response = api.request(path, method="POST", body=json.dumps(payload).encode(), bearer_token=access_token)
            return response.status, json.loads(response.body)

        revisions = api.fetch_json("/api/v1/firewall/revisions", bearer_token=access_token)["chains"]
        expected = [entry for entry in revisions if entry["chain"] == "work"]
        rule = {"family": "inet", "table": "filter", "chain": "work", "protocol": "tcp", "action": "accept"}
        batch = {
            "expected_revisions": expected,
            "changes": [
                {"type": "add_rule", "rule": {**rule, "destination_port": 2001}},
                {"type": "add_rule", "rule": {**rule, "destination_port": 2002}},
                {"type": "delete_rule", "family": "inet", "table": "filter", "chain": "work", "handle": 999999},
            ],
        }
        status, body = call("/api/v1/firewall/changes", batch)
        failures.check(status == 422 and body.get("change_index") == 2, f"the rejected change is named: {status} {body.get('change_index')}")
        failures.check("dport 2001" not in listed(), "earlier changes in the rejected list were undone")

        status, body = call("/api/v1/firewall/changes/check", {**batch, "changes": batch["changes"][:2]})
        failures.check(status == 200 and "dport 2001" not in listed(), "a check passes without applying anything")
        status, body = call("/api/v1/firewall/changes/check", batch)
        failures.check(status == 422 and body.get("change_index") == 2, "a check finds the same rejected change")
        status, body = call("/api/v1/firewall/changes", {**batch, "expected_revisions": [{**expected[0], "revision": "old"}]})
        failures.check(status == 409, "an outdated revision is refused")
        status, body = call("/api/v1/firewall/changes", {**batch, "expected_revisions": []})
        failures.check(status == 400, "an unreviewed chain is refused")

        print("-- nftables itself rejects a change, and bisection names it")
        nft("add chain inet filter late { type filter hook postrouting priority 0 ; }")
        revisions = api.fetch_json("/api/v1/firewall/revisions", bearer_token=access_token)["chains"]
        late_rule = {"family": "inet", "table": "filter", "chain": "late", "protocol": "tcp"}
        kernel_batch = {
            "expected_revisions": [entry for entry in revisions if entry["chain"] == "late"],
            "changes": [
                {"type": "add_rule", "rule": {**late_rule, "destination_port": 3001, "action": "accept"}},
                {"type": "add_rule", "rule": {**late_rule, "destination_port": 3002, "action": "accept"}},
                {"type": "add_rule", "rule": {**late_rule, "destination_port": 3003, "action": "accept"}},
                # The kernel doesn't allow reject on the postrouting hook.
                {"type": "add_rule", "rule": {**late_rule, "destination_port": 3004, "action": "reject"}},
                {"type": "add_rule", "rule": {**late_rule, "destination_port": 3005, "action": "accept"}},
            ],
        }
        status, body = call("/api/v1/firewall/changes/check", kernel_batch)
        failures.check(status == 422 and body.get("change_index") == 3, f"a check names the change nftables rejects: {status} {body.get('change_index')}")
        status, body = call("/api/v1/firewall/changes", kernel_batch)
        failures.check(status == 422 and body.get("change_index") == 3, f"applying names it too: {status} {body.get('change_index')}")
        failures.check("dport 3001" not in listed(), "the changes before it were undone")
        status, body = call("/api/v1/firewall/changes", {**kernel_batch, "changes": kernel_batch["changes"][:3]})
        failures.check(status == 200 and "dport 3003" in listed(), "dry runs left libnftables able to apply for real")

        print("-- 1,000 changes apply together")
        revisions = api.fetch_json("/api/v1/firewall/revisions", bearer_token=access_token)["chains"]
        expected = [entry for entry in revisions if entry["chain"] == "work"]
        many = [{"type": "add_rule", "rule": {**rule, "destination_port": 10000 + index}} for index in range(1000)]
        started = time.time()
        status, body = call("/api/v1/firewall/changes", {"expected_revisions": expected, "changes": many})
        failures.check(status == 200 and body.get("changes") == 1000, f"1,000 changes applied in {time.time() - started:.2f}s")
        failures.check(listed().count("tcp dport 1") >= 1000, "all 1,000 are in nftables")

        print("-- editing keeps the position, handle, and comment")
        nft("add chain inet filter editing", "add rule inet filter editing tcp dport 1 drop", 'add rule inet filter editing tcp dport 2 drop', "add rule inet filter editing tcp dport 3 drop")
        def editing_rules():
            listing = api.fetch_json("/api/v1/rules", bearer_token=access_token)
            return [entry["rule"] for entry in listing["nftables"] if "rule" in entry and entry["rule"]["chain"] == "editing"]

        before = editing_rules()
        result = dashboard.post("/rules/edit", form_action="add", family="inet", table="filter", chain="editing", handle=str(before[1]["handle"]), protocol="tcp", destination_port="2222", action="accept")
        failures.check(result.status_code == 302 and "dport 2222" not in listed(), "an edit is collected without changing the firewall")
        review = dashboard.page("/changes")
        failures.check("Edited rule" in review and "Drop TCP traffic to port 2" in review and "Accept TCP traffic to port 2222" in review, "the review shows before and new")
        result = dashboard.apply(confirm_risk="yes")
        after = editing_rules()
        failures.check(result.status_code == 302, "the edit applies")
        failures.check([rule["handle"] for rule in after] == [rule["handle"] for rule in before], "every handle and position is unchanged")
        failures.check(json.dumps(after[1]["expr"]) != json.dumps(before[1]["expr"]) and "accept" in json.dumps(after[1]["expr"]), "the rule has its new match and action")
        failures.check("comment" not in after[1], "an unmanaged rule stays unmanaged")
        failures.check(after[0]["expr"] == before[0]["expr"] and after[2]["expr"] == before[2]["expr"], "its neighbors are untouched")

        dashboard.add(chain=BASE + "editing", protocol="tcp", destination_port="4000", action="accept")
        dashboard.apply()
        managed = next(rule for rule in editing_rules() if "4000" in json.dumps(rule["expr"]))
        dashboard.post("/rules/edit", form_action="add", family="inet", table="filter", chain="editing", handle=str(managed["handle"]), protocol="tcp", destination_port="4001", action="accept")
        dashboard.apply()
        edited = next(rule for rule in editing_rules() if rule["handle"] == managed["handle"])
        failures.check(edited.get("comment") == "archangel-managed" and "4001" in json.dumps(edited["expr"]), "a managed rule stays managed")

        print("-- deleting through the dashboard")
        rules = api.fetch_json("/api/v1/rules", bearer_token=access_token)
        target = next(entry["rule"] for entry in rules["nftables"] if "rule" in entry and "7777" in json.dumps(entry["rule"]["expr"]))
        dashboard.post("/rules/delete", family="inet", table="filter", chain="work", handle=str(target["handle"]))
        review = dashboard.page("/changes")
        failures.check("doesn&#39;t manage this rule" in review, "an unmanaged rule is called out")
        result = dashboard.apply()
        failures.check(result.status_code == 400 and "dport 7777" in listed(), "it needs the second confirmation")
        result = dashboard.apply(confirm_risk="yes")
        failures.check(result.status_code == 302 and "dport 7777" not in listed(), "it deletes after the second confirmation")

        print("-- a mixed list applies together: add, edit, and delete")
        targets = editing_rules()
        first, second = targets[0], targets[1]
        dashboard.add(chain=BASE + "editing", protocol="udp", destination_port="5000", action="accept")
        dashboard.post("/rules/edit", form_action="add", family="inet", table="filter", chain="editing", handle=str(first["handle"]), protocol="tcp", destination_port="5001", action="accept")
        dashboard.post("/rules/delete", family="inet", table="filter", chain="editing", handle=str(second["handle"]))
        failures.check("3 changes" in dashboard.page("/changes"), "all three are reviewed together")
        result = dashboard.apply(confirm_risk="yes")
        rules = listed()
        failures.check(result.status_code == 302 and "udp dport 5000" in rules and "tcp dport 5001" in rules, "the addition and edit both applied")
        failures.check(not any(rule["handle"] == second["handle"] for rule in editing_rules()), "the deletion applied")

        print("-- importing a bundle applies all or none")
        bundle = {"format": "archangel-firewall-rules", "version": 2, "rules": [{"family": "inet", "table": "filter", "chain": "editing", "protocol": "tcp", "destination_port": 6000 + index, "action": "accept"} for index in range(50)]}
        result = dashboard.post("/rules/import", action="add", bundle=json.dumps(bundle))
        failures.check(result.status_code == 302 and "dport 6000" not in listed(), "an import is collected without changing the firewall")
        result = dashboard.apply()
        failures.check(result.status_code == 302 and all(f"dport {6000 + index}" in listed() for index in (0, 25, 49)), "all 50 imported rules applied")

        print("-- exporting and reimporting what the dashboard reads")
        exported = client.get("/rules/export")
        exported_bundle = json.loads(exported.get_data(as_text=True))
        exported.close()
        failures.check(exported_bundle["version"] == 2 and any(rule.get("connection_states") == ["established", "related"] for rule in exported_bundle["rules"]), "exports include the new rule fields")
        failures.check(any(rule.get("action") == "reject" for rule in exported_bundle["rules"]), "exports include reject rules")

        print("-- ordering rules, including rules the form can't represent")
        nft(
            "add chain inet filter ordered",
            "add rule inet filter ordered tcp dport 7001 accept",
            "add rule inet filter ordered tcp dport { 7002, 7003 } counter log prefix ordered accept",
            "add rule inet filter ordered ct state established accept",
        )
        def ordered_rules():
            listing = api.fetch_json("/api/v1/rules", bearer_token=access_token)
            return [entry["rule"] for entry in listing["nftables"] if "rule" in entry and entry["rule"]["chain"] == "ordered"]

        first, second, third = ordered_rules()
        order = lambda *values: client.post("/rules/organize", data={"csrf_token": dashboard.token(), "chain": BASE + "ordered", "order": list(values)})
        dashboard.add(chain=BASE + "ordered", protocol="tcp", destination_port="7004", action="drop")
        with client.session_transaction() as session:
            actor = session["actor_id"]
        with client.application.app_context():
            from webapp import pending_changes

            new_id = pending_changes.load(actor)["changes"][0]["id"]
        order(f"new:{new_id}", f"handle:{third['handle']}", f"handle:{first['handle']}", f"handle:{second['handle']}").close()
        review = dashboard.page("/changes")
        failures.check("Rule order" in review and "position" in review, "the review shows the new positions")
        failures.check("dport 7004" not in listed(), "nothing changes before applying")
        result = dashboard.apply(confirm_risk="yes")
        failures.check(result.status_code == 302, f"the new order applies: {result.status_code}")
        after = ordered_rules()
        ports = lambda rule: json.dumps(rule["expr"])
        failures.check(len(after) == 4, "no rule was lost or duplicated")
        failures.check("7004" in ports(after[0]) and "established" in ports(after[1]) and "7001" in ports(after[2]) and "7002" in ports(after[3]), "nftables has the new order, with the new rule first")
        failures.check(after[0].get("comment") == "archangel-managed", "the new rule is managed")
        failures.check("counter" in ports(after[3]) and "ordered" in ports(after[3]) and "7003" in ports(after[3]), "a rule the form can't represent keeps its set, counter, and log")
        failures.check("Applied 2 changes" in dashboard.page("/rules"), "the result is confirmed by reading it back")

        print("-- the connection warning, through the real API")
        nft("add chain inet filter input { type filter hook input priority 0 ; }")
        dashboard.add(chain=BASE + "input", protocol="tcp", destination_port=str(PORT), action="drop")
        review = dashboard.page("/changes")
        failures.check("1 MANAGEMENT RISK" in review, "a rule blocking the API is flagged")
        failures.check("will block the dashboard" in review, "the page warns that it will block")
        result = dashboard.apply()
        failures.check(result.status_code == 400 and f"dport {PORT} drop" not in listed(), "it needs the second confirmation")
        dashboard.post("/changes/discard")

        print(f"{len(failures)} failures")
        return 1 if failures else 0
    finally:
        backend.terminate()
        backend.wait()
        shutil.rmtree(directory, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
