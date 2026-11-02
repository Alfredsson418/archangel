"""Pending firewall changes: their effect, warnings, and API payloads.

Pure functions over nftables JSON listings and pending-change dictionaries;
nothing here depends on Flask. The backend remains authoritative: this only
helps a person review a change before it is applied.
"""
import copy
import json

from .connection_check import COULD_BLOCK, WILL_BLOCK, check_connection, rule_could_affect
from .firewall_rules import describe_rule, portable_rule, rules_from


MANAGED_RULE_COMMENT = "archangel-managed"
ADD_RULE = "add_rule"
DELETE_RULE = "delete_rule"
# Leave-one-out analysis repeats the connection check for each candidate. Past
# this many, every candidate is flagged rather than making the page slow.
_MAX_FLAG_CANDIDATES = 64
_INCOMING_HOOKS = ("input", "prerouting")
_TERMINAL_STATEMENTS = ("accept", "drop", "reject")


def chain_key(family, table, chain):
    """Build the key a pending change list uses for a chain.

    Returns:
        Text such as "inet filter input".
    """
    return f"{family} {table} {chain}"


def change_chain(change):
    """Name the chain a pending change touches.

    Returns:
        A chain key.
    """
    target = change["rule"] if change["type"] == ADD_RULE else change
    return chain_key(target["family"], target["table"], target["chain"])


def chains_from(ruleset):
    """List the chains that can hold structured rules.

    Returns:
        A list of chain dictionaries from the listing, in listing order.
    """
    if not isinstance(ruleset, dict) or not isinstance(ruleset.get("nftables"), list):
        return []
    return [
        entry["chain"]
        for entry in ruleset["nftables"]
        if isinstance(entry, dict)
        and isinstance(entry.get("chain"), dict)
        and entry["chain"].get("family") in ("ip", "ip6", "inet")
    ]


def find_rule(ruleset, family, table, chain, handle):
    """Find a listed rule by its chain and handle.

    Returns:
        The rule dictionary, or None if it doesn't exist.
    """
    for rule in rules_from(ruleset):
        if (
            rule.get("family") == family
            and rule.get("table") == table
            and rule.get("chain") == chain
            and rule.get("handle") == handle
        ):
            return rule
    return None


def rule_statements(rule):
    """Build the nftables statements a structured rule will have.

    Mirrors ruleExpressions in nft_rule.cpp, so that the connection check can
    follow rules that don't exist yet. The backend still builds the real ones.

    Returns:
        A list of nftables JSON statements.
    """
    statements = []
    meta = lambda key, right: {"match": {"op": "==", "left": {"meta": {"key": key}}, "right": right}}
    if rule.get("input_interface"):
        statements.append(meta("iifname", rule["input_interface"]))
    if rule.get("output_interface"):
        statements.append(meta("oifname", rule["output_interface"]))
    if rule.get("connection_states"):
        statements.append(
            {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": rule["connection_states"]}}
        )
    for field, direction in (("source_address", "saddr"), ("destination_address", "daddr")):
        value = rule.get(field)
        if value:
            statements.append(
                {
                    "match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "ip6" if ":" in value else "ip", "field": direction}},
                        "right": _listed_address(value),
                    }
                }
            )
    protocol = rule.get("protocol")
    if protocol:
        statements.append(meta("l4proto", "ipv6-icmp" if protocol == "icmpv6" else protocol))
    if rule.get("destination_port") is not None:
        end = rule.get("destination_port_end")
        statements.append(
            {
                "match": {
                    "op": "==",
                    "left": {"payload": {"protocol": protocol, "field": "dport"}},
                    "right": {"range": [rule["destination_port"], end]} if end else rule["destination_port"],
                }
            }
        )
    statements.append({rule["action"]: None})
    return statements


def _listed_address(value):
    """Convert a portable address to the shape nftables lists.

    Returns:
        A plain address, or a prefix dictionary for a subnet.
    """
    if "/" not in value:
        return value
    address, length = value.split("/")
    return {"prefix": {"addr": address, "len": int(length)}}


def apply_to_ruleset(ruleset, changes):
    """Work out the ruleset as it would be after pending changes.

    Returns:
        A new listing. Changes whose target no longer exists are skipped, and
        are reported separately by stale_changes.
    """
    result = copy.deepcopy(ruleset)
    entries = result["nftables"]
    for change in changes:
        if change["type"] == ADD_RULE:
            rule = change["rule"]
            entries.append(
                {
                    "rule": {
                        "family": rule["family"],
                        "table": rule["table"],
                        "chain": rule["chain"],
                        "handle": "new",
                        "comment": MANAGED_RULE_COMMENT,
                        "expr": rule_statements(rule),
                    }
                }
            )
        elif change["type"] == DELETE_RULE:
            entries[:] = [
                entry
                for entry in entries
                if not (
                    isinstance(entry, dict)
                    and isinstance(entry.get("rule"), dict)
                    and entry["rule"].get("family") == change["family"]
                    and entry["rule"].get("table") == change["table"]
                    and entry["rule"].get("chain") == change["chain"]
                    and entry["rule"].get("handle") == change["handle"]
                )
            ]
    return result


def _without_counters(rule):
    """Copy a rule's statements without counter values, for comparison.

    Returns:
        A list of statements.
    """
    statements = copy.deepcopy(rule.get("expr", []))
    for statement in statements:
        if isinstance(statement, dict) and isinstance(statement.get("counter"), dict):
            statement["counter"] = None
    return statements


def stale_changes(ruleset, changes):
    """Find changes whose target has changed since they were added.

    Returns:
        A set of change IDs.
    """
    chains = {chain_key(chain.get("family"), chain.get("table"), chain.get("name")) for chain in chains_from(ruleset)}
    stale = set()
    for change in changes:
        if change_chain(change) not in chains:
            stale.add(change["id"])
        elif change["type"] == DELETE_RULE:
            current = find_rule(ruleset, change["family"], change["table"], change["chain"], change["handle"])
            if current is None or _without_counters(current) != _without_counters(change["before"]):
                stale.add(change["id"])
    return stale


def describe_listed_rule(rule):
    """Describe a listed rule in plain language if possible.

    Returns:
        A description, or the rule's JSON statements if it can't be represented.
    """
    portable = portable_rule(rule)
    return describe_rule(portable) if portable else json.dumps(rule.get("expr", []))


def describe_change(change):
    """Describe a change's target and its state before and after.

    Returns:
        A dictionary with "kind", "target", "before", and "new".
    """
    if change["type"] == ADD_RULE:
        return {
            "kind": "New rule",
            "target": change_chain(change),
            "before": "(none)",
            "new": describe_rule(change["rule"]),
        }
    return {
        "kind": "Deleted rule",
        "target": f"{change_chain(change)}, handle {change['handle']}",
        "before": describe_listed_rule(change["before"]),
        "new": "(deleted)",
    }


def is_unmanaged(change):
    """Report whether a change affects a rule Archangel doesn't manage.

    Returns:
        True if it changes an existing rule without the managed marker.
    """
    return change["type"] != ADD_RULE and change["before"].get("comment") != MANAGED_RULE_COMMENT


def _hooks_by_chain(ruleset):
    """Map each chain to its hook.

    Returns:
        A dictionary of chain keys to hook names, or None for regular chains.
    """
    return {
        chain_key(chain.get("family"), chain.get("table"), chain.get("name")): chain.get("hook")
        for chain in chains_from(ruleset)
    }


def _rule_warnings(rule, hook, after, interfaces):
    """List warnings about a new rule.

    Returns:
        A list of warning messages.
    """
    warnings = []
    action = rule["action"]
    if hook == "input" and action in ("drop", "reject"):
        warnings.append("This could block other access to this server, such as SSH.")
    if rule.get("source_address", "").endswith("/0") or rule.get("destination_address", "").endswith("/0"):
        warnings.append("This subnet covers every address, which may be broader than intended.")
    elif hook == "input" and action == "accept" and not rule.get("source_address"):
        warnings.append("This accepts traffic from every address, which may be broader than intended.")
    if hook == "output" and rule.get("input_interface"):
        warnings.append("An input interface on an output hook means this rule can never match.")
    if hook == "input" and rule.get("output_interface"):
        warnings.append("An output interface on an input hook means this rule can never match.")
    if isinstance(interfaces, list):
        for field in ("input_interface", "output_interface"):
            name = rule.get(field)
            if name and name not in interfaces:
                warnings.append(
                    f"The interface {name} doesn't exist on this host. This may be a typing mistake, "
                    "and the rule won't match until it exists."
                )
    siblings = [
        listed
        for listed in rules_from(after)
        if chain_key(listed.get("family"), listed.get("table"), listed.get("chain"))
        == chain_key(rule["family"], rule["table"], rule["chain"])
    ]
    statements = rule_statements(rule)
    position = next((index for index, listed in enumerate(siblings) if listed.get("expr") == statements), None)
    if position is not None and any(_ends_chain(listed) for listed in siblings[:position]):
        warnings.append("An earlier rule always applies, so this rule may never take effect.")
    if sum(1 for listed in siblings if portable_rule(listed) == rule) > 1:
        warnings.append("An identical rule already exists, so this adds a duplicate.")
    return warnings


def _ends_chain(rule):
    """Report whether a rule is a verdict with no conditions.

    Returns:
        True if nothing after this rule in its chain can apply.
    """
    expression = rule.get("expr")
    return (
        isinstance(expression, list)
        and len(expression) == 1
        and isinstance(expression[0], dict)
        and next(iter(expression[0])) in _TERMINAL_STATEMENTS
    )


def change_warnings(ruleset, after, change, interfaces=None):
    """List warnings about one pending change.

    Returns:
        A list of warning messages. These never block a change.
    """
    hook = _hooks_by_chain(ruleset).get(change_chain(change))
    if change["type"] == ADD_RULE:
        return _rule_warnings(change["rule"], hook, after, interfaces)
    warnings = []
    if hook == "input" and portable_action(change["before"]) == "accept":
        warnings.append("This could remove access that's currently allowed.")
    if is_unmanaged(change):
        warnings.append("Archangel doesn't manage this rule. Another program or administrator may depend on it.")
    return warnings


def portable_action(rule):
    """Find a listed rule's verdict.

    Returns:
        The name of its last statement, such as "accept", or None.
    """
    expression = rule.get("expr")
    if isinstance(expression, list) and expression and isinstance(expression[-1], dict):
        return next(iter(expression[-1]))
    return None


def affects_incoming_traffic(ruleset, changes):
    """Report whether changes affect traffic arriving at this host.

    Regular chains count, because a base chain may jump to them.

    Returns:
        True if any change is on a chain that could see incoming traffic.
    """
    hooks = _hooks_by_chain(ruleset)
    return any(hooks.get(change_chain(change)) in (None,) + _INCOMING_HOOKS for change in changes)


def management_risk(ruleset, changes, connection):
    """Check the changes against the dashboard's connection to the API.

    Returns:
        A pair of (ConnectionCheck for the combined result, set of the change
        IDs responsible). The check only says something changed for the worse;
        the IDs say which changes to flag.
    """
    after = apply_to_ruleset(ruleset, changes)
    check = check_connection(ruleset, after, connection)
    if check.status not in (WILL_BLOCK, COULD_BLOCK):
        return check, set()

    candidates = [change for change in changes if _could_affect_connection(change, connection)]
    if len(candidates) > _MAX_FLAG_CANDIDATES:
        return check, {change["id"] for change in candidates}
    responsible = set()
    for candidate in candidates:
        others = [change for change in changes if change["id"] != candidate["id"]]
        without = check_connection(ruleset, apply_to_ruleset(ruleset, others), connection)
        if without.status != check.status:
            responsible.add(candidate["id"])
    # Two changes can each be enough to block alone, in which case removing
    # either one changes nothing, so flag them all rather than none.
    return check, responsible or {change["id"] for change in candidates}


def _could_affect_connection(change, connection):
    """Report whether a change's rule could apply to the connection at all.

    Returns:
        True unless the rule definitely never matches the connection.
    """
    statements = rule_statements(change["rule"]) if change["type"] == ADD_RULE else change["before"].get("expr")
    return rule_could_affect(statements, connection)


def api_payload(pending):
    """Build the API request for a pending change list.

    Returns:
        A JSON-compatible dictionary with the expected revisions and changes.
    """
    changes = []
    for change in pending["changes"]:
        if change["type"] == ADD_RULE:
            changes.append({"type": ADD_RULE, "rule": change["rule"]})
        else:
            changes.append(
                {
                    "type": DELETE_RULE,
                    "family": change["family"],
                    "table": change["table"],
                    "chain": change["chain"],
                    "handle": change["handle"],
                }
            )
    touched = {change_chain(change) for change in pending["changes"]}
    expected = []
    for key in sorted(touched):
        family, table, chain = key.split(" ")
        expected.append({"family": family, "table": table, "chain": chain, "revision": pending["revisions"].get(key, "")})
    return {"expected_revisions": expected, "changes": changes}


def verify_applied(ruleset, changes):
    """Confirm that applied changes appear in the ruleset read back afterward.

    Returns:
        True if every change is visible in the ruleset.
    """
    listed = [portable_rule(rule) for rule in rules_from(ruleset)]
    for change in changes:
        if change["type"] == ADD_RULE:
            if change["rule"] not in listed:
                return False
        elif find_rule(ruleset, change["family"], change["table"], change["chain"], change["handle"]) is not None:
            return False
    return True
