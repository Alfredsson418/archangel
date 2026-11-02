"""Pending firewall changes: their effect, warnings, and API payloads.

Pure functions over nftables JSON listings and pending-change dictionaries;
nothing here depends on Flask. The backend remains authoritative: this only
helps a person review a change before it is applied.
"""
import copy
import json

from .connection_check import COULD_BLOCK, WILL_BLOCK, check_connection, rule_could_affect
from .firewall_rules import RULE_FAMILIES, describe_rule, portable_rule, rules_from


MANAGED_RULE_COMMENT = "archangel-managed"
ADD_RULE = "add_rule"
DELETE_RULE = "delete_rule"
REPLACE_RULE = "replace_rule"
SET_RULE_ORDER = "set_rule_order"
CREATE_CHAIN = "create_chain"
RENAME_CHAIN = "rename_chain"
SET_CHAIN_POLICY = "set_chain_policy"
DELETE_CHAIN = "delete_chain"
CREATE_TABLE = "create_table"
DELETE_TABLE = "delete_table"
SET_TABLE_ENABLED = "set_table_enabled"
_RULE_TYPES = (ADD_RULE, DELETE_RULE, REPLACE_RULE, SET_RULE_ORDER)
_CHAIN_TYPES = (CREATE_CHAIN, RENAME_CHAIN, SET_CHAIN_POLICY, DELETE_CHAIN)
_TABLE_TYPES = (CREATE_TABLE, DELETE_TABLE, SET_TABLE_ENABLED)
# Leave-one-out analysis repeats the connection check for each candidate. Past
# this many, every candidate is flagged rather than making the page slow.
_MAX_FLAG_CANDIDATES = 64
_INCOMING_HOOKS = ("input", "prerouting")
_MAX_HIGHLIGHTED_RULES = 200
# With more rules than this, chains start collapsed so that the tree stays usable.
_MAX_RULES_OPEN_BY_DEFAULT = 30
_FAMILY_ORDER = ("inet", "ip", "ip6")
# What the API accepts for chain and table changes; the rest is for the review.
_STRUCTURE_FIELDS = ("type", "family", "table", "name", "new_name", "base", "policy", "enabled")
_TERMINAL_STATEMENTS = ("accept", "drop", "reject")


def chain_key(family, table, chain):
    """Build the key a pending change list uses for a chain.

    Returns:
        Text such as "inet filter input".
    """
    return f"{family} {table} {chain}"


def change_chain(change):
    """Name the chain a pending change is about.

    Returns:
        A chain key, or None for a change to a whole table.
    """
    if change["type"] in _TABLE_TYPES:
        return None
    if change["type"] in _CHAIN_TYPES:
        return chain_key(change["family"], change["table"], change["name"])
    target = change["rule"] if change["type"] in (ADD_RULE, REPLACE_RULE) else change
    return chain_key(target["family"], target["table"], target["chain"])


def chains_touched(changes):
    """Find the existing chains each pending change depends on.

    Chains the list itself creates are left out, since they have no revision.
    A change to a table records its chains when it's added.

    Returns:
        A dictionary of change IDs to sets of chain keys.
    """
    created = set()
    touched = {}
    for change in changes:
        if change["type"] == CREATE_CHAIN:
            created.add(change_chain(change))
            keys = set()
        elif change["type"] in (DELETE_TABLE, SET_TABLE_ENABLED):
            keys = set(change["chains"])
        elif change["type"] == CREATE_TABLE:
            keys = set()
        else:
            keys = {change_chain(change)}
            if change["type"] == RENAME_CHAIN:
                created.add(chain_key(change["family"], change["table"], change["new_name"]))
        touched[change["id"]] = keys - created
    return touched


def blocked_chains(changes):
    """Find chains whose rules can't change in the same list.

    nftables applies a rename at the end of a transaction, so neither name can
    be used. A deleted chain has nothing left to change.

    Returns:
        A set of chain keys.
    """
    blocked = set()
    for change in changes:
        if change["type"] == RENAME_CHAIN:
            blocked.add(change_chain(change))
            blocked.add(chain_key(change["family"], change["table"], change["new_name"]))
        elif change["type"] == DELETE_CHAIN:
            blocked.add(change_chain(change))
        elif change["type"] == DELETE_TABLE:
            blocked.update(change["chains"])
    return blocked


def rule_tree(ruleset, query="", highlighted=(), changes=()):
    """Group a ruleset by family, table, and chain, with rules in true order.

    Args:
        ruleset: The current listing.
        query: Filter text. A rule stays if it matches, and a chain or table
            with nothing left is left out.
        highlighted: Structured rules to mark as just applied.
        changes: The user's pending changes, which limit dragging.

    Returns:
        A dictionary with "families", a nested list, and "total" and "matching"
        rule counts.
    """
    tables = {}
    families = {}

    def table_entry(family, name):
        key = (family, name)
        if key not in tables:
            tables[key] = {
                "family": family,
                "name": name,
                "dormant": False,
                "manageable": family in RULE_FAMILIES,
                "chains": {},
                "contents": table_contents(ruleset, family, name),
            }
            families.setdefault(family, []).append(tables[key])
        return tables[key]

    def chain_entry(family, table, name, definition=None):
        chains = table_entry(family, table)["chains"]
        if name not in chains:
            chains[name] = {
                "name": name,
                "key": chain_key(family, table, name),
                "family": family,
                "table": table,
                "hook": None,
                "priority": None,
                "policy": None,
                "rules": [],
                "total": 0,
                "just_applied": False,
            }
        if definition:
            chains[name].update(hook=definition.get("hook"), priority=definition.get("prio"), policy=definition.get("policy"))
        return chains[name]

    for table in tables_from(ruleset):
        table_entry(table.get("family"), table.get("name"))["dormant"] = is_dormant(table)
    for chain in chains_from(ruleset):
        chain_entry(chain.get("family"), chain.get("table"), chain.get("name"), chain)

    needle = query.casefold()
    all_rules = rules_from(ruleset)
    matching = 0
    for rule in all_rules:
        chain = chain_entry(rule.get("family"), rule.get("table"), rule.get("chain"))
        chain["total"] += 1
        if needle and not _rule_matches(rule, needle):
            continue
        matching += 1
        portable = portable_rule(rule)
        just_applied = portable is not None and portable in highlighted
        chain["just_applied"] = chain["just_applied"] or just_applied
        chain["rules"].append(
            {
                "rule": rule,
                "handle": rule.get("handle"),
                "text": describe_listed_rule(rule),
                "position": chain["total"],
                "representable": portable is not None,
                "just_applied": just_applied,
                "unmanaged": rule.get("comment") != MANAGED_RULE_COMMENT,
            }
        )

    # Dragging submits the chain's rules as listed, which leaves out pending
    # rule changes, so those chains use the organize page instead.
    pending = {change_chain(change) for change in changes if change["type"] in (ADD_RULE, DELETE_RULE, REPLACE_RULE)}
    blocked = blocked_chains(changes)
    open_by_default = bool(needle) or len(all_rules) <= _MAX_RULES_OPEN_BY_DEFAULT
    for table in tables.values():
        chains = list(table["chains"].values())
        for chain in chains:
            chain["open"] = open_by_default or chain["just_applied"]
            chain["blocked"] = chain["key"] in blocked
            chain["reorderable"] = (
                table["manageable"]
                and not needle
                and chain["total"] > 1
                and chain["key"] not in pending
                and not chain["blocked"]
                and all(isinstance(row["handle"], int) for row in chain["rules"])
            )
        table["chains"] = [chain for chain in chains if not needle or chain["rules"]]
    result = []
    for family in sorted(families, key=lambda name: (_FAMILY_ORDER.index(name) if name in _FAMILY_ORDER else len(_FAMILY_ORDER), str(name))):
        kept = [table for table in families[family] if not needle or table["chains"]]
        if kept:
            result.append({"name": family, "tables": sorted(kept, key=lambda table: str(table["name"]))})
    return {"families": result, "total": len(all_rules), "matching": matching}


def _rule_matches(rule, needle):
    """Compare a rule against filter text.

    Returns:
        True if its location, handle, or statements contain the text.
    """
    location = " ".join(str(rule.get(field, "")) for field in ("family", "table", "chain", "handle"))
    return needle in location.casefold() or needle in json.dumps(rule.get("expr", []), sort_keys=True).casefold()


def tables_from(ruleset):
    """List the tables in a listing.

    Returns:
        A list of table dictionaries, in listing order.
    """
    if not isinstance(ruleset, dict) or not isinstance(ruleset.get("nftables"), list):
        return []
    return [entry["table"] for entry in ruleset["nftables"] if isinstance(entry, dict) and isinstance(entry.get("table"), dict)]


def is_dormant(table):
    """Report whether a table's enforcement is off.

    Returns:
        True if the table has the dormant flag.
    """
    flags = table.get("flags", [])
    return "dormant" in (flags if isinstance(flags, list) else [flags])


def dormant_tables(ruleset):
    """List the tables whose rules aren't being enforced.

    Returns:
        A list of text such as "inet filter".
    """
    return [f"{table.get('family')} {table.get('name')}" for table in tables_from(ruleset) if is_dormant(table)]


def table_contents(ruleset, family, table):
    """Count what a table holds.

    Returns:
        A dictionary with "chains", "rules", "unmanaged", and "objects", the
        number of named sets, maps, and other objects.
    """
    chains = [chain for chain in chains_from(ruleset) if chain.get("family") == family and chain.get("table") == table]
    rules = [rule for rule in rules_from(ruleset) if rule.get("family") == family and rule.get("table") == table]
    objects = 0
    for entry in ruleset.get("nftables", []) if isinstance(ruleset, dict) else []:
        if isinstance(entry, dict) and len(entry) == 1:
            kind, value = next(iter(entry.items()))
            if kind not in ("table", "chain", "rule", "metainfo") and isinstance(value, dict) and value.get("family") == family and value.get("table") == table:
                objects += 1
    return {
        "chains": len(chains),
        "rules": len(rules),
        "unmanaged": sum(1 for rule in rules if rule.get("comment") != MANAGED_RULE_COMMENT),
        "objects": objects,
    }


def jumps_to_chain(ruleset, family, table, chain):
    """Find rules that jump or go to a chain.

    Returns:
        A list of rule dictionaries.
    """
    found = []
    for rule in rules_from(ruleset):
        if rule.get("family") != family or rule.get("table") != table or rule.get("chain") == chain:
            continue
        for statement in rule.get("expr", []) if isinstance(rule.get("expr"), list) else []:
            if isinstance(statement, dict) and any(
                isinstance(statement.get(kind), dict) and statement[kind].get("target") == chain for kind in ("jump", "goto")
            ):
                found.append(rule)
                break
    return found


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


def pending_on_rule(changes, family, table, chain, handle):
    """Report whether a pending change already targets an existing rule.

    Returns:
        True if a pending edit or deletion names this rule.
    """
    return any(
        change["type"] in (DELETE_RULE, REPLACE_RULE)
        and change_chain(change) == chain_key(family, table, chain)
        and change["handle"] == handle
        for change in changes
    )


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
                        "pending_id": change.get("id"),
                    }
                }
            )
        elif change["type"] == SET_RULE_ORDER:
            _reorder_entries(entries, change)
        elif change["type"] in _CHAIN_TYPES or change["type"] in _TABLE_TYPES:
            _apply_structure_change(entries, change)
        elif change["type"] == REPLACE_RULE:
            rule = change["rule"]
            target = find_rule(result, rule["family"], rule["table"], rule["chain"], change["handle"])
            if target is not None:
                target["expr"] = rule_statements(rule)
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


def _apply_structure_change(entries, change):
    """Apply a chain or table change to listing entries, in place.

    Returns:
        None.
    """
    def is_in_table(value):
        return value.get("family") == change["family"] and value.get("table") == change.get("table", change["name"])

    def is_in_chain(value, field):
        return is_in_table(value) and value.get(field) == change["name"]

    kind = change["type"]
    if kind == CREATE_TABLE:
        entries.append({"table": {"family": change["family"], "name": change["name"]}})
    elif kind == CREATE_CHAIN:
        chain = {"family": change["family"], "table": change["table"], "name": change["name"]}
        if change.get("base"):
            base = change["base"]
            chain.update(type=base["type"], hook=base["hook"], prio=base["priority"], policy=base["policy"])
        entries.append({"chain": chain})
    elif kind == SET_CHAIN_POLICY:
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("chain"), dict) and is_in_chain(entry["chain"], "name"):
                entry["chain"]["policy"] = change["policy"]
    elif kind == RENAME_CHAIN:
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if isinstance(entry.get("chain"), dict) and is_in_chain(entry["chain"], "name"):
                entry["chain"]["name"] = change["new_name"]
            elif isinstance(entry.get("rule"), dict) and is_in_table(entry["rule"]):
                rule = entry["rule"]
                if rule.get("chain") == change["name"]:
                    rule["chain"] = change["new_name"]
                # Rules that jump to a renamed chain follow its new name.
                for statement in rule.get("expr", []) if isinstance(rule.get("expr"), list) else []:
                    for verb in ("jump", "goto"):
                        target = statement.get(verb) if isinstance(statement, dict) else None
                        if isinstance(target, dict) and target.get("target") == change["name"]:
                            target["target"] = change["new_name"]
    elif kind == DELETE_CHAIN:
        entries[:] = [
            entry
            for entry in entries
            if not (isinstance(entry, dict) and (
                (isinstance(entry.get("chain"), dict) and is_in_chain(entry["chain"], "name"))
                or (isinstance(entry.get("rule"), dict) and is_in_chain(entry["rule"], "chain"))
            ))
        ]
    elif kind == DELETE_TABLE:
        def in_deleted_table(entry):
            if not isinstance(entry, dict) or len(entry) != 1:
                return False
            object_kind, value = next(iter(entry.items()))
            if not isinstance(value, dict) or value.get("family") != change["family"]:
                return False
            return value.get("name") == change["name"] if object_kind == "table" else value.get("table") == change["name"]

        entries[:] = [entry for entry in entries if not in_deleted_table(entry)]
    elif kind == SET_TABLE_ENABLED:
        for entry in entries:
            table = entry.get("table") if isinstance(entry, dict) else None
            if isinstance(table, dict) and table.get("family") == change["family"] and table.get("name") == change["name"]:
                flags = table.get("flags", [])
                flags = [flag for flag in (flags if isinstance(flags, list) else [flags]) if flag != "dormant"]
                table["flags"] = flags if change["enabled"] else flags + ["dormant"]


def rule_key(rule):
    """Identify a rule within a chain's order.

    Returns:
        The handle of an existing rule, or the pending ID of a new one.
    """
    return rule["pending_id"] if rule.get("handle") == "new" else rule.get("handle")


def chain_rules(ruleset, family, table, chain):
    """List a chain's rules in order.

    Returns:
        A list of rule dictionaries.
    """
    return [
        rule
        for rule in rules_from(ruleset)
        if rule.get("family") == family and rule.get("table") == table and rule.get("chain") == chain
    ]


def _reorder_entries(entries, change):
    """Put a chain's rule entries into a change's order, in place.

    Returns:
        None. Entries the order doesn't mention stay at the end, and are
        reported separately by stale_changes.
    """
    positions = {key: index for index, key in enumerate(change["order"])}
    indexes = [
        index
        for index, entry in enumerate(entries)
        if isinstance(entry, dict)
        and isinstance(entry.get("rule"), dict)
        and entry["rule"].get("family") == change["family"]
        and entry["rule"].get("table") == change["table"]
        and entry["rule"].get("chain") == change["chain"]
    ]
    ordered = sorted(
        (entries[index] for index in indexes),
        key=lambda entry: positions.get(rule_key(entry["rule"]), len(positions)),
    )
    for index, entry in zip(indexes, ordered):
        entries[index] = entry


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

    Follows the list in order, because a change can depend on an earlier one.

    Returns:
        A set of change IDs.
    """
    chains = {chain_key(chain.get("family"), chain.get("table"), chain.get("name")) for chain in chains_from(ruleset)}
    tables = {(table.get("family"), table.get("name")) for table in tables_from(ruleset)}
    stale = set()
    for index, change in enumerate(changes):
        kind = change["type"]
        if kind == CREATE_TABLE:
            tables.add((change["family"], change["name"]))
        elif kind == DELETE_TABLE or kind == SET_TABLE_ENABLED:
            current = {
                chain
                for chain in chains
                if chain.startswith(f"{change['family']} {change['name']} ")
            }
            if (change["family"], change["name"]) not in tables or current - set(change["chains"]) - _created_chains(changes[:index]):
                stale.add(change["id"])
            if kind == DELETE_TABLE:
                tables.discard((change["family"], change["name"]))
                chains -= current
        elif kind == CREATE_CHAIN:
            if (change["family"], change["table"]) not in tables:
                stale.add(change["id"])
            chains.add(change_chain(change))
        elif change_chain(change) not in chains:
            stale.add(change["id"])
        elif kind == RENAME_CHAIN:
            chains.discard(change_chain(change))
            chains.add(chain_key(change["family"], change["table"], change["new_name"]))
        elif kind == DELETE_CHAIN:
            chains.discard(change_chain(change))
        elif kind == SET_RULE_ORDER:
            earlier = apply_to_ruleset(ruleset, changes[:index])
            current = chain_rules(earlier, change["family"], change["table"], change["chain"])
            if sorted(map(str, change["order"])) != sorted(str(rule_key(rule)) for rule in current):
                stale.add(change["id"])
        elif kind in (DELETE_RULE, REPLACE_RULE):
            target = change["rule"] if kind == REPLACE_RULE else change
            current = find_rule(ruleset, target["family"], target["table"], target["chain"], change["handle"])
            if current is None or _without_counters(current) != _without_counters(change["before"]):
                stale.add(change["id"])
    return stale


def _created_chains(changes):
    """Find chains a list creates.

    Returns:
        A set of chain keys.
    """
    return {change_chain(change) for change in changes if change["type"] == CREATE_CHAIN}


def describe_listed_rule(rule):
    """Describe a listed rule in plain language if possible.

    Returns:
        A description, or the rule's JSON statements if it can't be represented.
    """
    portable = portable_rule(rule)
    # Without counter values, so that traffic doesn't change the description.
    return describe_rule(portable) if portable else json.dumps(_without_counters(rule))


def _count(number, noun):
    """Format a count, such as "1 rule" or "3 rules".

    Returns:
        Text.
    """
    return f"{number} {noun}{'' if number == 1 else 's'}"


def _describe_structure_change(change, ruleset):
    """Describe a chain or table change's state before and after.

    Returns:
        A dictionary with "kind", "target", "before", and "new".
    """
    kind = change["type"]
    if kind == CREATE_TABLE:
        return {"kind": "New table", "target": f"{change['family']} {change['name']}", "before": "(none)", "new": "empty table"}
    if kind == CREATE_CHAIN:
        base = change.get("base")
        summary = f"{base['hook']} hook, priority {base['priority']}, policy {base['policy']}" if base else "regular chain"
        return {"kind": "New chain", "target": change_chain(change), "before": "(none)", "new": summary}
    if kind == RENAME_CHAIN:
        return {"kind": "Renamed chain", "target": f"{change['family']} {change['table']}", "before": change["name"], "new": change["new_name"]}
    if kind == SET_CHAIN_POLICY:
        return {"kind": "Chain policy", "target": change_chain(change), "before": change["old_policy"], "new": change["policy"]}
    if kind == DELETE_CHAIN:
        rules = len(chain_rules(ruleset, change["family"], change["table"], change["name"])) if ruleset else None
        return {
            "kind": "Deleted chain",
            "target": change_chain(change),
            "before": "contents unknown" if rules is None else _count(rules, "rule"),
            "new": "(deleted)",
        }
    target = f"{change['family']} {change['name']}"
    if kind == SET_TABLE_ENABLED:
        return {"kind": "Table enforcement", "target": target, "before": "off" if change["enabled"] else "on", "new": "on" if change["enabled"] else "off"}
    contents = table_contents(ruleset, change["family"], change["name"]) if ruleset else None
    return {
        "kind": "Deleted table",
        "target": target,
        "before": "contents unknown"
        if contents is None
        else f"{_count(contents['chains'], 'chain')}, {_count(contents['rules'], 'rule')}, {_count(contents['objects'], 'other object')}",
        "new": "(deleted)",
    }


def describe_change(change, ruleset=None):
    """Describe a change's target and its state before and after.

    Args:
        change: The pending change.
        ruleset: The current listing, for what a deletion would remove.

    Returns:
        A dictionary with "kind", "target", "before", and "new".
    """
    if change["type"] in _CHAIN_TYPES or change["type"] in _TABLE_TYPES:
        return _describe_structure_change(change, ruleset)
    if change["type"] == ADD_RULE:
        return {
            "kind": "New rule",
            "target": change_chain(change),
            "before": "(none)",
            "new": describe_rule(change["rule"]),
        }
    if change["type"] == SET_RULE_ORDER:
        moved = moved_rules(change)
        return {
            "kind": "Rule order",
            "target": change_chain(change),
            "before": f"{len(change['old_order'])} rules in the current order",
            "new": f"{len(moved)} moved",
            "moves": [
                f"{move['text']}: position {move['old']} -> position {move['new']}" if move["old"] else f"{move['text']}: new -> position {move['new']}"
                for move in moved
            ],
            "new_order": [row["text"] for row in change["new_order"]],
        }
    if change["type"] == REPLACE_RULE:
        return {
            "kind": "Edited rule",
            "target": f"{change_chain(change)}, handle {change['handle']}",
            "before": describe_listed_rule(change["before"]),
            "new": describe_rule(change["rule"]),
        }
    return {
        "kind": "Deleted rule",
        "target": f"{change_chain(change)}, handle {change['handle']}",
        "before": describe_listed_rule(change["before"]),
        "new": "(deleted)",
    }


def moved_rules(change):
    """List the rules whose position an order change alters.

    Returns:
        A list of dictionaries with "key", "text", "old", and "new". Positions
        count from 1, and "old" is None for a rule that's new to the chain.
    """
    old_positions = {row["key"]: index for index, row in enumerate(change["old_order"], start=1)}
    moves = []
    for index, row in enumerate(change["new_order"], start=1):
        old = old_positions.get(row["key"])
        if old != index:
            moves.append({"key": row["key"], "text": row["text"], "old": old, "new": index})
    return moves


def required_typed_name(change, ruleset):
    """Find the name a person must type to confirm a destructive change.

    nftables deletes a non-empty chain without warning, and turning a table off
    or deleting it affects everything inside, so a tick box isn't enough.

    Returns:
        The name to type, or None if the change doesn't need it.
    """
    if change["type"] == DELETE_TABLE or (change["type"] == SET_TABLE_ENABLED and not change["enabled"]):
        return change["name"]
    if change["type"] == DELETE_CHAIN and chain_rules(ruleset, change["family"], change["table"], change["name"]):
        return change["name"]
    return None


def is_unmanaged(change, ruleset=None):
    """Report whether a change affects anything Archangel doesn't manage.

    Args:
        change: The pending change.
        ruleset: The current listing, for what a chain or table contains.

    Returns:
        True if it changes or moves an existing rule without the managed marker,
        or changes a chain or table containing such a rule.
    """
    if change["type"] in (ADD_RULE, CREATE_CHAIN, CREATE_TABLE):
        return False
    if change["type"] in (RENAME_CHAIN, SET_CHAIN_POLICY, DELETE_CHAIN):
        rules = chain_rules(ruleset, change["family"], change["table"], change["name"]) if ruleset else []
        return any(rule.get("comment") != MANAGED_RULE_COMMENT for rule in rules)
    if change["type"] in (DELETE_TABLE, SET_TABLE_ENABLED):
        return bool(ruleset) and table_contents(ruleset, change["family"], change["name"])["unmanaged"] > 0
    if change["type"] == SET_RULE_ORDER:
        unmanaged = {row["key"] for row in change["old_order"] if row.get("unmanaged")}
        return any(move["key"] in unmanaged for move in moved_rules(change))
    return change["before"].get("comment") != MANAGED_RULE_COMMENT


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
    if change["type"] in _CHAIN_TYPES or change["type"] in _TABLE_TYPES:
        return _structure_warnings(ruleset, change)
    hook = {**_hooks_by_chain(ruleset), **_hooks_by_chain(after)}.get(change_chain(change))
    if change["type"] == ADD_RULE:
        return _rule_warnings(change["rule"], hook, after, interfaces)
    if change["type"] == SET_RULE_ORDER:
        return _order_warnings(ruleset, after, change, hook)
    warnings = _rule_warnings(change["rule"], hook, after, interfaces) if change["type"] == REPLACE_RULE else []
    if hook == "input" and portable_action(change["before"]) == "accept":
        warnings.append("This could remove access that's currently allowed.")
    if is_unmanaged(change):
        warnings.append("Archangel doesn't manage this rule. Another program or administrator may depend on it.")
    return warnings


def _structure_warnings(ruleset, change):
    """List warnings about a chain or table change.

    Returns:
        A list of warning messages.
    """
    warnings = []
    kind = change["type"]
    drop_policy = (kind == SET_CHAIN_POLICY and change["policy"] == "drop") or (
        kind == CREATE_CHAIN and change.get("base") and change["base"]["policy"] == "drop"
    )
    hook = change["base"]["hook"] if kind == CREATE_CHAIN and change.get("base") else _hooks_by_chain(ruleset).get(change_chain(change))
    if drop_policy and hook == "input":
        warnings.append("This could block other access to this server, such as SSH.")
    if kind == SET_TABLE_ENABLED and not change["enabled"]:
        warnings.append("Every rule in this table stops being enforced, so traffic it blocks would be allowed.")
    if kind == DELETE_TABLE:
        warnings.append("Every rule in this table stops being enforced, and can't be recovered from here.")
    if kind == DELETE_CHAIN and chain_rules(ruleset, change["family"], change["table"], change["name"]):
        warnings.append("nftables deletes this chain's rules with it, and they can't be recovered from here.")
    if is_unmanaged(change, ruleset):
        warnings.append(
            "This contains rules Archangel doesn't manage. Another program or administrator may depend on them, "
            "and software such as Docker may recreate or depend on its own tables."
        )
    return warnings


def _order_warnings(ruleset, after, change, hook):
    """List warnings about a new rule order.

    Returns:
        A list of warning messages.
    """
    warnings = []
    moved = {move["key"] for move in moved_rules(change)}
    current = chain_rules(ruleset, change["family"], change["table"], change["chain"])
    if hook == "input" and any(rule.get("handle") in moved and portable_action(rule) == "accept" for rule in current):
        warnings.append("This could remove access that's currently allowed.")
    if is_unmanaged(change):
        warnings.append("This moves rules Archangel doesn't manage. Another program or administrator may depend on them.")
    rules = chain_rules(after, change["family"], change["table"], change["chain"])
    ends = next((index for index, rule in enumerate(rules) if _ends_chain(rule)), None)
    if ends is not None and ends < len(rules) - 1:
        warnings.append("A rule in this order always applies, so the rules below it may never take effect.")
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
    return any(
        change["type"] in _TABLE_TYPES or hooks.get(change_chain(change)) in (None,) + _INCOMING_HOOKS for change in changes
    )


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
    if change["type"] == ADD_RULE:
        return rule_could_affect(rule_statements(change["rule"]), connection)
    if change["type"] not in (ADD_RULE, DELETE_RULE, REPLACE_RULE):
        return True
    if change["type"] == REPLACE_RULE and rule_could_affect(rule_statements(change["rule"]), connection):
        return True
    return rule_could_affect(change["before"].get("expr"), connection)


def api_payload(pending):
    """Build the API request for a pending change list.

    Returns:
        A JSON-compatible dictionary with the expected revisions and changes.
    """
    changes = []
    # Only rules an order refers to need an ID in the request.
    placed = {key for change in pending["changes"] if change["type"] == SET_RULE_ORDER for key in change["order"]}
    for change in pending["changes"]:
        if change["type"] == ADD_RULE:
            entry = {"type": ADD_RULE, "rule": change["rule"]}
            if change["id"] in placed:
                entry["id"] = change["id"]
            changes.append(entry)
        elif change["type"] == SET_RULE_ORDER:
            changes.append(
                {
                    "type": SET_RULE_ORDER,
                    "family": change["family"],
                    "table": change["table"],
                    "chain": change["chain"],
                    "order": change["order"],
                }
            )
        elif change["type"] in _CHAIN_TYPES or change["type"] in _TABLE_TYPES:
            changes.append({key: value for key, value in change.items() if key in _STRUCTURE_FIELDS})
        elif change["type"] == REPLACE_RULE:
            changes.append({"type": REPLACE_RULE, "handle": change["handle"], "rule": change["rule"]})
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
    touched = set().union(*chains_touched(pending["changes"]).values()) if pending["changes"] else set()
    expected = []
    for key in sorted(touched):
        family, table, chain = key.split(" ")
        expected.append({"family": family, "table": table, "chain": chain, "revision": pending["revisions"].get(key, "")})
    return {"expected_revisions": expected, "changes": changes}


def highlight_entries(changes):
    """Summarize applied changes so that the rules page can mark their rules.

    Bounded, because it's kept in the browser session until the next page. Past
    the limit, the page still reports the result but marks only some rules.

    Returns:
        A list of the structured rules that were added or edited.
    """
    rules = [change["rule"] for change in changes if change["type"] in (ADD_RULE, REPLACE_RULE)]
    return rules[:_MAX_HIGHLIGHTED_RULES]


def _structure_applied(change, chains, tables, later):
    """Check that a chain or table change shows in the listing read back.

    Returns:
        True if the change is visible, or a later change in the list altered
        the same object, which is checked in its own turn.
    """
    kind = change["type"]
    if kind in _TABLE_TYPES:
        key = (change["family"], change["name"])
        if any(other["type"] in _TABLE_TYPES and (other["family"], other["name"]) == key for other in later):
            return True
        if kind == CREATE_TABLE:
            return key in tables
        if kind == DELETE_TABLE:
            return key not in tables
        return key in tables and is_dormant(tables[key]) != change["enabled"]
    if any(
        other["type"] in _CHAIN_TYPES and change_chain(other) == change_chain(change)
        or (other["type"] == DELETE_TABLE and other["family"] == change["family"] and other["name"] == change["table"])
        for other in later
    ):
        return True
    key = change_chain(change)
    if kind == CREATE_CHAIN:
        return key in chains
    if kind == RENAME_CHAIN:
        return key not in chains and chain_key(change["family"], change["table"], change["new_name"]) in chains
    if kind == DELETE_CHAIN:
        return key not in chains
    return key in chains and chains[key].get("policy") == change["policy"]


def verify_applied(ruleset, changes):
    """Confirm that applied changes appear in the ruleset read back afterward.

    Returns:
        True if every change is visible in the ruleset.
    """
    listed = [portable_rule(rule) for rule in rules_from(ruleset)]
    chains = {chain_key(chain.get("family"), chain.get("table"), chain.get("name")): chain for chain in chains_from(ruleset)}
    tables = {(table.get("family"), table.get("name")): table for table in tables_from(ruleset)}
    # A later change can undo what an earlier one set up, such as a new chain
    # that's renamed, so only each object's final state can be checked.
    for index, change in enumerate(changes):
        if change["type"] in _CHAIN_TYPES or change["type"] in _TABLE_TYPES:
            if not _structure_applied(change, chains, tables, changes[index + 1 :]):
                return False
        elif change["type"] == ADD_RULE:
            if change["rule"] not in listed:
                return False
        elif change["type"] == SET_RULE_ORDER:
            # A later change to this chain alters its rules after the order.
            if any(change_chain(later) == change_chain(change) for later in changes[index + 1 :]):
                continue
            rules = chain_rules(ruleset, change["family"], change["table"], change["chain"])
            if [describe_listed_rule(rule) for rule in rules] != [row["text"] for row in change["new_order"]]:
                return False
        elif change["type"] == REPLACE_RULE:
            rule = change["rule"]
            current = find_rule(ruleset, rule["family"], rule["table"], rule["chain"], change["handle"])
            if current is None or portable_rule(current) != rule:
                return False
        elif find_rule(ruleset, change["family"], change["table"], change["chain"], change["handle"]) is not None:
            return False
    return True
