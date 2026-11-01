"""Firewall ruleset inspection and portable rule-bundle conversion.

Pure functions over nftables JSON and the dashboard's versioned
structured-rule bundle; nothing here depends on Flask.
"""
import ipaddress
import re


RULE_BUNDLE_FORMAT = "archangel-firewall-rules"
RULE_BUNDLE_VERSION = 1
MAX_RULE_BUNDLE_BYTES = 512 * 1024
MAX_RULE_BUNDLE_SIZE_TEXT = f"{MAX_RULE_BUNDLE_BYTES // 1024} KiB"
MAX_IMPORTED_RULES = 1000
RULE_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
# nftables lists layer-4 protocols by number when no port match implies them.
L4_PROTOCOLS = {"tcp": "tcp", "udp": "udp", 6: "tcp", 17: "udp"}


def rules_from(ruleset):
    """Extract rule objects from an nftables ruleset response.

    Returns:
        A list of rule dictionaries, or an empty list for an invalid shape.
    """
    if not isinstance(ruleset, dict):
        return []
    entries = ruleset.get("nftables", [])
    if not isinstance(entries, list):
        return []
    return [entry["rule"] for entry in entries if isinstance(entry, dict) and isinstance(entry.get("rule"), dict)]


def ruleset_shape_error(ruleset):
    """Return an error when the backend payload is not a complete ruleset."""
    if not isinstance(ruleset, dict) or not isinstance(ruleset.get("nftables"), list):
        return "The backend returned an invalid firewall ruleset response."
    return None


def portable_rule(rule):
    """Convert an nftables rule to the portable rule subset Archangel supports.

    Returns:
        A JSON-compatible rule specification, or None if the rule contains
        expressions outside the supported structured-rule contract.
    """
    if not isinstance(rule, dict):
        return None
    result = {}
    for field in ("family", "table", "chain"):
        value = rule.get(field)
        if not isinstance(value, str) or not value:
            return None
        result[field] = value

    expression = rule.get("expr")
    if not isinstance(expression, list):
        return None
    protocol = None
    action = None
    matches = {}
    for statement in expression:
        if not isinstance(statement, dict) or len(statement) != 1:
            return None
        if any(verdict in statement for verdict in ("accept", "drop", "reject")):
            verdict = next(verdict for verdict in ("accept", "drop", "reject") if verdict in statement)
            if action is not None or statement[verdict] is not None:
                return None
            action = verdict
            continue
        match = statement.get("match")
        if not isinstance(match, dict) or match.get("op") != "==":
            return None
        left = match.get("left")
        right = match.get("right")
        if not isinstance(left, dict) or len(left) != 1:
            return None
        if "meta" in left:
            meta = left["meta"]
            hashable = isinstance(right, (str, int)) and not isinstance(right, bool)
            l4_protocol = L4_PROTOCOLS.get(right) if hashable else None
            if (
                not isinstance(meta, dict)
                or meta.get("key") != "l4proto"
                or l4_protocol is None
                or protocol is not None
            ):
                return None
            protocol = l4_protocol
            continue
        payload = left.get("payload")
        if not isinstance(payload, dict):
            return None
        payload_protocol = payload.get("protocol")
        field = payload.get("field")
        if field in ("saddr", "daddr") and payload_protocol in ("ip", "ip6") and isinstance(right, str):
            target = "source_address" if field == "saddr" else "destination_address"
            if target in matches:
                return None
            try:
                address = ipaddress.ip_address(right)
            except ValueError:
                return None
            if (payload_protocol == "ip") != (address.version == 4):
                return None
            matches[target] = right
            continue
        if field == "dport" and payload_protocol in ("tcp", "udp") and isinstance(right, int) and not isinstance(right, bool):
            if "destination_port" in matches:
                return None
            matches["destination_port"] = right
            matches["port_protocol"] = payload_protocol
            continue
        return None

    # nftables omits the l4proto match when a port match already implies it.
    protocol = protocol or matches.get("port_protocol")
    if protocol not in ("tcp", "udp") or action not in ("accept", "drop", "reject"):
        return None
    if matches.get("port_protocol", protocol) != protocol:
        return None
    matches.pop("port_protocol", None)
    if not matches:
        return None
    result.update(protocol=protocol, action=action, **matches)
    return result


def portable_bundle(ruleset):
    """Create a versioned portable configuration from supported live rules.

    Returns:
        A bundle and the number of active rules that were not representable.
    """
    rules = []
    skipped = 0
    for rule in rules_from(ruleset):
        portable = portable_rule(rule)
        if portable is None:
            skipped += 1
        else:
            rules.append(portable)
    return {
        "format": RULE_BUNDLE_FORMAT,
        "version": RULE_BUNDLE_VERSION,
        "rules": rules,
        "omitted_unsupported_rules": skipped,
    }, skipped


def validate_rule_bundle(bundle):
    """Validate a portable rule bundle before showing or applying it.

    Returns:
        A list of normalized rule specifications.

    Raises:
        ValueError: If the bundle or any rule is invalid or unsupported.
    """
    if (
        not isinstance(bundle, dict)
        or bundle.get("format") != RULE_BUNDLE_FORMAT
        or bundle.get("version") != RULE_BUNDLE_VERSION
        or isinstance(bundle.get("version"), bool)
        or set(bundle) - {"format", "version", "rules", "omitted_unsupported_rules"}
    ):
        raise ValueError("The file is not a supported Archangel firewall-rules bundle.")
    omitted = bundle.get("omitted_unsupported_rules", 0)
    if not isinstance(omitted, int) or isinstance(omitted, bool) or omitted < 0:
        raise ValueError("The bundle has invalid unsupported-rule metadata.")
    rules = bundle.get("rules")
    if not isinstance(rules, list) or len(rules) > MAX_IMPORTED_RULES:
        raise ValueError(f"The bundle must contain no more than {MAX_IMPORTED_RULES} rules.")
    normalized = []
    allowed = {
        "family",
        "table",
        "chain",
        "protocol",
        "source_address",
        "destination_address",
        "destination_port",
        "action",
    }
    for index, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict) or set(rule) - allowed:
            raise ValueError(f"Rule {index} contains unsupported fields.")
        for field in ("family", "table", "chain", "protocol", "action"):
            if not isinstance(rule.get(field), str) or not rule[field]:
                raise ValueError(f"Rule {index} requires a non-empty {field}.")
        if rule["family"] not in ("ip", "ip6", "inet"):
            raise ValueError(f"Rule {index} has an unsupported address family.")
        if not RULE_NAME_PATTERN.fullmatch(rule["table"]) or not RULE_NAME_PATTERN.fullmatch(rule["chain"]):
            raise ValueError(f"Rule {index} has an invalid table or chain identifier.")
        if rule["protocol"] not in ("tcp", "udp") or rule["action"] not in ("accept", "drop", "reject"):
            raise ValueError(f"Rule {index} has an unsupported protocol or action.")
        has_match = False
        for field in ("source_address", "destination_address"):
            value = rule.get(field)
            if value is not None:
                if not isinstance(value, str):
                    raise ValueError(f"Rule {index} has an invalid {field}.")
                try:
                    address = ipaddress.ip_address(value)
                except ValueError as error:
                    raise ValueError(f"Rule {index} has an invalid {field}.") from error
                if rule["family"] == "ip" and address.version != 4:
                    raise ValueError(f"Rule {index} has an address incompatible with its family.")
                if rule["family"] == "ip6" and address.version != 6:
                    raise ValueError(f"Rule {index} has an address incompatible with its family.")
                has_match = True
        if "destination_port" in rule:
            port = rule["destination_port"]
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                raise ValueError(f"Rule {index} has an invalid destination port.")
            has_match = True
        if not has_match:
            raise ValueError(f"Rule {index} must have at least one address or destination-port match.")
        normalized.append({key: value for key, value in rule.items() if value is not None})
    return normalized


def firewall_status(ruleset):
    """Summarize whether nftables has base chains attached to packet hooks.

    Returns:
        A pair of (status label, active base-chain count).
    """
    if not isinstance(ruleset, dict) or not isinstance(ruleset.get("nftables"), list):
        return "Unavailable", None
    active_chains = sum(
        1
        for entry in ruleset["nftables"]
        if isinstance(entry, dict)
        and isinstance(entry.get("chain"), dict)
        and isinstance(entry["chain"].get("hook"), str)
        and entry["chain"]["hook"]
    )
    return ("Active" if active_chains else "No active base chains"), active_chains
