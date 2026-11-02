"""Firewall ruleset inspection and portable rule-bundle conversion.

Pure functions over nftables JSON and the dashboard's versioned
structured-rule bundle; nothing here depends on Flask.
"""
import ipaddress
import re


RULE_BUNDLE_FORMAT = "archangel-firewall-rules"
RULE_BUNDLE_VERSION = 2
# Version 1 files predate subnets, ranges, interfaces, connection state, ICMP,
# and rules without a protocol, and remain importable.
SUPPORTED_RULE_BUNDLE_VERSIONS = (1, RULE_BUNDLE_VERSION)
MAX_RULE_BUNDLE_BYTES = 512 * 1024
MAX_RULE_BUNDLE_SIZE_TEXT = f"{MAX_RULE_BUNDLE_BYTES // 1024} KiB"
MAX_IMPORTED_RULES = 1000
RULE_FAMILIES = ("ip", "ip6", "inet")
RULE_ACTIONS = ("accept", "drop", "reject")
RULE_PROTOCOLS = ("tcp", "udp", "icmp", "icmpv6")
# In the order the backend writes them (see CONNECTION_STATES in nft_rule.cpp).
CONNECTION_STATES = ("new", "established", "related", "invalid")
RULE_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
# Mirrors Config::Limits::MAX_INTERFACE_NAME_LENGTH; the backend is authoritative.
INTERFACE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,15}$")
# nftables lists layer-4 protocols by number when no port match implies them.
L4_PROTOCOLS = {
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "ipv6-icmp": "icmpv6",
    6: "tcp",
    17: "udp",
    1: "icmp",
    58: "icmpv6",
}
# nftables reports a plain reject with default options for what the rule covers:
# in an inet table, an IPv4 or IPv6 address match narrows the default.
DEFAULT_REJECT_TYPES = {"inet": "icmpx", "ip": "icmp", "ip6": "icmpv6"}
ADDRESS_REJECT_TYPES = {4: "icmp", 6: "icmpv6"}
RULE_FIELDS_V1 = {
    "family",
    "table",
    "chain",
    "protocol",
    "source_address",
    "destination_address",
    "destination_port",
    "action",
}
RULE_FIELDS = RULE_FIELDS_V1 | {
    "destination_port_end",
    "input_interface",
    "output_interface",
    "connection_states",
}


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


def normalize_address(value):
    """Validate an address or CIDR subnet the way the backend does.

    Returns:
        A pair of (normalized text, IP version). A subnet covering one host
        becomes a plain address, which is how nftables reads it back.

    Raises:
        ValueError: If the value is invalid or a subnet has host bits set,
            which nftables would silently mask.
    """
    network = ipaddress.ip_network(value, strict=True)
    if network.prefixlen == network.max_prefixlen:
        return str(network.network_address), network.version
    return str(network), network.version


def _listed_address(right):
    """Convert a listed nftables address or prefix to the portable form.

    Returns:
        A pair of (text, IP version), or None for any other shape.
    """
    if isinstance(right, dict) and set(right) == {"prefix"} and isinstance(right["prefix"], dict):
        address, length = right["prefix"].get("addr"), right["prefix"].get("len")
        if not isinstance(address, str) or not isinstance(length, int) or isinstance(length, bool):
            return None
        right = f"{address}/{length}"
    if not isinstance(right, str):
        return None
    try:
        return normalize_address(right)
    except ValueError:
        return None


def _listed_port_range(right):
    """Convert a listed port or port range to its start and optional end.

    Returns:
        A pair of (start, end or None), or None for any other shape.
    """
    is_port = lambda value: isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535
    if is_port(right):
        return right, None
    if isinstance(right, dict) and set(right) == {"range"} and isinstance(right["range"], list):
        bounds = right["range"]
        if len(bounds) == 2 and all(is_port(bound) for bound in bounds) and bounds[0] <= bounds[1]:
            return bounds[0], (bounds[1] if bounds[1] != bounds[0] else None)
    return None


def _listed_connection_states(right):
    """Convert a listed connection-state match to canonical order.

    nftables lists one state as a string and several as a list.

    Returns:
        A list of states, or None for any other shape.
    """
    states = [right] if isinstance(right, str) else right
    if (
        not isinstance(states, list)
        or not states
        or not all(isinstance(state, str) and state in CONNECTION_STATES for state in states)
    ):
        return None
    return [state for state in CONNECTION_STATES if state in states]


def portable_rule(rule):
    """Convert an nftables rule to the portable rule subset Archangel supports.

    Returns:
        A JSON-compatible rule specification, or None if the rule contains
        anything the structured-rule contract can't represent exactly. That
        includes any statement after the verdict, since it would change what
        the rule means.
    """
    if not isinstance(rule, dict):
        return None
    result = {}
    for field in ("family", "table", "chain"):
        value = rule.get(field)
        if not isinstance(value, str) or not value:
            return None
        result[field] = value
    family = result["family"]
    if (
        family not in RULE_FAMILIES
        or not RULE_NAME_PATTERN.fullmatch(result["table"])
        or not RULE_NAME_PATTERN.fullmatch(result["chain"])
    ):
        return None

    expression = rule.get("expr")
    if not isinstance(expression, list):
        return None
    protocol = None
    action = None
    reject_options = None
    matches = {}
    port_protocol = None
    ip_versions = set()
    for statement in expression:
        if action is not None or not isinstance(statement, dict) or len(statement) != 1:
            return None
        verdict = next((name for name in RULE_ACTIONS if name in statement), None)
        if verdict is not None:
            reject_options = statement[verdict]
            if reject_options is not None and verdict != "reject":
                return None
            action = verdict
            continue
        match = statement.get("match")
        if not isinstance(match, dict):
            return None
        op = match.get("op")
        left = match.get("left")
        right = match.get("right")
        if not isinstance(left, dict) or len(left) != 1:
            return None
        if "ct" in left:
            states = _listed_connection_states(right)
            if (
                left["ct"] != {"key": "state"}
                or op not in ("in", "==")
                or states is None
                or "connection_states" in matches
            ):
                return None
            matches["connection_states"] = states
            continue
        if op != "==":
            return None
        if "meta" in left:
            meta = left["meta"]
            key = meta.get("key") if isinstance(meta, dict) else None
            if key == "l4proto":
                hashable = isinstance(right, (str, int)) and not isinstance(right, bool)
                l4_protocol = L4_PROTOCOLS.get(right) if hashable else None
                if l4_protocol is None or protocol is not None:
                    return None
                protocol = l4_protocol
                continue
            target = {"iifname": "input_interface", "oifname": "output_interface"}.get(key)
            if (
                target is None
                or target in matches
                or not isinstance(right, str)
                or not INTERFACE_NAME_PATTERN.fullmatch(right)
            ):
                return None
            matches[target] = right
            continue
        payload = left.get("payload")
        if not isinstance(payload, dict):
            return None
        payload_protocol = payload.get("protocol")
        field = payload.get("field")
        if field in ("saddr", "daddr") and payload_protocol in ("ip", "ip6"):
            target = "source_address" if field == "saddr" else "destination_address"
            address = _listed_address(right)
            if target in matches or address is None:
                return None
            if (payload_protocol == "ip") != (address[1] == 4):
                return None
            matches[target] = address[0]
            ip_versions.add(address[1])
            continue
        if field == "dport" and payload_protocol in ("tcp", "udp"):
            ports = _listed_port_range(right)
            if "destination_port" in matches or ports is None:
                return None
            matches["destination_port"] = ports[0]
            if ports[1] is not None:
                matches["destination_port_end"] = ports[1]
            port_protocol = payload_protocol
            continue
        return None

    # nftables omits the l4proto match when a port match already implies it.
    protocol = protocol or port_protocol
    if action not in RULE_ACTIONS or (port_protocol and port_protocol != protocol):
        return None
    if reject_options is not None:
        reject_type = DEFAULT_REJECT_TYPES[family]
        if family == "inet" and len(ip_versions) == 1:
            reject_type = ADDRESS_REJECT_TYPES[next(iter(ip_versions))]
        if reject_options != {"type": reject_type, "expr": "port-unreachable"}:
            return None
    if protocol is not None:
        result["protocol"] = protocol
    elif not matches:
        return None
    result.update(action=action, **matches)
    try:
        return validate_rule(result, "Rule")
    except ValueError:
        return None


def validate_rule(rule, label, *, allowed_fields=RULE_FIELDS):
    """Validate one structured rule, matching the backend's rules.

    The backend remains authoritative; this only reports problems earlier.

    Returns:
        A normalized copy of the rule, without unset fields.

    Raises:
        ValueError: If a field is invalid, unsupported, or can't match
            alongside the others. The message starts with the given label.
    """
    if not isinstance(rule, dict) or set(rule) - allowed_fields:
        raise ValueError(f"{label} contains unsupported fields.")
    for field in ("family", "table", "chain", "action"):
        if not isinstance(rule.get(field), str) or not rule[field]:
            raise ValueError(f"{label} requires a non-empty {field}.")
    if rule["family"] not in RULE_FAMILIES:
        raise ValueError(f"{label} has an unsupported address family.")
    if not RULE_NAME_PATTERN.fullmatch(rule["table"]) or not RULE_NAME_PATTERN.fullmatch(rule["chain"]):
        raise ValueError(f"{label} has an invalid table or chain identifier.")
    protocol = rule.get("protocol")
    if protocol is not None and protocol not in RULE_PROTOCOLS:
        raise ValueError(f"{label} has an unsupported protocol or action.")
    if rule["action"] not in RULE_ACTIONS:
        raise ValueError(f"{label} has an unsupported protocol or action.")

    normalized = {key: value for key, value in rule.items() if value not in (None, [])}
    versions = set()
    for field in ("source_address", "destination_address"):
        value = rule.get(field)
        if value is None:
            continue
        if not isinstance(value, str):
            raise ValueError(f"{label} has an invalid {field}.")
        try:
            normalized[field], version = normalize_address(value)
        except ValueError as error:
            raise ValueError(
                f"{label} has an invalid {field}. A subnet must not have host bits set."
            ) from error
        versions.add(version)
    if len(versions) > 1:
        raise ValueError(f"{label} mixes IPv4 and IPv6 addresses.")
    if (rule["family"] == "ip" and 6 in versions) or (rule["family"] == "ip6" and 4 in versions):
        raise ValueError(f"{label} has an address incompatible with its family.")
    if (protocol == "icmp" and (rule["family"] == "ip6" or 6 in versions)) or (
        protocol == "icmpv6" and (rule["family"] == "ip" or 4 in versions)
    ):
        raise ValueError(f"{label} has a protocol incompatible with its family or addresses.")

    for field in ("destination_port", "destination_port_end"):
        port = rule.get(field)
        if port is not None and (not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535):
            raise ValueError(f"{label} has an invalid destination port.")
    port, port_end = rule.get("destination_port"), rule.get("destination_port_end")
    if port_end is not None and (port is None or port_end < port):
        raise ValueError(f"{label} has an invalid destination port range.")
    if port_end == port:
        normalized.pop("destination_port_end", None)
    if port is not None and protocol not in ("tcp", "udp"):
        raise ValueError(f"{label} needs TCP or UDP to use a destination port.")

    for field in ("input_interface", "output_interface"):
        name = rule.get(field)
        if name is not None and (not isinstance(name, str) or not INTERFACE_NAME_PATTERN.fullmatch(name)):
            raise ValueError(f"{label} has an invalid {field}.")
    states = rule.get("connection_states")
    if states is not None:
        if not isinstance(states, list) or not all(isinstance(state, str) and state in CONNECTION_STATES for state in states):
            raise ValueError(f"{label} has invalid connection_states.")
        if states:
            normalized["connection_states"] = [state for state in CONNECTION_STATES if state in states]

    if not any(
        normalized.get(field) is not None
        for field in (
            "protocol",
            "source_address",
            "destination_address",
            "destination_port",
            "input_interface",
            "output_interface",
            "connection_states",
        )
    ):
        raise ValueError(f"{label} must have at least one match.")
    return normalized


def describe_rule(rule):
    """Describe a structured rule in plain language.

    Returns:
        Text such as "Accept TCP traffic to port 443 from 192.0.2.10".
    """
    protocol = rule.get("protocol")
    parts = [rule["action"].capitalize(), protocol.upper() if protocol else "all", "traffic"]
    if rule.get("connection_states"):
        parts.insert(1, "/".join(rule["connection_states"]))
    port = rule.get("destination_port")
    if port is not None:
        end = rule.get("destination_port_end")
        parts.append(f"to ports {port}-{end}" if end else f"to port {port}")
    if rule.get("destination_address"):
        parts.append(f"going to {rule['destination_address']}")
    if rule.get("source_address"):
        parts.append(f"from {rule['source_address']}")
    if rule.get("input_interface"):
        parts.append(f"arriving on {rule['input_interface']}")
    if rule.get("output_interface"):
        parts.append(f"leaving on {rule['output_interface']}")
    return " ".join(parts)


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
    version = bundle.get("version") if isinstance(bundle, dict) else None
    if (
        not isinstance(bundle, dict)
        or bundle.get("format") != RULE_BUNDLE_FORMAT
        or isinstance(version, bool)
        or version not in SUPPORTED_RULE_BUNDLE_VERSIONS
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
    for index, rule in enumerate(rules, start=1):
        label = f"Rule {index}"
        if version == 1:
            _require_version_1_rule(rule, label)
            normalized.append(validate_rule(rule, label, allowed_fields=RULE_FIELDS_V1))
        else:
            normalized.append(validate_rule(rule, label))
    return normalized


def _require_version_1_rule(rule, label):
    """Apply the rules that version 1 bundles had beyond the current ones.

    Returns:
        None.

    Raises:
        ValueError: If the rule needs a feature version 1 didn't have.
    """
    if not isinstance(rule, dict):
        raise ValueError(f"{label} contains unsupported fields.")
    if rule.get("protocol") not in ("tcp", "udp"):
        raise ValueError(f"{label} has an unsupported protocol or action.")
    for field in ("source_address", "destination_address"):
        if isinstance(rule.get(field), str) and "/" in rule[field]:
            raise ValueError(f"{label} has an invalid {field}.")
    if all(rule.get(field) is None for field in ("source_address", "destination_address", "destination_port")):
        raise ValueError(f"{label} must have at least one address or destination-port match.")


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
