"""Whether a firewall change could disturb the dashboard's connection to the API.

Follows that connection through nftables rulesets as JSON listings, without
Flask or network access. This is a warning, not a guarantee: it sees one
connection and only this host's firewall. Anything it can't evaluate counts as
uncertain, so a limit it doesn't understand produces "could block" rather than
silence.
"""
import ipaddress
from dataclasses import dataclass


WILL_BLOCK = "will_block"
COULD_BLOCK = "could_block"
UNKNOWN_CONNECTION = "unknown_connection"
NO_CHANGE = "no_change"

_ALLOWED = "allowed"
_BLOCKED = "blocked"
_UNCERTAIN = "uncertain"

# Matches the kernel's limit on nested jumps.
_MAX_JUMP_DEPTH = 16
_INBOUND_HOOKS = ("prerouting", "input")
_OUTBOUND_HOOKS = ("output", "postrouting")
_PASSIVE_STATEMENTS = ("counter", "log")
_ACCEPTING_NAT_STATEMENTS = ("snat", "masquerade")
# A client's own port is unknown, but operating systems pick temporary ports
# from the top of the range. Linux starts at 32768 and Windows at 49152, so a
# rule for a lower port can't match it.
_LOWEST_TEMPORARY_PORT = 32768
_REDIRECTING_NAT_STATEMENTS = ("dnat", "redirect")


@dataclass(frozen=True)
class Connection:
    """The dashboard's connection to the API, as the backend sees it."""

    client_address: str
    api_port: int


@dataclass(frozen=True)
class ConnectionCheck:
    """The result of comparing a connection across two rulesets.

    `status` is one of WILL_BLOCK, COULD_BLOCK, UNKNOWN_CONNECTION, or
    NO_CHANGE, and `causes` describes the rules or policies responsible.
    """

    status: str
    causes: tuple = ()


@dataclass(frozen=True)
class _Packet:
    version: int
    source: object
    destination: object
    source_port: object
    destination_port: object
    state: str
    input_interface: object
    output_interface: object
    hooks: tuple


def connection_from_status(status):
    """Read connection details from a `/status/info` payload.

    Returns:
        A Connection, or None if the details are missing or invalid.
    """
    if not isinstance(status, dict):
        return None
    address = status.get("client_address")
    port = status.get("api_port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return None
    parsed = _client_ip(address)
    return Connection(str(parsed), port) if parsed is not None else None


def browser_crosses_firewall(connection, browser_address):
    """Report a dashboard on the firewall's own host used from another computer.

    Returns:
        True if the API sees the dashboard on loopback and the browser's
        address isn't a loopback address.
    """
    if connection is None:
        return False
    client = _client_ip(connection.client_address)
    browser = _client_ip(browser_address)
    return client is not None and browser is not None and client.is_loopback and not browser.is_loopback


def check_connection(before, after, connection):
    """Compare the dashboard's connection in the current and proposed rulesets.

    Args:
        before: Current nftables JSON ruleset.
        after: The ruleset as it would be after the change.
        connection: A Connection, or None if the details are unknown.

    Returns:
        A ConnectionCheck.
    """
    if connection is None or _client_ip(connection.client_address) is None:
        return ConnectionCheck(UNKNOWN_CONNECTION)
    before_status, _ = _evaluate(before, connection)
    after_status, causes = _evaluate(after, connection)
    if after_status == _BLOCKED and before_status != _BLOCKED:
        return ConnectionCheck(WILL_BLOCK, causes)
    if after_status == _UNCERTAIN and before_status == _ALLOWED:
        return ConnectionCheck(COULD_BLOCK, causes)
    return ConnectionCheck(NO_CHANGE)


def rule_could_affect(statements, connection):
    """Report whether a rule could apply to any traffic of the connection.

    Returns:
        True unless one of the rule's matches is definitely false for every
        packet and hook of the connection.
    """
    if connection is None or _client_ip(connection.client_address) is None:
        return True
    if not isinstance(statements, list):
        return True
    for packet in _packets(connection):
        for hook in packet.hooks:
            matches = (
                statement["match"]
                for statement in statements
                if isinstance(statement, dict) and "match" in statement
            )
            if all(_evaluate_match(match, packet, hook) is not False for match in matches):
                return True
    return False


def _client_ip(address):
    """Parse an address, unwrapping IPv4 addresses reported in IPv6 form.

    Returns:
        An IP address object, or None if the address is invalid.
    """
    # ip_address also accepts integers, which aren't addresses here.
    if not isinstance(address, str):
        return None
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    return getattr(parsed, "ipv4_mapped", None) or parsed


def _packets(connection):
    """List the traffic the connection depends on.

    The dashboard opens new TCP connections, so both new and established
    traffic have to pass, in both directions. On loopback, every packet passes
    both the sending and receiving hooks, on the `lo` interface.

    Returns:
        A list of _Packet values. Unknown fields are None.
    """
    client = _client_ip(connection.client_address)
    port = connection.api_port
    if client.is_loopback:
        loopback_hooks = _OUTBOUND_HOOKS + _INBOUND_HOOKS
        common = {"version": client.version, "source": client, "destination": client}
        names = {"input_interface": "lo", "output_interface": "lo", "hooks": loopback_hooks}
        return [
            _Packet(**common, **names, source_port=None, destination_port=port, state="new"),
            _Packet(**common, **names, source_port=None, destination_port=port, state="established"),
            _Packet(**common, **names, source_port=port, destination_port=None, state="established"),
        ]
    inbound = {
        "version": client.version,
        "source": client,
        "destination": None,
        "source_port": None,
        "destination_port": port,
        "input_interface": None,
        "output_interface": None,
        "hooks": _INBOUND_HOOKS,
    }
    return [
        _Packet(**inbound, state="new"),
        _Packet(**inbound, state="established"),
        _Packet(
            version=client.version,
            source=None,
            destination=client,
            source_port=port,
            destination_port=None,
            state="established",
            input_interface=None,
            output_interface=None,
            hooks=_OUTBOUND_HOOKS,
        ),
    ]


def _evaluate(ruleset, connection):
    """Follow the connection through one ruleset.

    Returns:
        A pair of (_ALLOWED, _BLOCKED, or _UNCERTAIN, and a tuple of causes).
    """
    firewall = _Firewall(ruleset)
    if not firewall.valid:
        return _UNCERTAIN, ("the firewall ruleset could not be read",)
    status = _ALLOWED
    causes = []
    for packet in _packets(connection):
        passes, blocks = firewall.follow(packet)
        for cause in blocks:
            if cause not in causes:
                causes.append(cause)
        if not passes:
            status = _BLOCKED
        elif blocks and status != _BLOCKED:
            status = _UNCERTAIN
    return status, tuple(causes)


class _Firewall:
    """A ruleset's enabled tables, base chains, and rules."""

    def __init__(self, ruleset):
        self.valid = isinstance(ruleset, dict) and isinstance(ruleset.get("nftables"), list)
        self.base_chains = []
        self.chains = {}
        self.has_unmodeled_chains = False
        if not self.valid:
            return
        entries = [entry for entry in ruleset["nftables"] if isinstance(entry, dict)]
        dormant = set()
        for entry in entries:
            table = entry.get("table")
            if isinstance(table, dict) and "dormant" in _as_list(table.get("flags")):
                dormant.add((table.get("family"), table.get("name")))
        for entry in entries:
            chain = entry.get("chain")
            if not isinstance(chain, dict) or (chain.get("family"), chain.get("table")) in dormant:
                continue
            key = (chain.get("family"), chain.get("table"), chain.get("name"))
            self.chains[key] = {"chain": chain, "rules": []}
            if chain.get("hook"):
                if chain.get("family") in ("ip", "ip6", "inet"):
                    self.base_chains.append(key)
                elif chain.get("family") == "netdev":
                    self.has_unmodeled_chains = True
        for entry in entries:
            rule = entry.get("rule")
            if isinstance(rule, dict):
                key = (rule.get("family"), rule.get("table"), rule.get("chain"))
                if key in self.chains:
                    self.chains[key]["rules"].append(rule)
        self.base_chains.sort(key=lambda key: _priority(self.chains[key]["chain"]))

    def follow(self, packet):
        """Follow one packet through every hook it passes.

        Returns:
            A pair of (whether the packet can pass, causes of possible blocks).
        """
        blocks = []
        if self.has_unmodeled_chains:
            blocks.append("a netdev chain that can't be checked")
        for hook in packet.hooks:
            for key in self.base_chains:
                chain = self.chains[key]["chain"]
                if chain.get("hook") != hook or not _family_applies(chain.get("family"), packet.version):
                    continue
                # Only the first packet of a connection passes through NAT
                # chains. Loopback traffic gets its NAT on the way out, so it
                # also skips NAT chains on the receiving hooks.
                if chain.get("type") == "nat" and (
                    packet.state != "new" or (packet.input_interface == "lo" and hook in _INBOUND_HOOKS)
                ):
                    continue
                outcomes = self._walk_base(key, packet, hook)
                blocks.extend(cause for kind, cause in outcomes if kind in ("drop", "uncertain") and cause not in blocks)
                if not any(kind in ("accept", "uncertain") for kind, _ in outcomes):
                    return False, blocks
        return True, blocks

    def _walk_base(self, key, packet, hook):
        """Evaluate a base chain, whose end applies its policy.

        Returns:
            A set of (kind, cause) outcomes that aren't "return".
        """
        outcomes = self._walk(key, packet, hook, {}, 0)
        if ("return", None) not in outcomes:
            return outcomes
        outcomes = outcomes - {("return", None)}
        if self.chains[key]["chain"].get("policy") == "drop":
            return outcomes | {("drop", f"the drop policy of {_chain_name(key)}")}
        return outcomes | {("accept", None)}

    def _walk(self, key, packet, hook, memo, depth):
        """Evaluate a chain's rules for one packet.

        Returns:
            A set of (kind, cause) outcomes, where kind is "accept", "drop",
            "uncertain", or "return" for reaching the chain's end.
        """
        if key in memo:
            # Revisiting a chain still being evaluated means a jump loop.
            return memo[key] if memo[key] is not None else {("uncertain", f"a jump loop in {_chain_name(key)}")}
        if key not in self.chains or depth > _MAX_JUMP_DEPTH:
            return {("uncertain", f"a jump to {_chain_name(key)} that can't be followed")}
        memo[key] = None
        outcomes = set()
        for rule in self.chains[key]["rules"]:
            matched, verdicts = self._apply_rule(rule, key, packet, hook, memo, depth)
            if _is_jump(rule):
                # A jump that comes back continues with this chain's next rule.
                outcomes |= verdicts - {("return", None)}
                if matched and ("return", None) not in verdicts:
                    break
                continue
            outcomes |= verdicts
            if matched:
                break
        else:
            outcomes.add(("return", None))
        memo[key] = outcomes
        return outcomes

    def _apply_rule(self, rule, key, packet, hook, memo, depth):
        """Apply one rule to a packet.

        Returns:
            A pair of (whether the rule definitely matches, its possible
            outcomes). A rule that might match is reported as not definitely
            matching, so evaluation continues with the following rules too.
        """
        name = _rule_name(rule, key)
        certain = True
        expression = rule.get("expr")
        if not isinstance(expression, list):
            return False, {("uncertain", f"{name}, which can't be read")}
        for statement in expression:
            if not isinstance(statement, dict) or len(statement) != 1:
                return False, {("uncertain", f"{name}, which can't be read")}
            kind, value = next(iter(statement.items()))
            if kind == "match":
                result = _evaluate_match(value, packet, hook)
                if result is False:
                    return False, set()
                if result is None:
                    certain = False
                continue
            if kind in _PASSIVE_STATEMENTS:
                continue
            verdict = self._apply_statement(kind, value, name, key, packet, hook, memo, depth)
            if verdict is None:
                # An unknown statement or limit may or may not stop the rule.
                certain = False
                continue
            if not certain:
                verdict = {
                    ("uncertain", cause or f"{name}, which may match")
                    if outcome == "drop"
                    else (outcome, cause)
                    for outcome, cause in verdict
                }
            return certain, verdict
        return False, set()

    def _apply_statement(self, kind, value, name, key, packet, hook, memo, depth):
        """Apply a statement that may end evaluation of the rule.

        Returns:
            A set of outcomes, or None for a statement with no known verdict.
        """
        if kind == "accept":
            return {("accept", None)}
        if kind in ("drop", "reject"):
            return {("drop", name)}
        if kind in _REDIRECTING_NAT_STATEMENTS:
            return {("drop", f"{name}, which redirects it")}
        if kind in _ACCEPTING_NAT_STATEMENTS:
            return {("accept", None)}
        if kind == "return":
            return {("return", None)}
        if kind in ("jump", "goto"):
            target = value.get("target") if isinstance(value, dict) else None
            subchain = (key[0], key[1], target)
            return self._walk(subchain, packet, hook, memo, depth + 1)
        if kind in ("limit", "quota", "continue"):
            return None
        return {("uncertain", f"{name}, which can't be checked")}


def _is_jump(rule):
    """Report whether a rule's verdict is a jump, which can come back.

    Returns:
        True if the rule's last statement is `jump`.
    """
    expression = rule.get("expr")
    return isinstance(expression, list) and bool(expression) and isinstance(expression[-1], dict) and "jump" in expression[-1]


def _evaluate_match(match, packet, hook):
    """Evaluate one match statement.

    Returns:
        True or False, or None if it can't be determined.
    """
    if not isinstance(match, dict):
        return None
    op = match.get("op")
    if op not in ("==", "!=", "in"):
        return None
    left = match.get("left")
    if not isinstance(left, dict) or len(left) != 1:
        return None
    result = _evaluate_left(left, match.get("right"), packet, hook)
    if result is None or op != "!=":
        return result
    return not result


def _evaluate_left(left, right, packet, hook):
    """Compare what a match reads from the packet against its expected value.

    Returns:
        True or False, or None if it can't be determined.
    """
    if "payload" in left:
        return _evaluate_payload(left["payload"], right, packet)
    if "meta" in left:
        key = left["meta"].get("key") if isinstance(left["meta"], dict) else None
        if key == "l4proto":
            return _in_values(right, "tcp", 6)
        if key in ("iifname", "iif"):
            if hook in _OUTBOUND_HOOKS:
                return False
            return _interface_matches(right, packet.input_interface)
        if key in ("oifname", "oif"):
            if hook in _INBOUND_HOOKS:
                return False
            return _interface_matches(right, packet.output_interface)
        return None
    if "ct" in left:
        key = left["ct"].get("key") if isinstance(left["ct"], dict) else None
        return _in_values(right, packet.state) if key == "state" else None
    return None


def _evaluate_payload(payload, right, packet):
    """Compare a packet header field against an expected value.

    Returns:
        True or False, or None if it can't be determined.
    """
    if not isinstance(payload, dict):
        return None
    protocol = payload.get("protocol")
    field = payload.get("field")
    if protocol in ("ip", "ip6"):
        if (protocol == "ip") != (packet.version == 4):
            return False
        if field in ("saddr", "daddr"):
            value = packet.source if field == "saddr" else packet.destination
            return _address_matches(right, value)
        if field in ("protocol", "nexthdr"):
            return _in_values(right, "tcp", 6)
        return None
    if protocol in ("udp", "icmp", "icmpv6", "sctp", "udplite", "dccp"):
        return False
    if protocol in ("tcp", "th") and field in ("sport", "dport"):
        value = packet.source_port if field == "sport" else packet.destination_port
        return _port_matches(right, value)
    return None


def _in_values(right, *values):
    """Compare a literal or set against known values, such as `tcp` and `6`.

    Returns:
        True or False, or None if the expected value's shape is unknown.
    """
    items = _set_items(right)
    if items is None or any(isinstance(item, dict) for item in items):
        return None
    if any(isinstance(item, str) and item.startswith("@") for item in items):
        return None
    return any(item in values for item in items)


def _interface_matches(right, interface):
    """Compare an interface match against the packet's interface, if known.

    Only `lo` is known by name. A connection known not to use loopback doesn't
    match `lo`, but could match any other name.

    Returns:
        True or False, or None if it can't be determined.
    """
    items = _set_items(right)
    if items is None or not all(isinstance(item, str) for item in items):
        return None
    if any(item.startswith("@") or item.endswith("*") for item in items):
        return None
    if interface is not None:
        return interface in items
    return None if any(item != "lo" for item in items) else False


def _address_matches(right, address):
    """Compare an address match against the packet's address, if known.

    Returns:
        True or False, or None if it can't be determined.
    """
    if address is None:
        return None
    items = _set_items(right)
    if items is None:
        return None
    results = [_address_item_matches(item, address) for item in items]
    if any(result is True for result in results):
        return True
    return None if any(result is None for result in results) else False


def _address_item_matches(item, address):
    """Compare one address, prefix, or range against an address.

    Returns:
        True or False, or None for any other shape.
    """
    try:
        if isinstance(item, str):
            if item.startswith("@"):
                return None
            return ipaddress.ip_address(item) == address
        if isinstance(item, dict) and isinstance(item.get("prefix"), dict):
            network = ipaddress.ip_network(f"{item['prefix']['addr']}/{item['prefix']['len']}", strict=False)
            return address.version == network.version and address in network
        if isinstance(item, dict) and isinstance(item.get("range"), list) and len(item["range"]) == 2:
            low, high = (ipaddress.ip_address(bound) for bound in item["range"])
            return address.version == low.version and low <= address <= high
    except (KeyError, TypeError, ValueError):
        return None
    return None


def _port_matches(right, port):
    """Compare a port match against the packet's port, or a temporary port.

    Returns:
        True or False, or None if it can't be determined.
    """
    items = _set_items(right)
    if items is None:
        return None
    results = [_port_item_matches(item, port) for item in items]
    if any(result is True for result in results):
        return True
    return None if any(result is None for result in results) else False


def _port_item_matches(item, port):
    """Compare one port or range against a port, or a temporary port if None.

    Returns:
        True or False, or None for a temporary port the item could include, or
        for any other shape, such as a service name.
    """
    if isinstance(item, int) and not isinstance(item, bool):
        low, high = item, item
    elif isinstance(item, dict) and isinstance(item.get("range"), list) and len(item["range"]) == 2:
        low, high = item["range"]
        if not all(isinstance(bound, int) and not isinstance(bound, bool) for bound in (low, high)):
            return None
    else:
        return None
    if port is None:
        return False if high < _LOWEST_TEMPORARY_PORT else None
    return low <= port <= high


def _set_items(right):
    """List the values in a match's right-hand side.

    Returns:
        A list of values. nftables lists sets as `{"set": [...]}` or a plain
        list, and a single value on its own.
    """
    if isinstance(right, dict) and "set" in right:
        return right["set"] if isinstance(right["set"], list) else None
    if isinstance(right, list):
        return right
    return [right]


def _as_list(value):
    """Wrap a value that nftables lists either alone or in a list.

    Returns:
        A list.
    """
    return value if isinstance(value, list) else [value]


def _family_applies(family, version):
    """Report whether a table family sees packets of an IP version.

    Returns:
        True if the family handles that version.
    """
    return family == "inet" or (family == "ip" and version == 4) or (family == "ip6" and version == 6)


def _priority(chain):
    """Read a chain's priority.

    Returns:
        The integer priority, or 0 if it isn't numeric.
    """
    priority = chain.get("prio")
    return priority if isinstance(priority, int) and not isinstance(priority, bool) else 0


def _chain_name(key):
    """Name a chain for messages.

    Returns:
        Text such as "inet filter input".
    """
    return " ".join(str(part) for part in key)


def _rule_name(rule, key):
    """Name a rule for messages.

    Returns:
        Text such as "rule 12 in inet filter input".
    """
    return f"rule {rule.get('handle', '?')} in {_chain_name(key)}"
