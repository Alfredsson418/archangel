"""Compare the connection check with real connections in a network namespace.

Mocks can't prove what nftables does, so this applies real rulesets and makes
real TCP connections, then requires the check to agree. It never touches the
host's firewall, but only run it through the isolating command in docs/test.md:

    unshare -rn dashboard/.venv/bin/python dashboard/tests/integration/connection_check_namespace.py

The script refuses to run unless it is root inside a new user namespace.
"""
import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from webapp.connection_check import (  # noqa: E402
    COULD_BLOCK,
    NO_CHANGE,
    WILL_BLOCK,
    Connection,
    check_connection,
)


API_PORT = 18080
OTHER_PORT = 18081
SERVER = "10.99.0.1"
CLIENT = "10.99.0.2"
PEER_NAMESPACE_TIMEOUT = 600
INPUT = "type filter hook input priority 0"
OUTPUT = "type filter hook output priority 0"
ALL = ("remote", "loopback")


def run(command, **kwargs):
    return subprocess.run(command, shell=True, check=True, capture_output=True, text=True, **kwargs)


def require_isolation():
    """Refuse to run outside a user and network namespace of our own."""
    uid_map = Path("/proc/self/uid_map").read_text().split()
    if os.geteuid() != 0 or uid_map[:3] == ["0", "0", "4294967295"]:
        sys.exit("Run this through unshare -rn, as described in docs/test.md.")


def ruleset(body):
    return "flush ruleset\n" + body


def table(*chains, family="inet", name="t"):
    return f"table {family} {name} {{\n" + "\n".join(chains) + "\n}\n"


def chain(name, spec, *rules, policy=None):
    header = f"{spec}; policy {policy};" if policy else (f"{spec};" if spec else "")
    return f"chain {name} {{\n{header}\n" + "\n".join(rules) + "\n}"


def scenarios():
    """List rulesets with the result expected for each kind of client.

    The check doesn't know the server's own address or which interface a remote
    client uses, so those give "could block" rather than a definite answer.
    """
    drop = "policy drop"
    return [
        ("no rules", "", {"remote": NO_CHANGE, "loopback": NO_CHANGE}),
        ("accept policy", table(chain("c", INPUT, policy="accept")), {"remote": NO_CHANGE, "loopback": NO_CHANGE}),
        ("drop policy, no rules", table(chain("c", INPUT, policy="drop")), {"remote": WILL_BLOCK, "loopback": WILL_BLOCK}),
        (
            "drop policy, API allowed",
            table(chain("c", INPUT, f"tcp dport {API_PORT} accept", policy="drop")),
            # On loopback, replies also pass the input hook, to a temporary port.
            {"remote": NO_CHANGE, "loopback": WILL_BLOCK},
        ),
        (
            "drop policy, other port allowed",
            table(chain("c", INPUT, f"tcp dport {OTHER_PORT} accept", policy="drop")),
            {"remote": WILL_BLOCK, "loopback": WILL_BLOCK},
        ),
        (
            "drop policy, only established allowed",
            table(chain("c", INPUT, "ct state established,related accept", policy="drop")),
            {"remote": WILL_BLOCK, "loopback": WILL_BLOCK},
        ),
        (
            "default-deny done properly",
            table(chain("c", INPUT, "ct state established,related accept", f"tcp dport {API_PORT} ct state new accept", policy="drop")),
            {"remote": NO_CHANGE, "loopback": NO_CHANGE},
        ),
        (
            "drop rule on the API port",
            table(chain("c", INPUT, f"tcp dport {API_PORT} drop")),
            {"remote": WILL_BLOCK, "loopback": WILL_BLOCK},
        ),
        (
            "reject rule on the API port",
            table(chain("c", INPUT, f"tcp dport {API_PORT} reject")),
            {"remote": WILL_BLOCK, "loopback": WILL_BLOCK},
        ),
        ("drop rule on another port", table(chain("c", INPUT, f"tcp dport {OTHER_PORT} drop")), {"remote": NO_CHANGE, "loopback": NO_CHANGE}),
        ("drop rule for UDP", table(chain("c", INPUT, f"udp dport {API_PORT} drop")), {"remote": NO_CHANGE, "loopback": NO_CHANGE}),
        (
            "accept above drop",
            table(chain("c", INPUT, f"tcp dport {API_PORT} accept", f"tcp dport {API_PORT} drop")),
            {"remote": NO_CHANGE, "loopback": NO_CHANGE},
        ),
        (
            "drop above accept",
            table(chain("c", INPUT, f"tcp dport {API_PORT} drop", f"tcp dport {API_PORT} accept")),
            {"remote": WILL_BLOCK, "loopback": WILL_BLOCK},
        ),
        (
            "drop the client's address",
            table(chain("c", INPUT, f"ip saddr {CLIENT} drop", "ip saddr 127.0.0.1 drop")),
            {"remote": WILL_BLOCK, "loopback": WILL_BLOCK},
        ),
        (
            "drop the client's subnet",
            table(chain("c", INPUT, "ip saddr 10.99.0.0/24 drop", "ip saddr 127.0.0.0/8 drop")),
            {"remote": WILL_BLOCK, "loopback": WILL_BLOCK},
        ),
        ("drop another subnet", table(chain("c", INPUT, "ip saddr 192.0.2.0/24 drop")), {"remote": NO_CHANGE, "loopback": NO_CHANGE}),
        (
            "drop everything except the client",
            table(chain("c", INPUT, f"ip saddr != {{ {CLIENT}, 127.0.0.1 }} drop")),
            {"remote": NO_CHANGE, "loopback": NO_CHANGE},
        ),
        ("drop all IPv4 in an ip table", table(chain("c", INPUT, policy="drop"), family="ip"), {"remote": WILL_BLOCK, "loopback": WILL_BLOCK}),
        ("drop policy in an ip6 table", table(chain("c", INPUT, policy="drop"), family="ip6"), {"remote": NO_CHANGE, "loopback": NO_CHANGE}),
        (
            "jump to a chain that drops",
            table(chain("c", INPUT, "jump d"), chain("d", "", f"tcp dport {API_PORT} drop")),
            {"remote": WILL_BLOCK, "loopback": WILL_BLOCK},
        ),
        (
            "jump comes back to an accept above a drop policy",
            table(chain("c", INPUT, "jump d", f"tcp dport {API_PORT} accept", policy="drop"), chain("d", "", "tcp dport 1 drop")),
            {"remote": NO_CHANGE, "loopback": WILL_BLOCK},
        ),
        (
            "goto ends at the base chain's drop policy",
            table(chain("c", INPUT, "goto d", f"tcp dport {API_PORT} accept", policy="drop"), chain("d", "", "tcp dport 1 drop")),
            {"remote": WILL_BLOCK, "loopback": WILL_BLOCK},
        ),
        (
            "second base chain drops after the first accepts",
            table(chain("a", "type filter hook input priority -10", "accept"), chain("b", "type filter hook input priority 10", policy="drop")),
            {"remote": WILL_BLOCK, "loopback": WILL_BLOCK},
        ),
        (
            "dormant table",
            "table inet t {\nflags dormant;\n" + chain("c", INPUT, policy="drop") + "\n}\n",
            {"remote": NO_CHANGE, "loopback": NO_CHANGE},
        ),
        (
            "output policy drop",
            table(chain("c", OUTPUT, policy="drop")),
            {"remote": WILL_BLOCK, "loopback": WILL_BLOCK},
        ),
        (
            "output drops replies from the API port",
            table(chain("c", OUTPUT, f"tcp sport {API_PORT} drop")),
            {"remote": WILL_BLOCK, "loopback": WILL_BLOCK},
        ),
        (
            "only loopback allowed",
            table(chain("c", INPUT, 'iifname "lo" accept', policy="drop")),
            {"remote": WILL_BLOCK, "loopback": NO_CHANGE},
        ),
        (
            "loopback dropped",
            table(chain("c", INPUT, 'iifname "lo" drop')),
            {"remote": NO_CHANGE, "loopback": WILL_BLOCK},
        ),
        (
            "output interface matched on an input hook never applies",
            table(chain("c", INPUT, 'oifname "lo" drop')),
            {"remote": NO_CHANGE, "loopback": NO_CHANGE},
        ),
        (
            "redirect the API port elsewhere",
            table(chain("c", "type nat hook prerouting priority dstnat", f"tcp dport {API_PORT} redirect to :{OTHER_PORT}")),
            {"remote": WILL_BLOCK, "loopback": NO_CHANGE},
        ),
        (
            "redirect locally generated traffic elsewhere",
            table(chain("c", "type nat hook output priority -100", f"tcp dport {API_PORT} redirect to :{OTHER_PORT}")),
            {"remote": NO_CHANGE, "loopback": WILL_BLOCK},
        ),
        (
            "drop a range of temporary ports",
            table(chain("c", INPUT, "tcp sport 32768-65535 drop")),
            {"remote": COULD_BLOCK, "loopback": COULD_BLOCK},
        ),
        (
            "named set containing the port",
            "table inet t {\nset s { type inet_service; elements = { " + str(API_PORT) + " }; }\n" + chain("c", INPUT, "tcp dport @s drop") + "\n}\n",
            {"remote": COULD_BLOCK, "loopback": COULD_BLOCK},
        ),
        (
            "rate limit on the API port",
            table(chain("c", INPUT, f"tcp dport {API_PORT} limit rate over 1000/second drop")),
            {"remote": COULD_BLOCK, "loopback": COULD_BLOCK},
        ),
        (
            "interface the check can't identify",
            table(chain("c", INPUT, 'iifname "nosuch0" drop')),
            {"remote": COULD_BLOCK, "loopback": NO_CHANGE},
        ),
    ]


def serve(port, reply, stop):
    """Answer each connection, so that a client can prove both directions work."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen()
    listener.settimeout(0.1)
    while not stop.is_set():
        try:
            connection, _ = listener.accept()
        except OSError:
            continue
        with connection:
            connection.settimeout(1)
            try:
                if connection.recv(4):
                    connection.sendall(reply)
            except OSError:
                pass
    listener.close()


CLIENT_CODE = (
    "import socket,sys\n"
    "s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=1)\n"
    "s.settimeout(1);s.sendall(b'ping')\n"
    "sys.exit(0 if s.recv(4)==b'pong' else 1)\n"
)


def can_connect(kind, peer):
    """Make a real connection and prove traffic passes in both directions.

    Returns:
        True if the exchange succeeded.
    """
    if kind == "remote":
        command = ["nsenter", "-t", str(peer), "-n", sys.executable, "-I", "-c", CLIENT_CODE, SERVER, str(API_PORT)]
    else:
        command = [sys.executable, "-I", "-c", CLIENT_CODE, "127.0.0.1", str(API_PORT)]
    return subprocess.run(command, capture_output=True).returncode == 0


def apply_ruleset(body):
    subprocess.run(["nft", "-f", "-"], input=ruleset(body), text=True, check=True, capture_output=True)


def listing():
    return json.loads(run("nft -j list ruleset").stdout)


def main():
    require_isolation()
    run("ip link set lo up")
    peer = subprocess.Popen(["unshare", "-n", "sleep", str(PEER_NAMESPACE_TIMEOUT)])
    stop = threading.Event()
    try:
        # Give the peer time to enter its namespace before moving an interface.
        for _ in range(50):
            if os.readlink(f"/proc/{peer.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                break
            threading.Event().wait(0.05)
        run(f"ip link add veth0 type veth peer name veth1 netns {peer.pid}")
        run(f"ip addr add {SERVER}/24 dev veth0 && ip link set veth0 up")
        run(
            f"nsenter -t {peer.pid} -n sh -c "
            f"'ip link set lo up && ip addr add {CLIENT}/24 dev veth1 && ip link set veth1 up'"
        )
        # The other port answers differently, so that a client redirected to it
        # doesn't count as having reached the API.
        for port, reply in ((API_PORT, b"pong"), (OTHER_PORT, b"nope")):
            threading.Thread(target=serve, args=(port, reply, stop), daemon=True).start()

        connections = {"remote": Connection(CLIENT, API_PORT), "loopback": Connection("127.0.0.1", API_PORT)}
        apply_ruleset("")
        empty = listing()
        failures = 0
        for name, body, expected in scenarios():
            apply_ruleset(body)
            after = listing()
            for kind in ALL:
                check = check_connection(empty, after, connections[kind])
                connected = can_connect(kind, peer.pid)
                # A definite verdict must match reality. "Could block" is a
                # warning about something the check can't see, so it may go
                # either way; only the expected status is required.
                agrees = (
                    check.status == expected[kind]
                    and not (check.status == WILL_BLOCK and connected)
                    and not (check.status == NO_CHANGE and not connected)
                )
                print(
                    f"{'ok  ' if agrees else 'FAIL'} {kind:8} {name}: check={check.status} "
                    f"connected={connected} causes={list(check.causes)}"
                )
                failures += not agrees
        print(f"{failures} failures")
        return 1 if failures else 0
    finally:
        stop.set()
        peer.kill()
        peer.wait()


if __name__ == "__main__":
    sys.exit(main())
