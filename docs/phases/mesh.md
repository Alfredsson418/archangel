# Mesh Network Design

**Status: Accepted. Nothing in this document is implemented.** It describes how an Archangel mesh should look and behave, and how to build it in stages. It does not change the current [security posture](../security-concerns.md). The [roadmap](../roadmap.md#mesh-network) tracks its progress.

## Scope

The mesh connects separated network zones through audited, encrypted gateways, managed from one place.

- **Isolated networks first.** The mesh works with no internet connection and no external services.
- **Central audit.** Traffic between zones passes through a central site, so one place records who talked to whom.
- **Scalable center.** The central site can grow from one host to several without changing how zones connect.
- **Optional internet access.** Selected zones can reach the internet through the central site, and this stays off until explicitly enabled.
- **Stages that work on their own.** The management mesh is useful before tunnels exist, and tunnels are useful before the central site scales.

These are not goals for the first release: nodes roaming behind NAT, relays, decrypting traffic, endpoint agents, or non-Linux nodes.

## Starting point

These facts from the current code shape the design:

| Fact | Consequence |
| --- | --- |
| Each backend manages only its own host, and the dashboard talks to one configured API. | A controller role is new, and the dashboard needs only that one connection. |
| Rule changes take effect immediately with no automatic rollback, and rules are identified by host-specific handles. | Safe remote changes need atomic apply, rollback, and stable rule IDs first. See M0 in [Verification](#verification). |
| The API authenticates users, and native TLS verifies only the server. | Nodes need their own identity and a separate mTLS listener. |
| Audit logs are local files that aren't tamper-evident, and MFA is deferred. | Central audit and the emergency override must add both. |
| The dashboard must not contain passthrough routes or backend identities. | The dashboard calls only the controller, never other nodes. |

## Behavior

### Overview

```text
                 Operator browser
                        |
                    Dashboard
                        |  operator API (existing login and roles)
 +----------------------v-----------------------------------------+
 |  CENTRAL SITE                                                  |
 |                                                                |
 |  Controller              Log collector                         |
 |  - inventory, policy     - flow and audit records              |
 |  - issuing CA            - tamper-evident storage              |
 |  - signed configuration                                        |
 |        ^                        ^                              |
 |        | control (mTLS)         | records (mTLS)               |
 |  ......|........................|.........................     |
 |        |                        |                              |
 |  Transit hub 1    Transit hub 2    ...    Egress gateway ------+--> Internet
 |  - forward, filter, log                   - off by default     |    (optional)
 +------^---------------^-----------------------------------------+
        |               |
        | WireGuard: every edge gateway has a tunnel to every hub
        |               |
   +----+----+     +----+----+
   | Edge    |     | Edge    |     Edge gateways enforce policy at each
   | gateway |     | gateway |     zone boundary and never tunnel directly
   | Zone A  |     | Zone B  |     to each other.
   +----+----+     +----+----+
        |               |
    Zone A hosts    Zone B hosts
```

#### Roles

Every role is the `archangel` backend with a different role set in its runtime configuration. A small or lab deployment may run several roles on one host, but production deployments should split them as described below.

| Role | Does | Holds | If compromised |
| --- | --- | --- | --- |
| **Controller** | Stores inventory and policy, issues certificates, publishes signed configuration, serves the dashboard's API. | Issuing CA key, configuration signing key, operator accounts. | Attacker can change policy and admit nodes. This is the highest-value target. |
| **Transit hub** | Terminates tunnels, forwards traffic between zones, enforces policy, produces flow records. | Its own keys. No CA or signing key. | Attacker can read and alter traffic that is unencrypted inside the tunnels, and can suppress its own records. |
| **Egress gateway** | Connects selected zones to the internet with NAT. | Its own keys. | Attacker has a path between the internet and the mesh. Keep it separate from the controller. |
| **Log collector** | Receives and stores records from every node. | Audit history. | Attacker can read traffic metadata. Tampering is detectable. |
| **Edge gateway** | Enforces policy at a zone boundary and sends inter-zone traffic to the hubs. This is the Edge Gateway role from [goal.md](../goal.md). | Its own keys. | Attacker controls that zone's boundary, but other zones still enforce their own policy. |
| **Resource gateway** | Protects one resource using the edge gateway's mechanisms. Added late; see M8. | Its own keys. | Attacker controls access to that resource. |

The controller must not carry traffic. The transit role is exposed to every zone's traffic, and the thesis's separation of control plane and data plane exists to keep that exposure away from the keys that control the whole network.

### Traffic between two zones

A host in Zone A connects to a host in Zone B:

1. The Zone A edge gateway checks policy and drops the packet if no rule allows it.
2. It selects the hub assigned to the pair of zones (see [Scaling](#scaling-the-central-site)) and sends the packet through that hub's tunnel.
3. The hub decrypts the packet, checks policy again, and records the flow.
4. The hub encrypts the packet into its tunnel to the Zone B edge gateway.
5. The Zone B edge gateway checks policy a third time and delivers the packet.

Checking three times is deliberate. A compromised edge gateway cannot grant itself access, because the hub and the destination still deny the traffic. Traffic inside a zone never reaches the hub.

The default is deny at every point: a newly enrolled zone can reach nothing until a policy allows it.

### Is central audit complete?

The hub model gives strong visibility, but its limits should be stated plainly in the product and documentation.

| Recorded | Not recorded |
| --- | --- |
| Source and destination addresses, ports, protocol | Traffic inside a zone, which never reaches a hub |
| Source and destination zone, and the policy that allowed or denied the flow | Contents of the traffic; hubs do not decrypt TLS or other application encryption |
| Start and end time, bytes and packets (from connection tracking) | The user or application behind a flow, until identity-aware enforcement exists |

Hubs can read traffic that isn't protected by application-level encryption, because the tunnels end there. Operators should continue to use TLS between hosts in sensitive zones.

Each edge gateway also keeps its own counters for traffic sent to each hub. Comparing them with the hub's records reveals traffic that one side claims and the other doesn't, which helps detect a compromised node.

### Audit pipeline

1. Hubs generate flow records from connection tracking events and write them to a bounded local spool.
2. They send records to the collector over mTLS. During a collector outage, records wait in the spool until it recovers.
3. Each node chains its records with hashes and periodically signs a checkpoint, so that removed or altered records are detectable. This also addresses the tamper-evident storage that Phase 2 deferred.
4. Records carry IP addresses and are privacy-sensitive: access is restricted, and retention follows the existing 30-day default unless the operator changes it.

Flow records follow the existing logging rules: no payloads, credentials, or tokens.

**No traffic passes a hub or egress gateway unrecorded.** If one can't record, for example because its spool is full, it stops forwarding all inter-zone and internet traffic, including connections already open, until recording recovers. This closes the path an attacker could otherwise use to move between zones without flow records.

- **Recovery stays possible.** Control traffic, time synchronization, and record delivery to the collector are exempt, because the node needs them to recover. They carry no zone traffic.
- **Hubs fail over.** A hub that can't record counts as failed, so its zone pairs move to the next hub in their ranking. Inter-zone traffic stops only when no hub for that pair can record.
- **Traffic inside a zone continues**, because it never reaches a hub.
- **Recovery is automatic.** Forwarding resumes once the node can record again, and the node writes the stopped period into its hash chain.

This turns a logging failure into a network outage, and a collector outage eventually fills every spool. An attacker who can fill spools can therefore cause a denial of service, though not unrecorded movement. To delay and contain this, spools are sized for the expected collector outage, alerts fire well before a spool is full, and each source zone has a limit on new flows so that one zone can't quickly fill a spool.

A future Policy Decision Point could respond to this kind of attack directly: it would detect the source of a flood and isolate that zone until an administrator reopens it, leaving other zones running. This isn't part of the build plan. Automated isolation needs its own design, because an attacker could try to trigger it against a healthy zone. Until then, alerts identify the source and an operator isolates the zone through policy.

### Emergency override

An administrator can temporarily let inter-zone traffic through without recording it, for cases where stopping the traffic is worse than the audit gap. Because this deliberately reopens that gap, it is tightly constrained:

- **Administrators only, confirmed with MFA.** Operators can't use an override. Every override requires a fresh MFA check, even in an active session. The C++ API enforces this; the dashboard only presents it.
- **Explicit risk confirmation.** The confirmation message states that traffic will pass unrecorded, that movement between zones during this period can't be investigated later, which hubs and zones are affected, and when the override ends. The administrator must enter a reason.
- **Narrow scope.** An override names specific hubs and zone pairs. Internet traffic stays blocked and can't be overridden.
- **Time-limited.** It lasts one hour by default, up to a fixed maximum. Extending it requires MFA and confirmation again. It ends early if recording recovers.
- **Recorded first.** The controller writes the override, with its administrator, reason, and scope, to its audit log before publishing it, and refuses if it can't. It reaches hubs as signed configuration with an expiry that each hub enforces itself.
- **Requires the controller.** No override is available while the controller is down.
- **Still visible.** A critical alert stays active for its whole duration, and the dashboard shows a persistent banner. Hubs mark the period in their hash chains and keep their traffic counters running.

### Alerts

Problems shouldn't go unnoticed, so every condition below raises an alert. Critical alerts stay active until an operator acknowledges them and the condition has cleared.

| Area | Alert when | Severity |
| --- | --- | --- |
| Audit | Spool passes warning thresholds, or a node can't record | Warning, then critical |
| Audit | Collector unreachable, or a node's records stop arriving | Critical |
| Audit | A hash chain fails verification, or hub and edge gateway counters disagree | Critical |
| Audit | An emergency override is active | Critical |
| Traffic | A hub, tunnel, or egress gateway is down, or a zone pair has failed over | Warning; critical if a zone is cut off |
| Traffic | A zone hits its new-flow limit, or traffic is abnormally high, which could indicate an attack | Warning |
| Traffic | A hub nears its capacity | Warning |
| Nodes | A node stops checking in, or restarts unexpectedly | Warning; critical for hubs, egress, and collector |
| Configuration | A node rolls back, rejects configuration, or stays on an old generation | Critical |
| Security | Certificate renewal keeps failing, or a CA nears expiry | Warning, then critical |
| Security | Repeated failed enrollments or rejected node certificates | Warning |
| Security | Egress is enabled, or a high-risk role is approved | Informational, always recorded |
| Health | A node's clock drifts, or its disk or memory runs low | Warning |

Alerts have to work without internet access, and the alerting system can itself fail:

- **Delivery.** Alerts appear in the dashboard and in each node's logs, and can later be sent to an operator-run service on the internal network, such as mail or a webhook.
- **Silence is an alert.** The controller treats a node that goes quiet as a problem, rather than assuming it's healthy.
- **Controller outages stay visible.** The dashboard reports when it can't reach the controller, and nodes log the loss of contact locally, so a dead controller can't hide other alerts.
- **Safe contents.** Alerts follow the logging rules and contain no credentials, tokens, or payloads.

### Internet access

Internet access weakens the isolation that is the mesh's main purpose, so it is constrained:

- **Off by default.** It is enabled per zone by a specific policy, and optionally limited to specific destinations and ports.
- **Outbound only.** The gateway uses NAT and accepts no connections from the internet. Published services are out of scope.
- **Single exit.** Edge gateways drop any traffic that would leave their zone other than through a tunnel, so a zone can't bypass the audit through a local uplink.
- **Separate from the controller.** The egress gateway is its own host or at least its own network namespace, and the controller has no route to the internet.
- **Kill switch.** One operator action, or a local command at the central site if the controller is down, stops all egress at once.
- **Audited.** The same flow records apply. DNS is served by a resolver at the central site, so that names can also be logged and DNS can't be used to tunnel out unnoticed. This needs a decision, since DNS is otherwise out of scope.

A network with an egress gateway enabled should not be described as air-gapped. The dashboard shows this state prominently, and truly air-gapped deployments can build without the egress role.

### Joining the mesh

1. An operator creates a node in the dashboard, choosing its name, role, and zone. The controller returns a one-time enrollment token.
2. The token contains a random secret and the fingerprint of the mesh's CA. The fingerprint lets the new node verify the controller on first contact, so it doesn't have to trust the network. Only a hash of the secret is stored, and it follows the existing setup-token rules: 256-bit, single use, one-hour expiry, shown once.
3. On the new node, a privileged CLI command reads the token interactively. The token is never passed as a command-line argument.
4. The node generates its own TLS and WireGuard keys. Private keys never leave the node.
5. The node sends a certificate request and its WireGuard public key. The name, role, and zone come from the token record, and nothing the node asks for can widen them.
6. **Hub, egress, and collector nodes also require explicit operator approval**, because they carry or store other zones' traffic data. Edge gateways can be configured to require it too.
7. The controller issues a certificate, and the node starts pulling configuration. The token is then useless.

### Applying a change

Nodes pull configuration from the controller rather than the controller pushing to nodes. Nodes then need no open management port, and zones with strict outbound-only rules still work.

1. An operator edits policy. The dashboard shows the exact effect per zone and requires confirmation, following the same pattern [Phase 3](phase-3.md#list-of-changes) establishes. Control traffic, tunnels to hubs, record delivery, and time synchronization join the [management connections](phase-3.md#connection-warning) it checks, so a change that could cut any of them off is flagged as a **MANAGEMENT RISK**.
2. The controller validates the policy, gives it a new increasing generation number, and signs it.
3. Each node picks it up within a short polling interval. It rejects anything with a bad signature, an older generation, or a role change.
4. **The node compiles structured policy into nftables rules locally.** The controller never sends native firewall commands, which keeps the existing rule against raw commands and limits what a compromised controller can express.
5. The node saves its current state, applies the new one as a single nftables transaction, and tests that it can still reach the controller and its hubs.
6. If those checks don't pass within the confirmation window, the node restores the previous state automatically. This protects against a rule that cuts off the node's own management path.
7. The node reports its result. The dashboard shows each node as current, applying, rolled back, or unreachable, and never reports a change as successful until the node has confirmed it.

Rollouts can be staged: apply to one zone, wait, then continue, and stop automatically if a node rolls back.

Mesh rules live in their own nftables table with stable IDs. Rules that a local administrator added stay untouched, in line with the existing `archangel-managed` separation.

### Revoking a node

An operator disables a node. The controller publishes a new generation that removes the node's WireGuard key from every hub, and refuses to renew its certificate. Because all inter-zone traffic goes through the hubs, the node is cut off as soon as the hubs apply that generation, without waiting for its certificate to expire. This is a real benefit of the hub design.

### When things fail

| Failure | What happens | Operator sees |
| --- | --- | --- |
| Controller down | Traffic continues. Nodes keep enforcing their last valid configuration. No policy changes or enrollments are possible. | Controller unreachable; nodes report when it returns. |
| One hub down | Edge gateways move the affected zone pairs to the next hub within seconds. Existing connections drop unless connection state is synchronized. | Hub down, reduced capacity. |
| All hubs down | Inter-zone traffic stops and traffic inside each zone continues. Zones are isolated, which is the safe direction. | Critical alert. |
| Log collector down | Traffic continues while hubs spool their records and send them later. If the outage outlasts the spools, the row below applies. | Collector down, spool usage and time remaining per hub. |
| Hub or egress spool full | That node stops forwarding all zone traffic, including open connections. Zone pairs move to another hub that can still record. See [Audit pipeline](#audit-pipeline). | Critical audit failure, with affected zones and the stopped period. |
| Egress gateway down | Internet access stops and internal traffic is unaffected. | Egress down. |
| Edge gateway down | With one edge gateway, that zone is disconnected from the others. A zone with the optional second gateway fails over to it. | Node unreachable. |
| Bad policy pushed | Nodes that lose connectivity roll back on their own, and a staged rollout stops. | Rolled back, with the generation and the failed check. |
| Node reboots | It restores its last valid configuration before the network comes up, or a deny-all baseline if none is valid. See [Design choices](#design-choices). | Node back, with its generation. |
| Clock drift | Certificates can appear invalid, which isn't unusual in isolated networks. The central site provides NTP over the mesh, and drift raises an alert. | Time drift warning. |
| Certificate expires during a long outage | Tunnels keep working because they use WireGuard keys, not certificates. On return, a recently expired, unrevoked node can renew with its old certificate within a grace period. | Renewed after outage. |
| Node compromised | Revoke it as above. Its certificate alone gives it no access to other zones, and all three policy checks still apply. | Audit mismatch, if detected. |
| Controller compromised | The attacker can change policy and admit nodes. Nodes refuse role changes and record every generation they apply. Recovery means rotating the issuing CA from the offline root and re-enrolling. | Unexpected generations in node-side logs. |

### Scaling the central site

**Hub-routed traffic can scale across multiple instances**, as long as one requirement holds: both directions of a connection must use the same hub. Hubs are stateful firewalls and audit points, so a connection split across two hubs would be dropped or recorded incorrectly.

The design meets this requirement without a load balancer:

1. Each edge gateway has a separate WireGuard interface to each hub. It needs one per hub because WireGuard routes a given address range to only one peer per interface.
2. The controller ranks hubs for each **unordered zone pair** with a stable hash, and includes the ranking in signed configuration.
3. Zone A and Zone B each compute the same first choice for the pair A–B, so both directions use the same hub.
4. If a hub fails, gateways on both sides move to the next hub in the ranking, without needing the controller.

Adding a hub moves only a small share of zone pairs. Egress traffic is pinned the same way, per zone.

This scales per zone pair rather than per connection, so one very busy pair is limited to one hub's capacity. That's an acceptable limit for a first version.

Scaling comes in three steps:

| Step | Setup | Provides | Limit |
| --- | --- | --- | --- |
| 1 | One hub | Full function | Single point of failure; zones isolated if it fails. |
| 2 | Two hubs, one active | Failover | Half the hardware sits idle. Connections drop on failover unless `conntrackd` synchronizes their state. |
| 3 | Several active hubs | Failover and more capacity | Rankings, health checks, and rebalancing all have to work. |

Known hazards to test:

- **Partial failure:** Zone A can reach only hub 1 and Zone B only hub 2. Each side would follow its own ranking and the pair would break. Links between hubs at the central site can fix this, at the cost of some added routing.
- **Flapping:** an unstable hub could cause repeated moves, so returning to a recovered hub requires a stable period.
- **Consistent policy:** hubs may briefly run different generations during a rollout. Each zone pair uses one hub, so a single connection still sees one consistent policy.

The controller scales differently, because its availability isn't needed for traffic. It starts as one instance with encrypted backups and a warm standby promoted by an operator. The existing SQLite storage suits this. Automatic controller failover would require a replicated database and isn't worth the complexity until there's a demonstrated need.

### Security model

#### Trust hierarchy

```text
Offline root CA (kept off the network; used rarely)
    `-- Issuing CA (on the controller; replaceable if the controller is compromised)
            `-- Node certificates (short-lived; renewed automatically)

Configuration signing key (on the controller; separate from the issuing CA)
Operator accounts (existing roles; separate from node identity)
```

| Item | Proposed | Why |
| --- | --- | --- |
| Node certificate lifetime | 7 days, renewed at half-life | Long enough to survive ordinary outages in an isolated network, short enough to limit exposure. |
| Control traffic | mTLS, TLS 1.3 only, on a dedicated listener | Node and operator APIs have different trust and shouldn't share a port. |
| Tunnels | WireGuard | Small, in the Linux kernel, and has no cipher negotiation. |
| WireGuard keys | Generated on each node, rotated regularly through signed configuration, with a pre-shared key per link | Pre-shared keys add a second secret, and some protection against future cryptographic breaks. |
| CA key protection | Owner-only files at first; hardware key support later | Follows the existing protected-file checks. |

#### Authorization

- **Node certificates and operator sessions never substitute for each other.** A node certificate can't call the operator API, and an operator session can't call the node API.
- **Each node API call is limited to that node's own identity.** A node can fetch only its own configuration and report only its own status.
- **Every node enforces locally.** The central role doesn't replace each backend's enforcement, as [architecture.md](../architecture.md) requires.
- **New operator permissions.** Viewers can see the mesh, operators can change policy and enroll and revoke nodes, and administrators can change the CA, enable egress, and use the MFA-confirmed [emergency override](#emergency-override).
- **Limits on the controller.** A node refuses a role change it didn't enroll with, so a compromised controller can't quietly make an edge gateway into a transit hub. Requiring two people to approve high-risk changes is a possible later addition.

## Design choices

All of these were agreed with the developer on 2026-11-02.

| Choice | Why | Rejected alternative |
| --- | --- | --- |
| **Management mesh first, then tunnels** | Each stage is usable on its own, and tunnels reuse the same identities. | Building tunnels first, or the full thesis architecture at once. |
| **All inter-zone traffic through central hubs** | Gives one place for audit and policy, and revoking a node takes effect at the hubs. Hubs can be scaled, as described in [Scaling](#scaling-the-central-site). | Direct links between zones, which would leave no central audit point. Decentralized control, which is much harder to build and reason about. |
| **Built-in private CA** | Self-contained for isolated networks, and supports revocation. A compromised controller could admit nodes, so an offline root limits recovery cost. | Pinned peer keys, where rotation and revocation are manual. External PKI, which adds a required service. |
| **Isolated networks as the primary target** | This is the ideal use case. Internet access through the central site is optional and off by default. | Roaming nodes behind NAT, which need traversal and relays. |
| **WireGuard for tunnels** | Small, in the Linux kernel, and has no cipher negotiation. There is no requirement for specific or certified cryptography. | IPsec, which isn't planned. |
| **Enrolled nodes restore state at boot** | A node that boots with no rules would be an open path, so it restores its last signed configuration through a separate early-boot unit, or a deny-all baseline if none is valid. This isn't a firewall bundle import: it applies signed, structured policy to the mesh's own table, and starting or restarting the service still doesn't change the firewall. When implemented, describe it in `AGENTS.md` and the [architecture](../architecture.md) so that neither mechanism is mistaken for the other. | Booting without rules until the controller is reachable. |
| **The transit hub is the Segmentation Gateway, in this repository** | It shares identity, policy, and enforcement code. Recorded in [goal.md](../goal.md). | A separate project. |
| **Stop all zone traffic when a node can't record** | Nothing crosses a hub unrecorded, closing a path for unaudited movement between zones. A logging failure can therefore become a network outage. See [Audit pipeline](#audit-pipeline). | Allowing inter-zone traffic unrecorded with an alert. Blocking only internet traffic. |
| **MFA-confirmed emergency override** | Stopping traffic can be worse than an audit gap, so administrators can make a narrow, temporary exception with a risk confirmation. Requires MFA, which Phase 2 deferred, so MFA moves into M5. See [Emergency override](#emergency-override). | No override, which invites someone to change the firewall by hand with no record. |
| **TOTP as the first MFA method** | Needs no internet or special hardware, though it depends on the mesh's time synchronization. Recovery from a lost device must be designed with M5. | Hardware security keys first; these could follow. |
| **No override while the controller is down** | The override's MFA check and signing both depend on the controller. If recording and the controller fail together, restoring inter-zone traffic means changing hubs by hand. The standby in M8 reduces this risk. | A local override on hubs, which would bypass those checks. |
| **Automated attack response left to a future Policy Decision Point** | It could isolate a zone until an administrator reopens it, but needs its own design. Alerts and manual isolation cover this until then. | Automatic isolation in the first version. |
| **Reject overlapping zone address ranges in the first version** | Zones keep their routed prefixes, so those with overlapping ranges must be renumbered to join. | NAT between zones, which would complicate both policy and audit. |
| **Operators manage the firewall and nodes, with two exceptions for administrators** | Enabling internet egress weakens the network's isolation, and the emergency override allows unrecorded traffic, so both are limited to administrators. Administrators also manage users and the underlying backend, and keep the firewall access they have today. | Letting operators enable egress or use the override. |
| **Combined controller and hub in labs only** | A hub compromise on a combined host also exposes the CA, so it carries a visible warning, and production documentation describes split roles. | Allowing it in production. |
| **Minimal DNS resolver at the central site, added with M6** | Without it, DNS is an unaudited path out of the mesh. | Leaving DNS to zones. |
| **Optional second edge gateway per zone** | One is the default. Support arrives with M8, and data structures allow for it from the start. Hub ranking and failover must work the same either way. | Requiring two, or leaving redundancy out. |

## Code changes

These changes respect the existing boundaries in [architecture.md](../architecture.md):

| Area | Change |
| --- | --- |
| `backend/{include,src}/mesh/` | New `Mesh` namespace: enrollment, certificate handling, signed configuration, policy compiler, and the apply-and-confirm loop. |
| `Mesh::TunnelProvider` | Contract with a WireGuard implementation in `mesh/providers/`. Justified because tunnel changes are privileged host operations that ordinary tests must replace with a fake, not by a planned second tunnel technology. |
| `Firewall::` | New optional capability in the style of `Firewall::BundleProvider`, for atomically applying a compiled ruleset and restoring the previous one. It builds on the existing transaction planning in `nft_import`. |
| `backend/src/http/server.cpp` | Registers both route groups, with handlers in `http/api/`: operator routes under `/api/v1/mesh/`, and node routes such as `/mesh/v1/enroll`, `/renew`, `/config`, `/status`, and `/records`. |
| `backend/src/http/tls.cpp` | Adds client-certificate verification for the node listener. |
| `backend/include/config/app_config.hpp` | Holds all new limits and defaults, such as lifetimes, polling intervals, spool bounds, and confirmation windows. |
| Runtime configuration | New `mesh` section: role, controller address, and CA fingerprint. Unset means a standalone backend that behaves exactly as today. |
| `logs/` | New `LogSink` for the spool and collector, plus hash chaining. |
| `auth/` | MFA enrollment and verification behind `AuthProvider`, enforced by the C++ API. The dashboard holds no MFA secrets. |
| `backend/{include,src}/mesh/` alerts | Alert conditions, active state, and acknowledgment on the controller. |
| `dashboard/` | New Network pages: zones and nodes, policy with effect preview, rollout status, and flow search. The dashboard calls only the controller, with no passthrough routes and no direct access to other nodes. |

## Open decisions

None.

## Verification

Each milestone leaves a working system. Integration tests run in Linux network namespaces, separate from `make test`, which stays free of privileged host state.

| Milestone | Delivers | Done when |
| --- | --- | --- |
| **M0: Foundations** | Phase 3, stable rule IDs, atomic apply with automatic rollback, and service-manager integration. Threat model. | A deliberately bad ruleset rolls back automatically on a test host. |
| **M1: Identity** | Offline root and issuing CA, enrollment, renewal, revocation, mTLS node listener. | A node joins with a token. Reused, expired, and wrong-CA tokens are rejected. A revoked node can't renew. |
| **M2: Read-only fleet** | Inventory, node status and health in the dashboard, and the alert system. Later milestones add their own alert conditions. No changes are pushed yet. | One dashboard shows the state of several backends, each read over the node API. A node that goes silent raises an alert. |
| **M3: Managed policy** | Zones, structured policy, signed configuration, compiler, staged rollout. | Policy reaches nodes, tampered and old configuration is rejected, and rollback is visible in the dashboard. **The management mesh is complete here.** |
| **M4: Single hub** | WireGuard tunnels through one hub, and three-point enforcement. | Allowed traffic flows and denied traffic is dropped at each point, including when one point is deliberately misconfigured. |
| **M5: Central audit** | Flow records, spool, collector, hash chains, flow search, MFA, and the emergency override. The block and the override ship together, so the block is never in place without its escape route. | Records survive a collector outage, a full spool stops all zone traffic through that node while it can still recover, and altered records are detected. An override fails without MFA, can't cover internet traffic, is recorded before it applies, and expires on its own. |
| **M6: Internet egress** | Egress gateway, DNS resolver, and kill switch. | Allowed zones get out, others don't, no inbound connections work, and a local-uplink bypass attempt is blocked. |
| **M7: Scaled hubs** | Multiple hubs, pair-based selection, failover, and optional state synchronization. | A hub is killed under load: flows recover within the target time and both directions always use the same hub. |
| **M8: Hardening** | Controller standby, key rotation drills, the optional second edge gateway per zone, and the resource gateway role. | A full recovery exercise from a compromised or lost controller is documented and passes. |

M1–M3 can be used on their own. If priorities change, the project can stop at M3 with a useful central firewall manager, or at M5 with a useful audited network.
