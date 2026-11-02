# Development Roadmap

This roadmap separates work that follows from the current implementation from longer-term concepts. It is directional, not a delivery schedule: priorities and designs may change as the project develops. A task is complete only when the behavior exists in the repository and its stated verification is satisfied.

## Traceability and status model

This roadmap uses status levels that keep the project evidence-based, even as some scope remains directional:

- Implemented: the feature or behavior exists in the repository and is covered by current code and documentation.
- In progress: the feature is partly present or being actively refined before it is considered complete.
- Planned: the work is defined but not yet implemented.
- Exploratory: the idea is part of the broader vision or thesis context, but it is not a committed implementation target yet.

A roadmap item should record clear evidence and verification criteria: repository evidence, current status, and the exit criteria that would mark it complete.

| Area | Status | Evidence in the repository | Notes |
| --- | --- | --- | --- |
| Backend firewall abstraction and nftables backend | Implemented | `backend/include/firewall/providers/`, `backend/src/firewall/providers/` | Provider contract exists and is used by the HTTP layer. |
| JSON rule management and statistics APIs | Implemented | `backend/src/http/api/` | Structured rule operations and system-status endpoints exist. |
| Health and version metadata endpoints | Implemented | `/status/health`, `/status/info`, versioned schema handling | Build embeds the Git commit hash and reports it in `/status/info`. |
| Dashboard overview, login, and firewall configuration UI | In progress | `dashboard/`, server-side session store, templates, and tests | Backend login, token-backed API requests, CSRF/Origin checks, and server-side browser sessions are implemented; broader dashboard workflows remain incomplete. |
| Logging and bounded log reads | Implemented | `backend/include/logs/providers/`, `backend/src/logs/`, `dashboard/webapp/audit_log.py` | Both services write owner-only JSONL audit logs through replaceable sinks; backend request records carry request ID, actor, operation, outcome, and source IP, and authorized requests fail closed with `503` when they cannot be recorded. Log reads are bounded and redacted per source. |
| Replaceable service contracts beyond the firewall backend | Implemented for Phase 2 | [architecture design](architecture.md#replaceable-implementations) | Authentication provider, log sink, log source, dashboard API transport, and dashboard API settings contracts are implemented with contract tests. The platform-neutral system-information provider remains Phase 4 work. |
| CLI import/export of firewall config bundles | Implemented | `Firewall::BundleProvider`, nftables implementation, and bundle tests | Optional capability, separate from the backend-neutral `Firewall::Backend` contract; imports require explicit merge or replace mode and do not claim arbitrary host recovery. |
| Backend API authentication and firewall role enforcement | Implemented | `backend/src/http/authentication.cpp`, `backend/src/http/api/auth.cpp`, auth middleware tests | All routes require backend Bearer sessions by default except health, login, and one-time setup; viewers are read-only, firewall writes require Operator/Administrator, and account APIs require Administrator. Account lifecycle APIs, dashboard login/session integration, and source/identity API and firewall-mutation limits are implemented. |
| Native API TLS | Implemented | `backend/src/http/tls.cpp`, `dashboard/webapp/api_client.py`, [runtime config](runtime-config.md#tls) | Optional TLS 1.2+ for the C++ API with fail-closed startup checks; the dashboard verifies certificates against system trust plus an optional CA bundle. Browser-to-dashboard HTTPS is left to an operator reverse proxy. |
| Service-manager integration | Planned | security and system-management design notes | Requires explicit deployment and trust-boundary decisions. |
| Mesh network: centralized management, audited inter-zone tunnels, and optional internet access | Planned | [mesh design](phases/mesh.md) | One controller manages enrolled backends, and inter-zone traffic passes through scalable transit hubs that record it. No peer enrollment, mesh transport, or centralized management is implemented. |
| Device Agent, Policy Decision Point, and wider thesis architecture | Exploratory | [goal.md](goal.md) and the thesis-inspired concept material | Strategic direction rather than a current implementation commitment. The Edge, Resource, and Segmentation Gateway roles are part of the planned mesh. |

## Current Baseline

The repository currently provides:

- A C++ HTTP API with a backend-neutral `Firewall::Backend` interface and an nftables implementation.
- JSON endpoints for listing, adding, and deleting firewall rules, plus firewall statistics and host system information.
- A versioned API endpoint returning bounded, source-grouped Archangel application logs and conditional nftables packet logs from the kernel journal.
- A bodyless `/status/health` liveness endpoint, a versioned JSON `/status/info` endpoint, and a schema-version header on API calls. The build embeds the current Git commit hash in the backend binary.
- A Flask dashboard with a server-health overview, a Firewall Configuration page for individual rules, a read-only System Management page with a source-grouped Logs subpage, and read-only API configuration status. It calls the C++ API server-side using the authenticated backend contract.
- Backend CLI one-shot export/import of a versioned `archangel-firewall-config` bundle containing only the full nftables JSON ruleset. The optional `Firewall::BundleProvider` capability keeps native config operations out of the backend-neutral `Firewall::Backend` contract. Every import requires an explicit firewall-rules mode: merge, managed-only replace, or whole-ruleset replace-all.
- The Firewall Configuration page shows active rules through a file tree of families, tables, and chains, can filter them, add, edit, duplicate, order, and delete rules, manage tables and chains, and export and import versioned, rules-only bundles. Changes, including imports, are collected as pending changes and applied together in one transaction. Exports omit unsupported nftables rules.
- The overview summarizes nftables base-chain hook status without rendering firewall rules. The System Management page reports host and backend status; restart controls are not operational because authenticated service control and a deployment-specific service-manager integration are not yet designed.
- The services are independently deployable in design: the privileged binary belongs on the managed server, while the Dockerized dashboard is intended to remain portable and may run on a separate management computer. The current Compose configuration is a same-host development setup, not a validated remote deployment recipe.
- Owner-only JSONL audit logs in both services, with request IDs returned in `X-Request-ID`, optional native TLS for the C++ API, and backend and dashboard unit test suites.

The C++ API authenticates requests, manages account lifecycle operations, and enforces roles and configured API/firewall-mutation limits. The Flask dashboard authenticates through the backend and stores browser sessions server-side. API traffic uses native TLS when enabled and plain HTTP otherwise; firewall rule mutations are privileged and take effect immediately. Keep both services on localhost or an isolated, trusted management network; when deployed on separate computers, ensure their communication and dashboard access stay within that trusted network. Do not expose them to the public internet. See [SECURITY.md](../SECURITY.md) and [endpoints.md](endpoints.md).

## Decisions and Open Questions

The decisions below record agreed direction as well as remaining questions. Unresolved design work must be closed at its phase gate rather than left implicit.

| Decision | Why it matters | Related phase or gate | Current direction / remaining decision |
| --- | --- | --- | --- |
| How should backend runtime settings be configured without coupling them to firewall import/export? | Firewall bundles contain privileged native rules and importing them can immediately change host state; runtime settings have a different lifecycle and risk profile. | Phase 2 | Use a separate, strictly validated versioned JSON runtime config for persistent network, authentication/database, TLS, logging, rate-limit, and session settings at `/etc/archangel/config.json`. Load it automatically when present; defaults apply only if this implicit file is absent. `--config PATH` is an explicit required path. CLI values override file values, which override built-in defaults. Require service/root ownership and prohibit group/world writes; reject malformed or unreadable files. Keep firewall import/export as explicit CLI-only operations; runtime config never triggers a firewall ruleset mutation. |
| Which users and deployment environments should the first secured release support? | Defines trust boundaries, personnel model, and operational risk. | Phase 2 / Phase 4 | Initial local backend accounts; support the dashboard on a separate management computer. Keep dashboard browser access loopback by default; secure dashboard-to-API traffic with TLS. |
| What backend identity and credential model should be used, and how will administrators recover access? | This determines how trustworthy access is provisioned, revoked, and recovered. | Phase 2 | Backend authentication-provider abstraction; SQLite-backed local provider first, OIDC future; Argon2id password hashes; configurable backend DB path defaulting to `/var/lib/archangel/archangel.db`; privileged interactive CLI bootstrap/recovery plus authenticated administrator API; opaque revocable sessions with configurable 15-minute idle and 8-hour absolute defaults. Flask uses a separate SQLite server-side session store containing no identity records. |
| Should TLS terminate in the application, a trusted reverse proxy, or support both? | Affects trust assumptions, deployment complexity, and certificate lifecycle. | Phase 2 / Phase 4 | Optional native C++ API TLS in backend config, off by default, with operator-managed certificates. Dashboard validates using system trust plus an optional private CA bundle. Dashboard remains loopback by default; remote browser access uses an operator-managed reverse proxy. |
| What permission roles and rate-limit policy fit expected single-gateway and multi-gateway use? | Affects access control, abuse resistance, and API stability. | Phase 2 | Viewer/operator/administrator roles and configurable conservative per-identity/source-IP rate limits, with no permanent account lockout; health is exempt. Set tested defaults and state handling before implementation. |
| Which service-manager integrations and authorized operations, if any, should be supported by the System Management page? | Governs service restart and administrative scope, which are high-impact operations. | Phase 3 / Phase 4 | Enabling operational controls or system-management actions. |
| How should peer backends authenticate, authorize, discover, and securely communicate when forming a mesh? | Core requirement for backend-to-backend trust and topology decisions. | Mesh network | Enrollment tokens, a built-in private CA with mTLS, signed configuration pulled by nodes, and WireGuard tunnels through central transit hubs. See [Design choices](phases/mesh.md#design-choices) in the mesh design. |
| Which platforms and firewall implementations are in scope for a usable release? | Prevents overextending the project into unsupported environments. | Phase 4 | Linux is the primary design and development platform. Other operating systems may be supported later, but are not a current priority or compatibility commitment. Assess them only when a concrete platform and firewall capability set is selected. |
| Which long-term network features are priorities, and which remain out of scope? | Keeps the roadmap aligned with realistic product scope. | Phase 5 | Committing to new network or policy features. |
| What availability and recovery requirements should apply to the PDP, SG, PKI, and security-log services? | These are critical dependencies and may become single points of failure. | Phase 5 | Launching a broader Zero Trust or segmented architecture. |
| Which application components need replaceable implementation contracts? | Concrete implementations can otherwise couple domain and API behavior to a single provider, operating-system interface, transport, or storage format. | Phase 2 / Phase 4 | Keep the existing backend-neutral `Firewall::Backend` contract as the pattern. Phase 2 adds contracts for authentication providers, logging sinks, API log-source readers, dashboard HTTP transport, and dashboard API settings. The dashboard reads its API destination only from deployment-fixed `ARCHANGEL_API_URL`; the earlier JSON-file settings fallback has been removed. Phase 4 adds a platform-neutral system-information provider with Linux as the initial implementation. Select implementations at composition/configuration boundaries; do not add runtime plugin loading. |

## Broader Project Vision

The project is intended to evolve beyond a firewall UI and into a Zero Trust network-segmentation model in which access is controlled at explicit boundaries, identities are verified, and policy decisions are enforced via authenticated, protected control planes. This direction is conceptually aligned with the thesis ideas captured in [goal.md](goal.md), especially the Edge Gateway, Resource Gateway, Segmentation Gateway, Device Agent, and Policy Decision Point concepts.

### Directional architecture

The broader vision is a layered model in which:

- An Edge Gateway (EG) sits at a zone boundary and controls zone-level communication.
- A Resource Gateway (RG) sits in front of an individual resource and enforces resource-specific access.
- A Segmentation Gateway (SG) provides a logical boundary between zones and routes authorized traffic between them.
- A Device Agent (DA) identifies supported devices or endpoints and can provide posture or credential context.
- A Policy Decision Point (PDP) evaluates identity, permissions, policy, and context, while Policy Enforcement Points (PEPs) enforce the resulting decisions.

This proposal includes protected control-plane communication, authenticated gateway relationships, certificate-based trust, and separate handling of security logs and policy decisions. The intention is to make communication explicit and policy-driven instead of assuming that network placement or local access alone is sufficient.

### Thesis-inspired future sequence

If this direction is selected, the thesis suggests a staged sequence rather than a single large leap:

1. Secure SG/EG core connectivity: establish zone boundaries and authenticated, encrypted gateway-to-gateway communication.
2. Integrate trust and decision services: connect the PDP, PKI, identity management, and security-information sources with explicit policy and revocation flows.
3. Add endpoint agents: authenticate supported devices and collect only the posture data the threat model justifies.
4. Add resource-level enforcement: deploy RG/PEP functionality in front of selected resources and apply least-privilege resource policies.

These are future-stage concepts, not current implementation commitments. They should be treated as exploratory architecture until the corresponding trust model, failure behavior, and operational constraints are documented.

### Industry-standard considerations

The project should align with common security and engineering expectations for network-management systems, including:

- Zero Trust principles such as explicit verification, least privilege, and continuous monitoring
- Strong identity and access boundaries between administrative users, services, and peers
- Mutual TLS and PKI lifecycle management where trust relationships are established across gateways or services
- Secure logging, auditability, and incident response so that security-relevant activity can be reviewed without exposing sensitive data
- A clear separation between the control plane and the data plane, with explicit fail-safe behavior when dependencies fail or are compromised
- Threat modeling and residual-risk documentation before consuming broader deployment scope or exposing services beyond a trusted management network

The thesis also discusses KSF-related concepts, but the project should not claim compliance or certification without a deployment-specific assessment and a concrete threat model. The architecture remains a directional vision until those decisions are made and verified.

## Phase 1: Testing and Contribution Readiness

**Status: Implemented. See the [Phase 1 design](phases/phase-1.md).**

1. **Add automated C++ tests.**
   - **Status: Implemented.** Unit tests cover nftables statistics parsing, firewall bundle v1 parsing and serialization, managed-rule replacement transaction planning, and structured API handlers, using controlled fixtures and a mock firewall.
   - Test API request parsing and validation, status codes, and JSON responses without changing the host firewall.
   - Test backend-neutral behavior and nftables statistics parsing using controlled fixtures.
   - Keep tests isolated from privileged host state; destructive operations must never run in ordinary test suites.
   - **Exit criteria:** `make test` runs the backend suite and returns a failing status for a failing test; the debug build and dashboard tests continue to pass.
2. **Add a repeatable project verification workflow.**
   - **Status: Implemented.** `docs/test.md` documents prerequisites, commands, coverage, and expected output; GitHub Actions runs on every push and pull request: dashboard tests, backend unit tests, the C++ debug build, and a clang-format check.
   - Document the build and test commands, required system dependencies, and any tests that require special environments.
   - Extend CI when additional supported build or test environments are selected.
   - **Exit criteria:** a clean checkout can follow the documented local verification steps, and CI reports build and test outcomes.
3. **Publish contribution guidance.**
   - **Status: Implemented.** [CONTRIBUTING.md](../CONTRIBUTING.md) provides issue-first contribution, verification, implementation, documentation, and security-reporting guidance.
   - **Status: Implemented.** [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) describes expected behavior and private reporting to maintainers.
   - **Exit criteria:** contribution and conduct documents are linked from the README and state clear reporting paths.
4. **Separate Archangel-managed rules from other rules in backend config export/import.**
   - **Status: Implemented.** Firewall bundle v1 (`archangel-firewall-config`) contains firewall rules only and uses the reserved `archangel-managed` nftables comment on rules created through the structured API; v1 is the only supported import/export format.
   - `replace` updates only marked rules; `replace-all` explicitly flushes the full ruleset.
   - **Exit criteria:** ownership behavior is documented; tests cover managed/unmanaged classification, v1 round-tripping without listener settings, unsupported-version rejection, and merge/replace mode selection and transaction planning.

## Phase 2: Backend-Owned Security Controls

**Status: Implemented. Backend authentication and roles, account lifecycle APIs, dashboard login and sessions, rate limits, native TLS, JSONL audit logging, and the Phase 2 service contracts are in place; the security review is recorded in [security concerns](security-concerns.md#phase-2-security-review). The follow-ups identified after the review are implemented: the `user recover` command, rehashing passwords after login when the configured Argon2id cost increases, an operator-provided password blocklist, and dashboard audit records with the actor and outcome that fail closed for every non-health request. MFA and tamper-evident log storage remain deferred. See the [Phase 2 design](phases/phase-2.md).**

Security controls must be enforced at the backend/API trust boundary. The backend is authoritative for identity, authentication, and authorization. Do not create a separate Flask dashboard or browser user-authentication database. `GET /status/health` remains unauthenticated and returns only a status code for liveness. Authentication operations may accept credentials to establish a backend session and must be narrowly scoped and rate-limited; they must not disclose protected data. `GET /status/info` and every protected API route require backend authentication. Retain the deployment restrictions in [SECURITY.md](../SECURITY.md): TLS is optional and off by default, and controls such as MFA and tamper-evident audit storage are not implemented.

1. **Decide and document the security model before implementation.**
   - **Status: Complete.** The selected design, threat tradeoffs, recovery model, and residual risks are recorded in the [Phase 2 design](phases/phase-2.md). OIDC and MFA are explicitly deferred.
   - **Exit criteria — met:** document the threat model and selected design, including remaining risks and operational recovery; settle persistence, credential, TLS, rate-limit, logging, identity, authorization, API-destination, and replaceable-contract decisions. No design may depend on frontend-only access checks.
2. **Implement backend authentication and authorization.**
   - **Status: Implemented for the backend and dashboard authentication flow.** The backend-owned `AuthProvider` contract and SQLite/Argon2id local provider include private account/session persistence, interactive initial-administrator bootstrap and local administrator recovery, rehashing on login after an Argon2id cost increase, an optional operator-provided password blocklist, API login/logout, default authentication, firewall role enforcement, account lifecycle APIs, and per-source login-attempt limiting. The dashboard authenticates with the backend, keeps the token server-side, and sends it with protected API calls. A dashboard account-management UI remains future work.
   - Require credentials or a verifiable backend-issued credential on every API call except `GET /status/health`. Authenticate and authorize each request independently in the C++ API; do not infer API access from having passed a frontend login screen or from frontend-only session state.
   - Flask may present the login experience and account-management pages, but each call it makes to the C++ API other than the liveness check must include a credential the API can validate. Apply the agreed role policy to every other API route and deny access by default when the caller is unauthenticated or lacks permission.
   - Protect browser form submissions and session handling against request forgery and session misuse as appropriate to the chosen design.
   - **Exit criteria:** backend tests cover missing, invalid, and valid credentials, role permissions, public-route exceptions, account lifecycle, login/logout, and login throttling; dashboard tests verify session handling, CSRF/Origin enforcement, and protected page access. `/status/health` remains available without credentials and returns no body. Any future frontend login state must not bypass backend authorization.
3. **Provide HTTPS support.**
   - **Status: Implemented.** The C++ API serves HTTPS when `tls.enabled` is set, requires TLS 1.2 or newer, and fails startup on missing, unsafe, or mismatched certificate and key files. The dashboard verifies the API certificate against system trust plus `ARCHANGEL_API_CA_BUNDLE` with no bypass, and warns when the API URL is plain HTTP to a non-loopback host. Unit tests cover file validation and context setup; container integration checks confirmed a verified TLS 1.2/1.3 connection, refusal of TLS 1.1 and plain HTTP, and dashboard refusal without the CA bundle. The dashboard binds to loopback by default (`WEB_HOST=127.0.0.1`).
   - Implement optional native TLS for the C++ API using operator-provisioned certificates. Validate certificate configuration and client-side API certificate trust explicitly. Keep browser-to-dashboard access loopback-only by default; document operator-managed reverse-proxy HTTPS for remote browser access.
   - **Exit criteria:** deployment documentation explains secure setup and certificate lifecycle; tests or integration checks confirm encrypted API connections, reject invalid TLS configuration, and verify loopback defaults for the dashboard.
4. **Add API rate limiting.**
   - **Implemented:** failed-login limits default to 5 attempts per source IP per 5 minutes; general API limits default to 120 requests per minute per source IP and authenticated identity; firewall mutations have an additional 30-per-minute limit per source IP and identity. The bounded, thread-safe in-memory fixed-window limiters return HTTP `429` with `Retry-After`, use the direct peer IP, ignore forwarded headers, and reset on backend restart. Health is exempt.
   - **Exit criteria:** tests verify configured limits, source and identity isolation for firewall mutations, the response contract, and health exemption. Tune defaults if deployment evidence shows normal authorized use is unintentionally blocked.
5. **Add replaceable backend and dashboard service contracts.**
   - **Status: Implemented.** `AuthProvider` with the SQLite provider; `LogSink` with `JsonlFileSink` in the backend and a JSONL handler in the dashboard; `LogSource` with application-log and nftables-journal sources; the dashboard `ApiTransport` contract with `UrllibTransport`; and `load_api_settings` for deployment-fixed API settings. Implementations are selected at startup, and each contract has tests using fakes. OIDC and alternate sinks remain later implementations.
   - Add a source-reader contract for API log sources and adapt the Archangel application log and nftables journal source to it. Preserve per-source availability and safe explanations, bounded output, and common redaction.
   - Formalize the dashboard HTTP transport and API-settings provider boundaries. Use deployment-fixed `ARCHANGEL_API_URL` configuration for the dashboard; keep API destination configuration separate from dashboard session and credential storage. The secured dashboard must not let browser users edit the API destination or redirect backend-held credentials. Keep API configuration separate from dashboard session/credential storage.
   - **Exit criteria:** implementations are selected at composition/configuration boundaries; contract tests exercise local account, file-sink, log-source, HTTP transport, and API-settings behavior using fakes where appropriate. No speculative plugin loader is introduced.
6. **Update security documentation and review the result.**
   - **Status: Implemented.** Security, endpoint, runtime-config, and deployment documentation describe the implemented controls and remaining gaps, and the CIA/IAAA review is recorded in [security concerns](security-concerns.md#phase-2-security-review). The review does not recommend exposing either service beyond a trusted management network.
   - Update [SECURITY.md](../SECURITY.md), [endpoints.md](endpoints.md), and deployment instructions to distinguish implemented protections from remaining gaps.
   - **Exit criteria:** current posture, setup, route requirements, and remaining risks agree across documentation and implementation; verify the controls against the CIA triad and IAAA responsibilities, and complete a security review before recommending broader network exposure.

## Phase 3: Safe Firewall Management in the Dashboard

**Status: Planned; next phase. See the [Phase 3 design](phases/phase-3.md).**

The API already supports structured rule creation and deletion. The dashboard can already apply rules through the confirmed, additive bundle import on the Firewall Configuration page; it has no workflow for changing an individual rule, chain, or table.

1. Add dashboard workflows to create, edit, and delete rules, order them by dragging, and manage tables and chains, extending the structured API contract. Do not accept or construct raw nftables commands in browser input.
2. Expand the structured rule model to cover addresses, ports, connection state, interfaces, ICMP, logging, counters, rate limits, `jump` and `goto`, `reject` options, and NAT.
3. Collect changes as pending changes, including bundle imports, and apply them together in one all-or-nothing transaction.
4. Before applying, show a `before -> new` list of every change, and require a deliberate confirmation. Flag any change that could disrupt the dashboard's connection to the API as a management risk.
5. Handle validation failures, unavailable backends, changed rules, and permission denials with clear non-color-only status messages.
6. Keep API validation authoritative; the dashboard may improve usability but must not be treated as a security boundary.
7. **Next:** have Archangel manage its own table, and show other tables read-only behind a toggle, so that it can't break Docker, firewalld, or other programs. This comes before the remaining rule features. See [table ownership](phases/phase-3.md#next-step-table-ownership).
8. **Exit criteria:** tests cover successful and rejected changes, conflicts, and failures partway through a batch, and an authorized user can verify the target and result of each change. The UI never implies a change succeeded if the API rejected or failed it. Automatic rollback is not part of this phase, so any lockout may need console access to fix.

## Mesh Network

**Status: Planned; follows Phase 3 and runs alongside Phase 4**

The [mesh design](phases/mesh.md) defines the behavior, security model, and completion tests for each milestone. Isolated networks are the primary target. The milestones build on each other, and the project can stop usefully after M3 or M5.

| Milestone | Delivers |
| --- | --- |
| M0: Foundations | Phase 3, stable rule IDs, atomic apply with automatic rollback, service-manager integration from Phase 4, and a threat model. |
| M1: Identity | Private CA, enrollment, renewal, revocation, and the mTLS node listener. |
| M2: Read-only fleet | Inventory, node status, and alerts. |
| M3: Managed policy | Zones, structured policy, signed configuration, and staged rollout. This completes the management mesh. |
| M4: Single hub | WireGuard tunnels through one hub, with policy enforced at three points. |
| M5: Central audit | Flow records, tamper-evident collection, MFA, and the emergency override. |
| M6: Internet egress | Optional per-zone internet access, a DNS resolver, and a kill switch. |
| M7: Scaled hubs | Multiple hubs, failover, and optional connection-state synchronization. |
| M8: Hardening | Controller standby, key rotation drills, an optional second edge gateway per zone, and the Resource Gateway role. |

## Phase 4: Operational and Platform Maturity

**Status: Planned; Linux is the primary target; other operating systems are not a current priority**

1. Define supported Linux distributions, nftables/library versions, deployment modes, and minimum resource/privilege requirements. Linux is the primary design and validation target.
2. Document installation, configuration, upgrades, backup/recovery, service operation, and safe rollback expectations. Do not imply firewall changes are automatically rolled back unless implemented.
3. Review error handling, logging, configuration validation, and observability across both services; ensure diagnostics do not expose credentials, request bodies, or raw firewall rule input.
4. Introduce a platform-neutral system-information provider contract and adapt the existing Linux metrics collector as the initial implementation. Keep platform-specific collection details behind the provider and expose backend-neutral metric types to API handlers; this contract does not make non-Linux support a current deliverable.
5. Treat other operating systems as possible future targets, not current priorities. Assess another platform only when there is a concrete need, supported firewall technology, and agreed capability set; preserve backend-neutral contracts and test provider parity when implemented.
6. **Exit criteria:** supported Linux environments and operational procedures are explicit, and every implemented firewall or system-information provider has automated contract coverage. Any additional OS support is separately scoped and tested before being claimed.

## Phase 5: Long-Term Network Features

**Status: Exploratory; not committed scope**

The thesis [Zero Trust i isolerade komplexa miljöer](../assets/Zero_Trust_i_Komplexa_Isolerade_Miljöer.pdf) provides a reference architecture and proof-of-concept sequence, not an implementation specification. It describes a central Segmentation Gateway (SG), Edge Gateways (EGs) at zone boundaries, Resource Gateways (RGs) in front of individual resources, Device Agents (DAs) for endpoint identity/posture, and a Policy Decision Point (PDP) that directs Policy Enforcement Points (PEPs). The proposed PDP comprises a Policy Engine and Policy Administrator. See [goal.md](goal.md) for component roles, control/data-plane flow, principles, and limitations.

### Thesis-inspired proof-of-concept sequence

If this direction is selected, the thesis suggests incremental stages (printed pp. 75–76):

1. **Secure SG/EG core connectivity.** Establish zone boundaries and authenticated, encrypted gateway-to-gateway communication. Agree on peer identity and bootstrap before connecting gateways.
2. **Integrate decision and trust services.** Connect the PDP, PKI, identity management, and chosen security-information sources. Define policy, credential issuance/revocation, control-plane protection, and behavior when a dependency is unavailable.
3. **Add endpoint agents.** Authenticate supported endpoints and collect only the posture information justified by the threat model. Treat any hardware proxy for legacy endpoints as a separate design with explicit limitations.
4. **Add resource-level enforcement.** Deploy RG/PEP functionality in front of selected resources and apply least-privilege resource policies.

These exploratory stages do not supersede the nearer-term project phases above and should not be interpreted as an approved schedule or a decision to implement every thesis component.

Before committing to any stage, assess the control and data planes, CIA and IAAA requirements, complexity, threat model, and fail-safe behavior. The thesis highlights availability risks if the central PDP or SG is unavailable, compromise risks to these high-impact components, and severe consequences if the PKI is compromised. Define redundancy/recovery, certificate revocation and key protection, authenticated and encrypted control-plane links, protected security-event logging, monitoring, and zone-containment behavior as explicit design decisions. Fail-closed choices must be weighed against availability; the appropriate behavior can differ by operation and deployment.

The following additional items originate from the broader project vision and require separate scope, threat-model, and architecture decisions before implementation:

- DNS resolver and DHCP controllers.
- Device enrollment and identity agents.
- Port/service discovery.
- Deep packet inspection.
- Packet-flow visualization and network topology views.
- Expanded hardware information and monitoring.
- A management frontend used to administer and update backend services.
- A Policy Decision Point that detects attacks such as floods and isolates the affected zone until an administrator reopens it. This needs its own design, because an attacker could try to trigger isolation against a healthy zone.

The mesh network and centralized backend management have moved to the [Mesh Network](#mesh-network) section.

For any item selected for development, first document the use case, trust boundaries, required data and permissions, failure behavior, privacy implications, operational impact, and API/UI contract. Then define testable acceptance criteria and update the relevant architecture, endpoint, security, and goal documentation. These concepts are not current capabilities.

The thesis discusses Swedish Armed Forces security-function requirements (KSF). It is not evidence that Archangel or a future deployment is KSF-compliant or certified. Any real deployment must be assessed against its applicable requirements, threat model, and component-specific security obligations.

## Decisions Still Open

The first secured release's users and environments, identity and recovery model, TLS placement, and roles and rate limits are settled; see [Decisions and Open Questions](#decisions-and-open-questions) and Phase 2.

- Which backend service-manager integrations and authorized operations, if any, should be supported by the System Management page? Define restart scope, authorization, and behavior before enabling controls.
- Which platforms and firewall implementations are in scope for a usable release?
- Which long-term network features are priorities, and which should remain out of scope?
- What availability and recovery requirements should apply to the PDP, SG, PKI, and security-log services?
