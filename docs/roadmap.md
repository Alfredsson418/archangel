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
| Backend firewall abstraction and nftables backend | Implemented | `core/include/firewall/providers/`, `core/src/firewall/providers/` | Provider contract exists and is used by the HTTP layer. |
| JSON rule management and statistics APIs | Implemented | `core/src/http/api/` | Structured rule operations and system-status endpoints exist. |
| Health and version metadata endpoints | Implemented | `/status/health`, `/status/info`, versioned schema handling | Build embeds the Git commit hash and reports it in `/status/info`. |
| Dashboard overview, login, and firewall configuration UI | In progress | `app/web/`, server-side session store, templates, and tests | Backend login, token-backed API requests, CSRF/Origin checks, and server-side browser sessions are implemented; broader dashboard workflows remain incomplete. |
| Structured logging and bounded log reads | Implemented | backend and dashboard logging configuration | Useful diagnostics exist, but access and retention policies remain limited. |
| Replaceable service contracts beyond the firewall backend | In progress | [architecture design](architecture.md#replaceable-implementations) | The authentication-provider contract and SQLite provider are implemented; logging sinks, API log sources, dashboard transport/settings, and system-information providers remain planned. |
| CLI import/export of firewall config bundles | Implemented | `FirewallConfigProvider`, nftables implementation, and bundle tests | Optional capability, separate from the backend-neutral `Firewall` contract; imports require explicit merge or replace mode and do not claim arbitrary host recovery. |
| Backend API authentication and firewall role enforcement | Implemented | `core/src/http/authentication.cpp`, `core/src/http/api/auth.cpp`, auth middleware tests | All routes require backend Bearer sessions by default except health, login, and one-time setup; viewers are read-only, firewall writes require Operator/Administrator, and account APIs require Administrator. Account lifecycle APIs, dashboard login/session integration, and source/identity API and firewall-mutation limits are implemented. |
| HTTPS and service-manager integration | Planned | security and system-management design notes | Requires explicit deployment and trust-boundary decisions. |
| Centralized management of multiple backends and enrollment-token-based mesh | Exploratory | [goal.md](goal.md#centralized-management-and-backend-mesh), [architecture](architecture.md#future-centralized-backend-management) | One backend may manage multiple enrolled peer backends from one instance. Enrollment-token bootstrap is the intended direction; no peer enrollment, mesh transport, or centralized management is implemented. |
| Long-term EG/RG/SG mesh architecture | Exploratory | [goal.md](goal.md) and the thesis-inspired concept material | Strategic direction rather than a current implementation commitment. |

## Current Baseline

The repository currently provides:

- A C++ HTTP API with a backend-neutral `Firewall` interface and an nftables implementation.
- JSON endpoints for listing, adding, and deleting firewall rules, plus firewall statistics and host system information.
- A versioned API endpoint returning bounded, source-grouped Archangel application logs and conditional nftables packet logs from the kernel journal.
- A bodyless `/status/health` liveness endpoint, a versioned JSON `/status/info` endpoint, and a schema-version header on API calls. The build embeds the current Git commit hash in the backend binary.
- A Flask dashboard with a server-health overview, a Firewall Configuration page for individual rules, a read-only System Management page with a source-grouped Logs subpage, and read-only API configuration status. It calls the C++ API server-side using the authenticated backend contract.
- Backend CLI one-shot export/import of a versioned `archangel-firewall-config` bundle containing only the full nftables JSON ruleset. The optional `FirewallConfigProvider` capability keeps native config operations out of the backend-neutral `Firewall` contract. Every import requires an explicit firewall-rules mode: merge, managed-only replace, or whole-ruleset replace-all.
- The Firewall Configuration page can filter and sort active rules and provides a disabled Edit control. It can export and preview-import versioned, rules-only bundles; imports are additive and non-atomic, and exports omit unsupported nftables rules.
- The overview summarizes nftables base-chain hook status without rendering firewall rules. The System Management page reports host and backend status; restart controls are not operational because authenticated service control and a deployment-specific service-manager integration are not yet designed.
- The services are independently deployable in design: the privileged binary belongs on the managed server, while the Dockerized dashboard is intended to remain portable and may run on a separate management computer. The current Compose configuration is a same-host development setup, not a validated remote deployment recipe.
- Structured application logging and a dashboard unittest suite.

The C++ API authenticates requests, manages account lifecycle operations, and enforces roles and configured API/firewall-mutation limits. The Flask dashboard authenticates through the backend and stores browser sessions server-side. API traffic has no project-configured TLS; firewall rule mutations are privileged and take effect immediately. Keep both services on localhost or an isolated, trusted management network; when deployed on separate computers, ensure their communication and dashboard access stay within that trusted network. Do not expose them to the public internet. See [SECURITY.md](../SECURITY.md) and [endpoints.md](endpoints.md).

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
| How should peer backends authenticate, authorize, discover, and securely communicate when forming a mesh? | Core requirement for backend-to-backend trust and topology decisions. | Phase 5 | Designing peer mesh relationships or backend federation. |
| Which platforms and firewall implementations are in scope for a usable release? | Prevents overextending the project into unsupported environments. | Phase 4 | Linux is the primary design and development platform. Other operating systems may be supported later, but are not a current priority or compatibility commitment. Assess them only when a concrete platform and firewall capability set is selected. |
| Which long-term network features are priorities, and which remain out of scope? | Keeps the roadmap aligned with realistic product scope. | Phase 5 | Committing to new network or policy features. |
| What availability and recovery requirements should apply to the PDP, SG, PKI, and security-log services? | These are critical dependencies and may become single points of failure. | Phase 5 | Launching a broader Zero Trust or segmented architecture. |
| Which application components need replaceable implementation contracts? | Concrete implementations can otherwise couple domain and API behavior to a single provider, operating-system interface, transport, or storage format. | Phase 2 / Phase 4 | Keep the existing backend-neutral `Firewall` contract as the pattern. Phase 2 adds contracts for authentication providers, logging sinks, API log-source readers, dashboard HTTP transport, and dashboard API settings. The dashboard reads its API destination only from deployment-fixed `ARCHANGEL_API_URL`; the earlier JSON-file settings fallback has been removed. Phase 4 adds a platform-neutral system-information provider with Linux as the initial implementation. Select implementations at composition/configuration boundaries; do not add runtime plugin loading. |

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

**Status: Implemented; first hosted CI run pending**

1. **Add automated C++ tests.**
   - **Status: Implemented.** Unit tests cover nftables statistics parsing, firewall bundle v1 parsing and serialization, managed-rule replacement transaction planning, and structured API handlers, using controlled fixtures and a mock firewall.
   - Test API request parsing and validation, status codes, and JSON responses without changing the host firewall.
   - Test backend-neutral behavior and nftables statistics parsing using controlled fixtures.
   - Keep tests isolated from privileged host state; destructive operations must never run in ordinary test suites.
   - **Exit criteria:** `make test` runs the backend suite and returns a failing status for a failing test; the debug build and dashboard tests continue to pass.
2. **Add a repeatable project verification workflow.**
   - **Status: Implemented.** `docs/test.md` documents prerequisites, commands, coverage, and expected output; GitHub Actions runs dashboard tests, backend unit tests, and the C++ debug build. The first hosted workflow run remains pending.
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

**Status: In progress; backend authentication, account lifecycle APIs, dashboard login/session integration, role enforcement, and configured rate limits are implemented; TLS and other security controls remain pending**

Security controls must be enforced at the backend/API trust boundary. The backend is authoritative for identity, authentication, and authorization. Do not create a separate Flask dashboard or browser user-authentication database. `GET /status/health` remains unauthenticated and returns only a status code for liveness. Authentication operations may accept credentials to establish a backend session and must be narrowly scoped and rate-limited; they must not disclose protected data. `GET /status/info` and every protected API route require backend authentication. Retain the deployment restrictions in [SECURITY.md](../SECURITY.md) because API traffic remains plain HTTP and several broader controls are incomplete.

1. **Decide and document the security model before implementation.**
   - **Status: Complete.** The selected design, threat tradeoffs, recovery model, and residual risks are documented below. OIDC and MFA are explicitly deferred.
   - **Identity/privacy decision:** require only username and password; do not require email, phone, or other personal data. Assign immutable random UUID user IDs. Usernames use ASCII letters/digits plus `._-`, 3–64 characters, are case-insensitive and normalized, and cannot be reused after disablement. Return generic login failures for unknown, disabled, or incorrect-password accounts and perform dummy Argon2id verification for nonexistent users. Initial authentication is password-only; MFA is deferred and the residual risk must be documented.
   - **Authorization matrix:** viewer may read rules, stats, system information, logs, and `/status/info`; operator inherits viewer and may create/delete firewall rules; administrator inherits operator and may create/list/update/disable accounts and manage roles, with no hard-delete operation. Login returns only an opaque backend session credential; logout revokes it. Credential/setup/reset endpoints are limited to those operations. `GET /status/health` is unauthenticated and bodyless; unknown routes/methods deny by default.
   - Treat security as a major concern throughout the project. Assess each design against the CIA triad: confidentiality, integrity, and availability.
   - Apply IAAA access-control principles: identification, authentication, authorization, and accounting. Define what identities are represented, how they are authenticated, what each identity may do, and what security-relevant events are recorded.
   - Compare the expected reduction in security risk with the attack surface, configuration risk, operational burden, and maintenance complexity introduced by each control. Prefer the simplest effective design, not complexity for its own sake.
   - **Agreed direction:** use a backend-owned authentication-provider abstraction. Implement local accounts first; retain OIDC as a future provider option, not part of the initial implementation. The backend owns identity records and authorization; Flask and the browser do not maintain a separate user store.
   - **Agreed account lifecycle:** store backend-owned local accounts, opaque session records, and schema metadata in a SQLite database at a runtime-configurable path, defaulting to `/var/lib/archangel/archangel.db`. Require a service-owned parent directory with mode `0700` and DB file mode `0600`; fail if permissions are unsafe. Keep Flask's browser-session DB on the dashboard host and separate from user identity. Use SQLite online backup (or stop the service before copying); apply versioned migrations and fail startup on migration errors. Hash passwords with Argon2id through a maintained library. Provide privileged interactive CLI subcommands `user bootstrap-admin` (allowed only if no active administrator exists) and `user recover` (local recovery may bypass last-admin API safeguards); both prompt securely on a TTY, never accept passwords in command-line arguments, and do not ship default credentials. Account deletion is disable-only; retain immutable user IDs for audit traceability and never reuse them. Prevent disabling the last active administrator through the API.
   - Backend administrator account APIs issue 256-bit CSPRNG, single-use setup tokens shown once for out-of-band delivery; only token hashes are stored, tokens are not logged, and account holders set their own passwords. A dashboard account-management UI remains future work. Tokens expire after one hour, only one may be outstanding per account, and new accounts remain pending until setup completes. Only administrators initiate resets; reset initiation revokes existing sessions and invalidates prior tokens. Disabled accounts cannot redeem tokens; successful setup requires a normal login.
   - **Agreed password policy:** require at least 15 characters, allow passphrases up to 128 characters, avoid arbitrary composition rules and forced periodic rotation, and reject known common/compromised passwords where feasible. Use Argon2id via a maintained implementation, with OWASP baseline defaults of 19 MiB memory, 2 iterations, and parallelism 1. Runtime config may increase but never lower these parameters; store the encoded parameters with each hash and rehash after successful login when cost is raised. Benchmark increases to avoid availability problems on managed hosts.
   - **Agreed authorization:** use `viewer`, `operator`, and `administrator` roles. Viewers can read rules, statistics, system information, and logs; operators also perform firewall rule changes; administrators also manage authentication accounts/settings. Login accepts credentials and returns only an opaque backend session credential; logout revokes it. Administrator account operations are create/list/update/disable, with no hard-delete operation. Deny by default. Keep `GET /status/health` unauthenticated and bodyless; credential-submission routes are limited to authentication operations.
   - **Agreed dashboard flow:** use Flask as a backend-for-frontend. Issue 256-bit CSPRNG opaque API session tokens; return them only during login, store only SHA-256 token hashes in the private backend SQLite DB, and never log tokens. Keep the credential in `/data/sessions.db` (configurable for deployment) in a dedicated server-side SQLite session store on the dashboard host, not browser-readable storage. This store contains session credentials only, never local identities or password hashes, and requires an owner-only directory and database file. Loss invalidates browser sessions and requires reauthentication; no session DB backup is required. Backend sessions have configurable lifetimes, initially 15 minutes idle and 8 hours absolute, and are revoked on logout or account/security changes. The C++ API authenticates and authorizes every protected request independently.
   - **Agreed API destination:** configure the dashboard's API base URL at deployment through `ARCHANGEL_API_URL`; do not expose it as a browser-editable setting. This prevents a user-controlled destination from redirecting backend-held credentials to an arbitrary host. Dashboard configuration and deployment examples must distinguish same-host local development from a separate management computer.
   - **Agreed browser session protections:** use an opaque browser session ID in an `HttpOnly`, `SameSite=Lax` cookie; set `Secure` when dashboard HTTPS is provided by an operator reverse proxy, but not for default loopback HTTP. Rotate the browser session ID after login and privilege changes. Require CSRF tokens on all state-changing dashboard forms, including login/logout, settings, and account management; validate `Origin` where available. Keep the cookie/session signing key outside config and source control in a protected file or environment variable. Production fails startup if missing; local development may use a documented ephemeral key that invalidates sessions on restart.
   - **Agreed transport:** support optional native TLS for the C++ API, configured in backend runtime JSON and disabled by default for local development. Require TLS 1.2 or newer. When enabled, certificate and private-key paths are required and invalid/missing files fail startup; never fall back silently to plaintext. Private-key files are readable only by the backend service account. Load certificates at startup; after renewal, operators restart the backend (no live reload in the initial design). Flask validates hostname and certificate using system trust plus an optional dashboard-host CA bundle selected by a deployment environment variable (for example `ARCHANGEL_API_CA_BUNDLE`) pointing to a read-only-mounted PEM file; retain system trust and do not provide a verification bypass. Keep the dashboard bound to loopback by default; browser-to-dashboard TLS is not required for local access. Operators exposing the dashboard beyond the local computer must provide HTTPS through their own reverse proxy.
   - **Agreed transport exception:** a non-loopback HTTP listener without TLS is allowed but must emit a prominent startup warning. This does not make the connection safe: credentials and API traffic remain observable/modifiable on the network. Production and separate-host deployments should enable TLS.
   - **Agreed accounting:** add replaceable logging backends in both services, with separate configurable JSONL append files initially: backend default `/var/log/archangel/backend.jsonl`, dashboard default `/data/archangel-frontend.jsonl`. Include timestamp, level, service, event, actor ID when known, operation, outcome, request ID, and source IP on every request. Never record credentials, request/response bodies, submitted values, or raw rules. IPs are privacy-sensitive; restrict access and retain compressed rotations for 30 days by default (operator-configurable). Require owner-only access and OS-managed rotation; backend reopens on a safe signal and dashboard detects rotation, avoiding `copytruncate`. Ordinary append files are not tamper-evident. Consider journald/syslog or a protected append-only sink as future adapters.
   - If the configured log sink cannot open at startup, fail startup. If writes fail at runtime, emit a sanitized stderr diagnostic, fail closed for protected/mutating operations, and keep only bodyless health available until logging recovers. No protected action may proceed without its required audit event being recorded; already completed in-flight operations cannot be rolled back if recording their outcome later fails.
   - **Agreed availability control:** use configurable defaults of 5 failed authentication attempts per source IP per 5 minutes, 120 API requests per minute per authenticated identity and source IP, and 30 firewall mutations per minute per identity and IP. Use bounded, expiring, thread-safe in-memory fixed-window limits; counters reset on backend restart. Do not permanently lock accounts. Use direct socket peer IP only and ignore forwarded headers. Exclude the minimal health check. Return JSON HTTP `429` with `Retry-After`.
   - **CIA and IAAA assessment:** backend authorization and protected transport reduce confidentiality and integrity risks from network observers and unauthorized callers; actor-attributed audit events support accounting. The local provider avoids a mandatory identity-service dependency, while OIDC remains a future option with an availability and trust dependency. TLS certificate failures and rate limits can affect availability; multiple provider and log-sink adapters add code, configuration, and test burden. Residual risks include host compromise, privileged administrator misuse, no MFA and resulting password-compromise risk, privacy exposure from retained source IPs, rate-limit counters resetting on restart, file-log alteration because append files are not tamper-evident, certificate lifecycle failures, temporary lockout from rate limiting, and credential/network exposure if a remotely reachable listener is intentionally run without TLS.
   - **Agreed runtime configuration:** use a separate versioned JSON runtime config with `format: "archangel-runtime-config"` and `version: 1`, containing `server`, `auth`, `sessions`, `tls`, `logging`, and `rate_limits`. It covers bind address/port; local provider, database path, password policy and Argon2id parameters; session lifetimes; TLS enablement/certificate/key paths; log sink/path/level; and the agreed rate thresholds. Omitted fields use documented defaults. Reject unknown keys, unsupported versions, wrong types, malformed, unreadable, or insecurely writable files. Store settings and protected-file paths only, never passwords or private-key contents. Dashboard-only settings (CA bundle path, `/data/sessions.db`, browser cookie/session signing key) are configured on the dashboard host, not in the backend config. Use `/etc/archangel/config.json`; load it when present, but use built-in defaults if this implicit default file is absent. `--config PATH` selects an explicit required file. CLI flags override runtime-config values, which override built-in defaults. Require service/root ownership and prohibit group/world writes. Keep runtime config distinct from the version 1 firewall ruleset bundle; firewall import/export remain explicit CLI-only operations and never run implicitly at service startup.
   - **Implementation status:** the strict v1 parser, protected-file loader, documented defaults, and backend bind/auth settings are implemented. The bootstrap command consumes its configured database path, password policy, and Argon2id parameters; API sessions and per-source login-attempt limits are also active. TLS and logging-sink configuration remain pending; API and firewall-mutation rate limits and dashboard session integration are implemented. Unsupported settings fail startup rather than being silently ignored.
   - OIDC claim-to-role mapping is deferred until OIDC is selected for implementation.
   - **Exit criteria — met:** document the threat model and selected design, including remaining risks and operational recovery; settle persistence, credential, TLS, rate-limit, logging, identity, authorization, API-destination, and replaceable-contract decisions. No design may depend on frontend-only access checks. Implementation remains pending.
2. **Implement backend authentication and authorization.**
   - **Status: Implemented for the backend and dashboard authentication flow.** The backend-owned `AuthProvider` contract and SQLite/Argon2id local provider include private account/session persistence, interactive initial-administrator bootstrap, API login/logout, default authentication, firewall role enforcement, account lifecycle APIs, and per-source login-attempt limiting. The dashboard authenticates with the backend, keeps the token server-side, and sends it with protected API calls. A dashboard account-management UI remains future work.
   - Require credentials or a verifiable backend-issued credential on every API call except `GET /status/health`. Authenticate and authorize each request independently in the C++ API; do not infer API access from having passed a frontend login screen or from frontend-only session state.
   - Flask may present the login experience and account-management pages, but each call it makes to the C++ API other than the liveness check must include a credential the API can validate. Apply the agreed role policy to every other API route and deny access by default when the caller is unauthenticated or lacks permission.
   - Protect browser form submissions and session handling against request forgery and session misuse as appropriate to the chosen design.
   - **Exit criteria:** backend tests cover missing, invalid, and valid credentials, role permissions, public-route exceptions, account lifecycle, login/logout, and login throttling; dashboard tests verify session handling, CSRF/Origin enforcement, and protected page access. `/status/health` remains available without credentials and returns no body. Any future frontend login state must not bypass backend authorization.
3. **Provide HTTPS support.**
   - Implement optional native TLS for the C++ API using operator-provisioned certificates. Validate certificate configuration and client-side API certificate trust explicitly. Keep browser-to-dashboard access loopback-only by default; document operator-managed reverse-proxy HTTPS for remote browser access.
   - **Exit criteria:** deployment documentation explains secure setup and certificate lifecycle; tests or integration checks confirm encrypted API connections, reject invalid TLS configuration, and verify loopback defaults for the dashboard.
4. **Add API rate limiting.**
   - **Implemented:** failed-login limits default to 5 attempts per source IP per 5 minutes; general API limits default to 120 requests per minute per source IP and authenticated identity; firewall mutations have an additional 30-per-minute limit per source IP and identity. The bounded, thread-safe in-memory fixed-window limiters return HTTP `429` with `Retry-After`, use the direct peer IP, ignore forwarded headers, and reset on backend restart. Health is exempt.
   - **Exit criteria:** tests verify configured limits, source and identity isolation for firewall mutations, the response contract, and health exemption. Tune defaults if deployment evidence shows normal authorized use is unintentionally blocked.
5. **Add replaceable backend and dashboard service contracts.**
   - **Status: In progress.** The backend `AuthProvider` interface and SQLite local-account implementation are implemented. Keep authentication-provider and backend/frontend logging-sink interfaces separate from HTTP handlers and Flask views. Add separate JSONL file sinks; leave OIDC and alternate sinks for later implementations.
   - Add a source-reader contract for API log sources and adapt the Archangel application log and nftables journal source to it. Preserve per-source availability and safe explanations, bounded output, and common redaction.
   - Formalize the dashboard HTTP transport and API-settings provider boundaries. Use deployment-fixed `ARCHANGEL_API_URL` configuration for the dashboard; keep API destination configuration separate from dashboard session and credential storage. The secured dashboard must not let browser users edit the API destination or redirect backend-held credentials. Keep API configuration separate from dashboard session/credential storage.
   - **Exit criteria:** implementations are selected at composition/configuration boundaries; contract tests exercise local account, file-sink, log-source, HTTP transport, and API-settings behavior using fakes where appropriate. No speculative plugin loader is introduced.
6. **Update security documentation and review the result.**
   - Update [SECURITY.md](../SECURITY.md), [endpoints.md](endpoints.md), and deployment instructions to distinguish implemented protections from remaining gaps.
   - **Exit criteria:** current posture, setup, route requirements, and remaining risks agree across documentation and implementation; verify the controls against the CIA triad and IAAA responsibilities, and complete a security review before recommending broader network exposure.

## Phase 3: Safe Firewall Management in the Dashboard

**Status: Planned**

The API already supports structured rule creation and deletion; the current dashboard is primarily read-oriented.

1. Add focused dashboard workflows to create and delete rules using the existing JSON API contract. Do not accept or construct raw nftables commands in browser input.
2. Show the exact target and effect of a proposed change and require a deliberate confirmation before applying mutations.
3. Handle validation failures, unavailable backends, stale rule handles, and permission denials with clear non-color-only status messages.
4. Keep API validation authoritative; the dashboard may improve usability but must not be treated as a security boundary.
5. **Exit criteria:** tests cover successful and rejected form submissions, and an authorized user can verify the target and result of each mutation. The UI never implies a change succeeded if the API rejected or failed it.

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
- Backend API communication with peer backends to form a mesh network, building on the Resource Gateway, Device Agent, Segmentation Gateway, and encrypted gateway-tunnel concepts described in [goal.md](goal.md).
- A centralized management backend that can enroll and manage multiple peer backends, with enrollment initiated using a scoped enrollment token and continuing through authenticated peer credentials.

For any item selected for development, first document the use case, trust boundaries, required data and permissions, failure behavior, privacy implications, operational impact, and API/UI contract. For centralized backend management and a mesh, also decide peer identity and authentication, authorization across peers, secure transport, discovery and membership, topology, configuration authority and propagation, and behavior when links or peers fail; do not assume that network location implies trust. Enrollment-token design must cover who may issue tokens, how tokens are delivered and bound to an intended enrollment, expiration and single-use or replay behavior, revocation, and how the exchange establishes durable peer credentials. Prefer high-entropy, short-lived bootstrap tokens used only over an authenticated protected channel, with least-privilege scope and explicit approval where appropriate; these are design criteria, not implemented controls or a final protocol choice. Then define testable acceptance criteria and update the relevant architecture, endpoint, security, and goal documentation. These concepts are not current capabilities.

The thesis discusses Swedish Armed Forces security-function requirements (KSF). It is not evidence that Archangel or a future deployment is KSF-compliant or certified. Any real deployment must be assessed against its applicable requirements, threat model, and component-specific security obligations.

## Decisions Still Open

- Which users and deployment environments should the first secured release support?
- What backend identity and credential-management model should be used, and how will administrators recover access?
- Should TLS terminate in the application, a trusted reverse proxy, or support both?
- What permission roles and rate-limit policy fit expected single-gateway and multi-gateway use?
- Which backend service-manager integrations and authorized operations, if any, should be supported by the System Management page? Define restart scope, authorization, and behavior before enabling controls.
- What should the centralized manager be authoritative for across managed backends, and which actions remain locally controlled?
- How should enrollment tokens be issued, scoped, delivered, expired, redeemed, and revoked, and how should they bootstrap durable peer identities and credentials?
- How should peer backends authenticate, authorize, discover, and securely communicate when forming a mesh?
- Which platforms and firewall implementations are in scope for a usable release?
- Which long-term network features are priorities, and which should remain out of scope?
- What availability and recovery requirements should apply to the PDP, SG, PKI, and security-log services?
