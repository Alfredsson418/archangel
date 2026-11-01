# Current Security Concerns

This document summarizes security limitations visible in the current Archangel implementation and deployment configuration, reviewed on 2026-11-01. It is a living status document, not a penetration-test report, vulnerability disclosure, compliance claim, or complete threat assessment. Risk labels are relative priorities for addressing the concerns, not CVSS ratings.

## At a Glance

| Priority | Current concern | Current status |
| --- | --- | --- |
| Critical | Unauthenticated firewall control API and dashboard | No user authentication or authorization is implemented. API schema-version checks are not access controls. |
| High | Unprotected network transport | The C++ API serves plain HTTP; the project does not configure TLS termination. |
| High | Browser-accessible configuration and mutation surfaces | Dashboard routes have no login; the connection-settings form has no CSRF token. |
| High | Privileged, immediate firewall changes | Rule changes take effect immediately; dashboard bundle imports consist of separate, non-atomic API calls. CLI config import uses nftables transactions but remains privileged. |
| Medium | Log confidentiality and audit limitations | The unauthenticated logs endpoint exposes bounded application and packet logs; redaction is partial. |
| Medium | Availability controls and verification gaps | No API rate limiting is implemented. Automated C++ unit tests cover selected parsing and HTTP-handler behavior but do not constitute broad integration, fuzz, or security testing. |
| Medium | Session and deployment configuration | The Flask session key defaults to a per-process random value; the session cookie is not explicitly marked Secure. |

These priorities assume the API or dashboard can be reached by an untrusted party. Binding to localhost reduces network exposure but does not add authentication and is not sufficient for a deployment that intentionally exposes either service to a network.

## Current Concerns

### 1. The API and dashboard have no authentication or authorization — Critical

The C++ API registers firewall reads and mutations, host information, status, and logs without authenticating callers or checking permissions. In particular, callers able to reach the API can request `POST /api/v1/rules` and `DELETE /api/v1/rules`. The separate `/status/info` endpoint is also unauthenticated. The `X-Archangel-Schema-Version` header validates the API contract only; it does not identify or authorize a caller.

The Flask dashboard has no login or user authorization either. Its server-rendered pages call the C++ API, but restricting a page or adding a frontend login alone would not protect direct API requests. Until backend access controls exist, keep both services on localhost or an isolated, trusted management network, including traffic between separate computers. Do not expose either service to the public internet.

The liveness endpoint `GET /status/health` is intentionally public and returns no response body. It should remain the narrow exception when backend authentication is implemented.

### 2. Network traffic is not protected by project-configured TLS — High

The C++ service uses a plain HTTP server. The dashboard accepts an HTTP or HTTPS API base URL, but that validation does not provide TLS for the C++ service. The supplied same-host Compose setup uses host networking and loopback defaults; separate-host operation requires explicit network configuration and currently has no built-in authenticated or encrypted API transport.

On an untrusted network, requests and responses can be observed or modified in transit. This is especially serious because API requests can change firewall rules. Keep service-to-service and browser-to-dashboard traffic on localhost or a trusted, isolated management network until an appropriate TLS deployment and backend authentication model are implemented. HTTPS at a reverse proxy, if independently configured by an operator, is not configured or guaranteed by this repository.

### 3. Dashboard settings and browser state are not protected by a login — High

The `/config` form accepts a submitted HTTP(S) API base URL and persists it for later dashboard requests. The route has no authentication or CSRF token. A party that can reach the dashboard can change which backend the dashboard contacts. Because the dashboard makes server-side requests to the configured address, accepting arbitrary destinations also creates a server-side request-forgery and internal-network probing risk if the dashboard is exposed or its settings can be changed by an untrusted party.

The firewall import workflow does require a session-bound CSRF token and explicit confirmation, but this only protects that workflow against cross-site form submission; it is not user authentication or API authorization. Other future state-changing dashboard forms must not be assumed protected by that import-specific token.

The Flask session cookie is configured `HttpOnly` and `SameSite=Lax`, but `Secure` is not explicitly enabled. The session signing key comes from `FLASK_SECRET_KEY` or is generated randomly for each application process. A deployment with multiple workers or restarts should configure a stable secret shared by the workers; otherwise session-backed import previews may fail across workers or become invalid after restart. This key does not currently represent a user credential because the app has no login.

### 4. Firewall changes have immediate host impact — High

The C++ backend can add and delete active firewall rules. The effective operating-system privileges depend on how the binary is launched, but it must have sufficient privilege to perform its firewall operations. Compromise or misuse of an API process with those privileges can affect host or network availability. Run the backend with only the privileges it needs and protect its host and management network.

Rule updates take effect immediately and are not automatically rolled back. The dashboard portable-rules importer validates and previews the bundle, then submits rules individually. If a later request fails, earlier rules remain applied; there is no batch transaction or rollback. Its export omits rules that the structured API cannot represent.

The backend CLI exports and imports version 2 JSON configs containing the complete active nftables ruleset and bind settings. Config v2 separates rules bearing the reserved `archangel-managed` nftables comment from other rules and objects. `--rules-mode replace` atomically replaces marked rules only, leaving external rules and objects untouched; referenced tables and chains must already exist. `--rules-mode replace-all` explicitly flushes the entire active ruleset and may disconnect clients or lock out administrators. Review imported files and confirm recovery access before using full replacement. The ownership comment is a categorization marker, not an authentication or authorization control. Neither the dashboard bundle nor the CLI JSON config is automatically restored after reboot unless an operator configures the startup command or service accordingly.

The System Management page is currently read-only. It does not restart or otherwise control the host.

### 5. Logs may reveal sensitive information; redaction is limited — Medium

The unauthenticated `/api/v1/logs` endpoint exposes recent Archangel application-log entries and, when configured rules generate packet logs, recent matching kernel-journal entries. These can reveal host details, network addresses, and operational behavior. The backend bounds the returned entries and applies pattern-based redaction to common credential-like fields, but this is not comprehensive secret detection and must not be treated as a confidentiality boundary.

The current API request logs record method, fixed path, status, duration, and some operation outcomes. Since callers are not authenticated, requests cannot be attributed to a verified identity. No tamper-resistant audit-log storage or retention policy is implemented. Do not place credentials or secrets in log messages; restrict log and dashboard access as carefully as other host information.

### 6. Denial-of-service and security verification controls are incomplete — Medium

The API does not implement request rate limiting or per-identity quotas. This is especially relevant while endpoints are unauthenticated: a reachable service can be repeatedly queried or asked to perform privileged operations. No security or capacity guarantee should be inferred from the liveness endpoint.

The dashboard unittest suite and `make test` provide automated coverage for selected frontend behavior, config parsing/serialization, nftables statistics parsing, and API handlers. They do not provide broad integration, fuzz, authorization, or live nftables tests. Ordinary tests must remain isolated from privileged host firewall state; security-sensitive changes need focused tests and an appropriate non-production integration environment.

### 7. Listener exposure depends on deployment configuration

The C++ API defaults to `localhost:8080`, and the Flask development entry point defaults to `127.0.0.1:8081`; these defaults reduce remote exposure on a single host but do not add access control. Both services can be configured differently. The supplied Compose file uses host networking with a loopback dashboard bind. Changing bind addresses, publishing ports, adding a reverse proxy, or deploying the services on separate hosts changes the reachable attack surface and must be reviewed before use.

The portable-dashboard deployment model is intentional, but portability does not itself make remote connections safe. A remotely deployed dashboard must only reach its intended backend over a trusted management network until authentication and protected transport are available.

## Planned Security Work

The following controls are planned or required by the project guidance but are not implemented protections:

- **Selected direction, not implemented:** use a backend-owned authentication-provider abstraction, implement SQLite-backed local accounts first, and retain OIDC as a future provider option. Hash passwords with Argon2id via a maintained library. Provide privileged interactive `user bootstrap-admin` (only when no active admin exists) and `user recover` CLI commands; recovery may bypass API last-admin safeguards. Prompt securely on a TTY, never accept passwords in command-line arguments, and ship no default credentials. Provide authenticated administrator API account management. Account deletion is disable-only; preserve immutable user IDs for audit attribution and never reuse them. Do not maintain a separate frontend identity store; API operations cannot disable the last active administrator.
- Dashboard account creation and password reset use backend-generated single-use setup tokens, shown once to the administrator for out-of-band delivery. Store only token hashes, never log tokens, and require the account holder to set their own password.
- Setup tokens expire after one hour; allow only one outstanding token per account. New accounts remain pending until password setup completes. Only administrators initiate resets; reset initiation revokes sessions and invalidates prior tokens. Disabled accounts cannot redeem tokens; after setup the user performs a normal login.
- Use the OWASP Argon2id baseline (19 MiB memory, 2 iterations, parallelism 1). Runtime configuration may raise but must not lower these values. Store encoded parameters with each hash and rehash after successful authentication when configured cost increases; benchmark stronger settings to avoid login-driven availability issues.
- Store local accounts, opaque API sessions, and schema metadata in a runtime-configurable SQLite database, default `/var/lib/archangel/archangel.db`. Require a service-owned parent directory with mode `0700` and DB file mode `0600`; fail if unsafe. Use SQLite online backup or stop the service before copying; version migrations and fail startup if migration fails.
- Require at least 15-character passwords, allow passphrases up to 128 characters, avoid arbitrary composition rules or forced periodic rotation, and reject known common/compromised passwords where feasible.
- Require only username and password; do not require email, phone, or other personal data. Assign immutable random UUID user IDs. Usernames use ASCII letters/digits plus `._-`, 3–64 characters, are case-insensitive and normalized, and cannot be reused after disablement. Use generic login failures for unknown, disabled, and incorrect-password accounts and perform dummy Argon2id verification for nonexistent users. Initial authentication is password-only; MFA is deferred and password compromise remains a residual risk.
- Use backend-enforced `viewer`, `operator`, and `administrator` roles. Viewers read rules, statistics, system information, and logs; operators can also change firewall rules; administrators can also manage authentication accounts/settings. Deny by default. Keep `GET /status/health` as the only anonymous data endpoint; credential-submission routes must be limited to authentication operations and rate-limited.
- Use a Flask backend-for-frontend flow with a 256-bit CSPRNG opaque API session token returned only at login; store only its SHA-256 hash in the private backend SQLite DB and never log it. Keep the token in `/data/sessions.db` (configurable) in a dedicated server-side SQLite browser-session store on the dashboard host. This store contains session credentials only, not identities or password hashes, and requires an owner-only directory and database file. Loss invalidates browser sessions and requires reauthentication; no session DB backup is required. Backend session lifetimes are configurable, initially 15 minutes idle and 8 hours absolute, and sessions are revoked on logout or account/security changes. Authenticate and authorize each protected API request independently.
- Protect dashboard sessions with an opaque `HttpOnly`, `SameSite=Lax` cookie; enable `Secure` when served behind operator-managed HTTPS, but keep it off for default loopback HTTP. Rotate the browser session ID after login and privilege changes. Require CSRF tokens on every state-changing dashboard form, including login/logout, settings, and account management; validate `Origin` where available. Keep the cookie/session signing key in a protected file or environment variable, not config/source; production startup fails if absent, while local development may use an ephemeral key that invalidates sessions on restart.
- Add optional native TLS for the C++ API, disabled by default for local development, with operator-provisioned certificate/key paths in backend runtime config. Require TLS 1.2 or newer; when enabled, missing or invalid cert/key files fail startup rather than falling back to HTTP. The private key is readable only by the backend service account. Certificates load at startup; operator restarts the backend after renewal. The dashboard validates hostname and certificate using system trust plus an optional private CA bundle selected by a deployment environment variable such as `ARCHANGEL_API_CA_BUNDLE` pointing to a read-only-mounted PEM file; verification cannot be disabled. Recommend enabling TLS in production. Keep the dashboard loopback-bound by default; remote browser access requires operator-managed reverse-proxy HTTPS.
- A non-loopback API listener without TLS is allowed by the selected design but must produce a prominent startup warning. This remains plaintext and exposes credentials and API traffic to network interception/modification; it is not a secure production configuration.
- Add configurable rate limits with initial defaults of 5 failed authentication attempts per source IP per 5 minutes, 120 API requests per minute per identity and source IP, and 30 firewall mutations per minute per identity and IP. Use bounded, expiring, thread-safe in-memory token buckets; counters reset on backend restart. Do not permanently lock accounts. Use direct peer IP only and ignore forwarded headers. Return JSON HTTP `429` with `Retry-After`; exempt health.
- Add a separate, strictly validated versioned JSON runtime configuration (`format: "archangel-runtime-config"`, version 1) with `server`, `auth`, `sessions`, `tls`, `logging`, and `rate_limits` sections. It covers persistent backend settings; omitted fields use documented defaults, while unknown keys, unsupported versions, wrong types, and invalid files fail startup. Dashboard-only settings, including its private CA bundle, browser-session DB, and session-signing key, are configured on the dashboard host. Keep runtime config separate from privileged firewall import/export; import/export are explicit CLI operations only. Never store password or private-key contents in config.
- Use `/etc/archangel/config.json` as the implicit default runtime-config path. If it is absent, use built-in defaults; if present but invalid, unreadable, or group/world writable, fail startup. An explicit `--config PATH` must exist and pass validation. Require service/root ownership and prohibit group/world writes.
- Add replaceable logging backends to both services. Start with separate configurable JSONL append files: backend default `/var/log/archangel/backend.jsonl`, dashboard default `/data/archangel-frontend.jsonl`. Include timestamp, level, service, event, actor ID when known, operation, outcome, request ID, and source IP on every request. Never log credentials, request/response bodies, submitted values, or raw rules. IPs are privacy-sensitive; restrict access and retain compressed rotations for 30 days by default, configurable by operators. Require owner-only access and OS-managed rotation; reopen safely on rotation without `copytruncate`. Consider journald/syslog or a protected append-only sink as future adapters. Ordinary append files are not tamper-evident.
- If a configured log sink cannot open at startup, fail startup. At runtime, log-write failures emit sanitized stderr diagnostics, block protected/mutating operations, and leave only bodyless health available until recovery. Require the audit intent event before privileged mutation; outcome logging can still fail after an already-completed operation, which cannot be rolled back.
- Complete the threat model and CIA/IAAA assessment, including operational dependencies and residual risks. The local provider avoids a mandatory external identity-service dependency; TLS certificate failures, rate limits, file-log alteration, privileged misuse, and added provider/sink abstractions remain relevant risks.
- OIDC claim-to-role mapping remains deferred until OIDC is selected for implementation. MFA is deferred; the initial design uses username/password only.
- Dashboard session protections are selected: CSRF tokens on all state-changing forms, session rotation, and secure cookie configuration when HTTPS is used. Fix the API destination at deployment through `ARCHANGEL_API_URL`; do not allow browser users to edit it, which could redirect backend-held credentials to an arbitrary host. Enforce the approved security policy without allowing TLS-verification bypass.
- Expand the automated C++ unit tests and add appropriate security-focused checks without allowing ordinary tests to alter a live firewall.

The [security-control roadmap](roadmap.md#phase-2-backend-owned-security-controls) tracks the planned backend-owned authentication, HTTPS, and rate-limiting work. Design choices that affect identity, credentials, trust boundaries, or deployment should be decided before implementation.

## Design Principles

Security controls should be proportionate to the threats they address. New components can add attack surface, configuration hazards, and maintenance burden; complexity can itself increase risk. Prefer the simplest effective control, state residual risk, and consider operational recovery and availability as well as access prevention.

The thesis [Zero Trust i isolerade komplexa miljöer](../assets/Zero_Trust_i_Komplexa_Isolerade_Miljöer.pdf) provides long-term architectural context, including mutually authenticated gateway links, policy decision and enforcement points, microsegmentation, session review, and protected security logging. Those ideas are not current controls or evidence of compliance. Any future design must account for availability, recovery, key and certificate lifecycle, control-plane protection, and log integrity.
