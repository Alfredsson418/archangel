# Current Security Concerns

This document summarizes security limitations visible in the current Archangel implementation and deployment configuration, reviewed on 2026-10-16. It is a living status document, not a penetration-test report, vulnerability disclosure, compliance claim, or complete threat assessment. Risk labels are relative priorities for addressing the concerns, not CVSS ratings.

## At a Glance

| Priority | Current concern | Current status |
| --- | --- | --- |
| Critical | Unauthenticated firewall control API and dashboard | No user authentication or authorization is implemented. API schema-version checks are not access controls. |
| High | Unprotected network transport | The C++ API serves plain HTTP; the project does not configure TLS termination. |
| High | Browser-accessible configuration and mutation surfaces | Dashboard routes have no login; the connection-settings form has no CSRF token. |
| High | Privileged, immediate firewall changes | Rule changes take effect immediately; imports consist of separate, non-atomic API calls. |
| Medium | Log confidentiality and audit limitations | The unauthenticated logs endpoint exposes bounded application and packet logs; redaction is partial. |
| Medium | Availability controls and verification gaps | No API rate limiting is implemented, and the repository has no automated C++ test target. |
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

The backend CLI can export the complete active nftables ruleset and bind settings with `--export-config PATH`, and apply a versioned JSON config with `--import-config PATH --rules-mode merge|replace` before serving. Merge can fail on conflicting objects. Replace flushes the entire active ruleset, including tables not created by Archangel, and may disconnect clients or lock out administrators. Review imported files and confirm recovery access before choosing replace. Neither the dashboard bundle nor the CLI JSON config is automatically restored after reboot unless an operator configures the startup command or service accordingly.

The System Management page is currently read-only. It does not restart or otherwise control the host.

### 5. Logs may reveal sensitive information; redaction is limited — Medium

The unauthenticated `/api/v1/logs` endpoint exposes recent Archangel application-log entries and, when configured rules generate packet logs, recent matching kernel-journal entries. These can reveal host details, network addresses, and operational behavior. The backend bounds the returned entries and applies pattern-based redaction to common credential-like fields, but this is not comprehensive secret detection and must not be treated as a confidentiality boundary.

The current API request logs record method, fixed path, status, duration, and some operation outcomes. Since callers are not authenticated, requests cannot be attributed to a verified identity. No tamper-resistant audit-log storage or retention policy is implemented. Do not place credentials or secrets in log messages; restrict log and dashboard access as carefully as other host information.

### 6. Denial-of-service and security verification controls are incomplete — Medium

The API does not implement request rate limiting or per-identity quotas. This is especially relevant while endpoints are unauthenticated: a reachable service can be repeatedly queried or asked to perform privileged operations. No security or capacity guarantee should be inferred from the liveness endpoint.

The dashboard has an automated unittest suite, but the repository currently has no automated C++ test target. This limits repeatable coverage of API parsing, authorization (which is not implemented), and host-operation behavior. Ordinary tests must remain isolated from privileged host firewall state; security-sensitive changes need focused tests and an appropriate non-production integration environment.

### 7. Listener exposure depends on deployment configuration

The C++ API defaults to `localhost:8080`, and the Flask development entry point defaults to `127.0.0.1:8081`; these defaults reduce remote exposure on a single host but do not add access control. Both services can be configured differently. The supplied Compose file uses host networking with a loopback dashboard bind. Changing bind addresses, publishing ports, adding a reverse proxy, or deploying the services on separate hosts changes the reachable attack surface and must be reviewed before use.

The portable-dashboard deployment model is intentional, but portability does not itself make remote connections safe. A remotely deployed dashboard must only reach its intended backend over a trusted management network until authentication and protected transport are available.

## Planned Security Work

The following controls are planned or required by the project guidance but are not implemented protections:

- Define a threat model and security design that weighs the CIA triad—confidentiality, integrity, and availability—and IAAA access-control principles—identification, authentication, authorization, and accounting. Evaluate the added attack surface and operational complexity of each control.
- Make the backend authoritative for identity and authorization. Authenticate and authorize each API request independently, except the bodyless `GET /status/health` liveness endpoint. This includes `/status/info`, reads, logs, and mutations. Do not create a separate frontend user-authentication database.
- Provide an HTTPS option for service endpoints, with explicit certificate configuration and lifecycle responsibilities.
- Add API rate limiting with documented behavior and tests.
- Decide and implement the required protections for dashboard state-changing forms and API URL configuration as part of the authentication and deployment design. Consider how configured backend destinations are constrained to avoid unintended server-side requests.
- Define the audit events, identity attribution, protection, and retention required for accounting and incident investigation.
- Add automated C++ API tests and appropriate security-focused checks without allowing ordinary tests to alter a live firewall.

The [security-control roadmap](roadmap.md#phase-2-backend-owned-security-controls) tracks the planned backend-owned authentication, HTTPS, and rate-limiting work. Design choices that affect identity, credentials, trust boundaries, or deployment should be decided before implementation.

## Design Principles

Security controls should be proportionate to the threats they address. New components can add attack surface, configuration hazards, and maintenance burden; complexity can itself increase risk. Prefer the simplest effective control, state residual risk, and consider operational recovery and availability as well as access prevention.

The thesis [Zero Trust i isolerade komplexa miljöer](../assets/Zero_Trust_i_Komplexa_Isolerade_Miljöer.pdf) provides long-term architectural context, including mutually authenticated gateway links, policy decision and enforcement points, microsegmentation, session review, and protected security logging. Those ideas are not current controls or evidence of compliance. Any future design must account for availability, recovery, key and certificate lifecycle, control-plane protection, and log integrity.
