# Development Roadmap

This roadmap separates work that follows from the current implementation from longer-term concepts. It is directional, not a delivery schedule: priorities and designs may change as the project develops. A task is complete only when the behavior exists in the repository and its stated verification is satisfied.

## Current Baseline

The repository currently provides:

- A C++ HTTP API with a backend-neutral `Firewall` interface and an nftables implementation.
- JSON endpoints for listing, adding, and deleting firewall rules, plus firewall statistics and host system information.
- A versioned API endpoint returning bounded, source-grouped Archangel application logs and conditional nftables packet logs from the kernel journal.
- A bodyless `/status/health` liveness endpoint, a versioned JSON `/status/info` endpoint, and a schema-version header on API calls. Make embeds the current Git commit hash in the backend binary.
- A Flask dashboard with a server-health overview, a Firewall Configuration page for individual rules, a read-only System Management page with a source-grouped Logs subpage, and API connection configuration. It calls the C++ API server-side.
- Backend CLI one-shot export/import of a versioned JSON config containing bind settings and the full nftables JSON ruleset. Every import requires an explicit merge or whole-ruleset replace mode.
- The Firewall Configuration page can filter and sort active rules and provides a disabled Edit control. It can export and preview-import versioned, rules-only bundles; imports are additive and non-atomic, and exports omit unsupported nftables rules.
- The overview summarizes nftables base-chain hook status without rendering firewall rules. The System Management page reports host and backend status; restart controls are not operational because authenticated service control and a deployment-specific service-manager integration are not yet designed.
- The services are independently deployable in design: the privileged binary belongs on the managed server, while the Dockerized dashboard is intended to remain portable and may run on a separate management computer. The current Compose configuration is a same-host development setup, not a validated remote deployment recipe.
- Structured application logging and a dashboard unittest suite.

The C++ API and Flask dashboard currently have no authentication or authorization. Firewall rule mutations are privileged and take effect immediately. Keep both services on localhost or an isolated, trusted management network; when deployed on separate computers, ensure their communication and dashboard access stay within that trusted network. Do not expose them to the public internet. See [SECURITY.md](../SECURITY.md) and [endpoints.md](endpoints.md).

## Phase 1: Testing and Contribution Readiness

**Status: In progress**

1. **Add automated C++ tests.**
   - Test API request parsing and validation, status codes, and JSON responses without changing the host firewall.
   - Test backend-neutral behavior and nftables statistics parsing using controlled fixtures.
   - Keep tests isolated from privileged host state; destructive operations must never run in ordinary test suites.
   - **Exit criteria:** a documented test command runs the C++ tests and returns a failing status for a failing test; the debug build and dashboard tests continue to pass.
2. **Add a repeatable project verification workflow.**
   - Document the build and test commands, required system dependencies, and any tests that require special environments.
   - Add continuous integration for the supported build and test commands once the required runner dependencies are known.
   - **Exit criteria:** a clean checkout can follow the documented local verification steps, and CI reports build and test outcomes.
3. **Publish contribution guidance.**
   - Add `CONTRIBUTING.md` with issue-first feature discussion, build/test steps, code and documentation expectations, and security reporting guidance.
   - Add a Code of Conduct and explain how to report conduct concerns.
   - **Exit criteria:** contribution and conduct documents are linked from the README and state clear reporting paths.
4. **Other**
   - For export/import system/firewall config, seperate firewall rules in the config between other rules and archangel rules

## Phase 2: Backend-Owned Security Controls

**Status: Planned; design decisions are open**

Security controls must be enforced at the backend/API trust boundary. The backend is authoritative for identity, authentication, and authorization. Do not create a separate Flask dashboard or browser user-authentication database. `GET /status/health` is the deliberate exception: it remains unauthenticated and returns only a status code for liveness. `GET /status/info` and every other API route are intended to require backend authentication once controls are implemented. Until then, retain the deployment restrictions in [SECURITY.md](../SECURITY.md).

1. **Decide and document the security model before implementation.**
   - Treat security as a major concern throughout the project. Assess each design against the CIA triad: confidentiality, integrity, and availability.
   - Apply IAAA access-control principles: identification, authentication, authorization, and accounting. Define what identities are represented, how they are authenticated, what each identity may do, and what security-relevant events are recorded.
   - Compare the expected reduction in security risk with the attack surface, configuration risk, operational burden, and maintenance complexity introduced by each control. Prefer the simplest effective design, not complexity for its own sake.
   - Define the threat model, supported deployment topologies, identity provisioning and recovery, credential/session handling, and the API-to-dashboard authentication flow.
   - Define which operations require which permissions, including read-only access, firewall mutations, and diagnostic status. Keep the minimal `/status/health` liveness check public and free of sensitive details.
   - Decide how HTTPS is provided for browser-to-dashboard and dashboard-to-API traffic, including certificate configuration and renewal responsibilities.
   - Define rate-limit scope and behavior, including how authenticated identities and unauthenticated requests are treated.
   - **Exit criteria:** the decisions, threat analysis against confidentiality/integrity/availability, IAAA responsibilities, complexity tradeoffs, and remaining risks are documented before selecting protocols or storage details; no proposed design depends on frontend-only access checks.
2. **Implement backend authentication and authorization.**
   - Require credentials or a verifiable backend-issued credential on every API call except `GET /status/health`. Authenticate and authorize each request independently in the C++ API; do not infer API access from having passed a frontend login screen or from frontend-only session state.
   - Flask may present the login experience, but each call it makes to the C++ API other than the liveness check must include a credential the API can validate. Apply explicit authorization to every other API route and deny access by default when the caller is unauthenticated or lacks permission.
   - Protect browser form submissions and session handling against request forgery and session misuse as appropriate to the chosen design.
   - **Exit criteria:** tests cover missing, invalid, and valid credentials plus allowed and denied permissions for every authenticated route, including reads and `/status/info`; tests also verify `/status/health` remains available without credentials and returns no body; bypassing or skipping the frontend login cannot grant access to other API routes; identity and permissions are not independently managed by the dashboard.
3. **Provide HTTPS support.**
   - Implement the selected TLS deployment option for the documented service boundaries and validate certificate/configuration failures explicitly.
   - **Exit criteria:** deployment documentation explains secure setup and certificate lifecycle; tests or integration checks confirm encrypted connections and reject invalid TLS configuration.
4. **Add API rate limiting.**
   - Enforce limits at the backend/API boundary, with policy chosen in the security design and safe behavior under concurrent requests.
   - Return and document consistent rate-limit responses without logging credentials or sensitive request data.
   - **Exit criteria:** tests verify the configured limit, response contract, and recovery after the limiting window; normal authorized use is not unintentionally blocked.
5. **Update security documentation and review the result.**
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

**Status: Planned; scope depends on supported deployment targets**

1. Define supported Linux distributions, nftables/library versions, deployment modes, and minimum resource/privilege requirements.
2. Document installation, configuration, upgrades, backup/recovery, service operation, and safe rollback expectations. Do not imply firewall changes are automatically rolled back unless implemented.
3. Review error handling, logging, configuration validation, and observability across both services; ensure diagnostics do not expose credentials, request bodies, or raw firewall rule input.
4. Assess additional firewall backends only when a concrete platform and capability set is selected; preserve the backend-neutral `Firewall` contract and test backend parity.
5. **Exit criteria:** supported environments and operational procedures are explicit, and each supported backend has automated contract coverage.

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

For any item selected for development, first document the use case, trust boundaries, required data and permissions, failure behavior, privacy implications, operational impact, and API/UI contract. For a backend mesh, also decide peer identity and authentication, authorization across peers, secure transport, discovery and membership, topology, and behavior when links or peers fail; do not assume that network location implies trust. Then define testable acceptance criteria and update the relevant architecture, endpoint, security, and goal documentation. These concepts are not current capabilities.

The thesis discusses Swedish Armed Forces security-function requirements (KSF). It is not evidence that Archangel or a future deployment is KSF-compliant or certified. Any real deployment must be assessed against its applicable requirements, threat model, and component-specific security obligations.

## Decisions Still Open

- Which users and deployment environments should the first secured release support?
- What backend identity and credential-management model should be used, and how will administrators recover access?
- Should TLS terminate in the application, a trusted reverse proxy, or support both?
- What permission roles and rate-limit policy fit expected single-gateway and multi-gateway use?
- Which backend service-manager integrations and authorized operations, if any, should be supported by the System Management page? Define restart scope, authorization, and behavior before enabling controls.
- How should peer backends authenticate, authorize, discover, and securely communicate when forming a mesh?
- Which platforms and firewall implementations are in scope for a usable release?
- Which long-term network features are priorities, and which should remain out of scope?
- What availability and recovery requirements should apply to the PDP, SG, PKI, and security-log services?
