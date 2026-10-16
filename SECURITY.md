# Security

Security is a major concern for Archangel because its backend can make immediate, privileged changes to a host firewall. Security controls and implementations should be designed and reviewed against the CIA triad—confidentiality, integrity, and availability—and IAAA access-control principles: identification, authentication, authorization, and accounting. These are design requirements, not a claim that the planned controls are already implemented.

Controls should be proportionate to the threats they address. New mechanisms can themselves increase attack surface, create configuration hazards, and make secure operation harder through added complexity. Designs should weigh that residual risk and operational burden against the expected security benefit, and prefer the simplest effective control rather than adding mechanisms without a clear purpose.

The thesis [Zero Trust i isolerade komplexa miljöer](assets/Zero_Trust_i_Komplexa_Isolerade_Miljöer.pdf) is a source of long-term architectural ideas, including mutually authenticated gateway links, policy decision and enforcement points, microsegmentation, session review, and protected security logging. It also identifies high impact from failures or compromise of central decision/gateway services and the PKI. These ideas are not current controls or a compliance claim. Any future design must address availability, recovery, key/certificate lifecycle, control-plane protection, and log integrity as well as access prevention. See the [project goal](docs/goal.md) and [roadmap](docs/roadmap.md).

## If You Detect a Security Flaw

1. Do not publish the details in a public issue, pull request, discussion, or other public channel.
2. Report the suspected vulnerability through a private GitHub security advisory for this repository. If private reporting is unavailable, contact the repository maintainers privately.
3. Include the affected component and version or commit, impact, prerequisites, and concise reproduction steps. Redact credentials, personal data, and other sensitive information. Do not include data taken from systems you do not own or have permission to test.
4. Stop testing once you have enough evidence to explain the issue. Do not exploit the flaw against live systems, alter firewall rules, access other users' data, or cause service disruption.
5. If you operate an affected deployment, restrict access to the affected service while maintainers assess the report. Preserve relevant logs and configuration for investigation, and avoid making unreviewed firewall changes.

## Current Security Posture

Archangel's C++ API can add and delete host firewall rules and should be treated as privileged control-plane software. The API and Flask dashboard currently have no authentication or authorization. Keep them bound to localhost or an isolated, trusted management network; do not expose them to the public internet. Run the API only with the privileges needed to query and modify nftables. Rule changes take effect immediately and are not automatically rolled back.

## Planned Security Work

The planned security model requires the backend to authenticate and authorize every API call independently, including read and health/status requests. A frontend login screen or its session state must not be sufficient to access an API; each call must present credentials or a verifiable backend-issued credential, and the backend must check permissions for that request. The dashboard must not maintain a separate user-authentication database.

The [development roadmap](docs/roadmap.md#phase-2-backend-owned-security-controls) describes the planned security work and its sequencing. These controls are not yet implemented:

- Add backend/API-managed authentication and permission-based access control. The backend must be authoritative for identity and access decisions; do not introduce a separate Flask dashboard or browser user-authentication database.
- Add an HTTPS option for endpoints.
- Add rate limiting to endpoints.
