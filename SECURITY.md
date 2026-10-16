# Reporting a Security Flaw

If you believe you have found a security flaw in Archangel:

1. Do not publish the details in a public issue, pull request, discussion, or other public channel.
2. Report the suspected vulnerability through a private GitHub security advisory for this repository. If private reporting is unavailable, contact the repository maintainers privately.
3. Include the affected component and version or commit, impact, prerequisites, and concise reproduction steps. Redact credentials, personal data, and other sensitive information. Do not include data taken from systems you do not own or have permission to test.
4. Stop testing once you have enough evidence to explain the issue. Do not exploit the flaw against live systems, alter firewall rules, access other users' data, or cause service disruption.
5. If you operate an affected deployment, restrict access to the affected service while maintainers assess the report. Preserve relevant logs and configuration for investigation, and avoid making unreviewed firewall changes.

Archangel's current exposure and known security gaps are documented in [Current Security Concerns](docs/security-concerns.md). That document describes the implementation as it exists; it is not a security certification or a substitute for assessing a specific deployment.
