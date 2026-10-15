# Security

Archangel's C++ API can add and delete host firewall rules. Treat it as privileged control-plane software.

- The API has no authentication or authorization. Keep it bound to localhost or an isolated management network; do not expose it to the public internet.
- Run Archangel only with the privileges required to query and modify nftables. Prefer a dedicated host or VM while developing rules.
- `POST /api/v1/rules` accepts a structured rule description. It does not accept raw nftables commands. Supported protocols are TCP and UDP, and supported verdicts are accept, drop, and reject.
- `DELETE /api/v1/rules` deletes the rule identified by family, table, chain, and numeric handle. Confirm the target before issuing a request.
- Use `GET /api/v1/rules` to inspect the active ruleset before and after changes. Rule changes are applied immediately and are not automatically rolled back.
- The Flask dashboard also has no authentication. Keep it on localhost or a trusted management network.

Report suspected vulnerabilities through a private security advisory rather than a public issue.
