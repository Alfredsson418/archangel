# Exposed Endpoints
The C++ API runs separately from the Flask dashboard. The intended deployment places the privileged API binary on the server whose firewall it manages and allows the portable, Dockerized dashboard to run on a separate management computer. Configure the dashboard with an API base URL routable to that server; do not assume localhost refers to the same machine in a split-host setup. Flask reads the API directly while rendering pages and does not expose API passthrough routes. This separation is an architectural goal; the current API lacks authentication and HTTPS, so deployments must remain on localhost or a trusted, isolated management network.

## Flask Dashboard

### `GET /`

Renders the server overview with nftables enforcement status, backend version/connectivity, host identity, uptime, CPU load, memory, and disk metrics. It does not display individual firewall rules.

### `GET /rules`

Fetches the C++ ruleset in Flask and renders individual firewall rules on the Firewall Configuration page with the `rules.html` template.

Rules can be filtered across family, table, chain, handle, and expression, and sorted by family, table, chain, handle, or expression in ascending or descending order. Each row has a disabled Edit button; rule editing is not currently available.

### `GET /rules/export`

Downloads `archangel-firewall-rules.json`, a versioned JSON snapshot containing only active rules that can be represented using Archangel's structured rule API:

```json
{
  "format": "archangel-firewall-rules",
  "version": 1,
  "rules": [
    {
      "family": "inet",
      "table": "filter",
      "chain": "input",
      "protocol": "tcp",
      "destination_port": 443,
      "action": "accept"
    }
  ],
  "omitted_unsupported_rules": 2
}
```

The `omitted_unsupported_rules` count indicates rules from the active ruleset that cannot be represented by the structured API. Unsupported nftables expressions are omitted, not translated or preserved. Exported bundles do not include API URLs, service settings, or arbitrary nftables commands. The `X-Archangel-Skipped-Rules` response header provides the same count when nonzero.

### `GET, POST /rules/import`

`GET` renders the import page. `POST` with multipart form field `bundle_file` validates a JSON bundle and shows a preview; a separate confirmation submission is required before applying it. The importer accepts only the bundle format and version above, up to 512 KiB and 1,000 rules, and validates all rules before making backend requests. Bundles may contain zero rules, which is a no-op.

Import is additive: it calls `POST /api/v1/rules` once per rule and does not delete or replace existing rules. Each change takes effect immediately. These calls are not atomic; if a later API call fails, earlier rules remain applied and the page reports the partial count. A preview warns about rules omitted during export. The bundle is a portable snapshot only; it is not loaded automatically on backend startup and does not make nftables rules persistent across restarts. The preview/apply form uses a session-bound CSRF token and explicit confirmation; this is not backend authentication or authorization.

### `GET /system`

Renders the read-only System Management page with host resource information and Archangel backend version/process uptime. Restart controls are displayed as unavailable; this page does not issue service or host operations.

### `GET /system/logs`

Renders recent server-side logs grouped by source. It displays the Archangel application log and, when active nftables rules include `log` statements and the host kernel journal is readable, recent packet-log entries. Unavailable or unconfigured sources are shown with an explanation. Additional sources can be added independently.

### `GET, POST /config`

Renders and updates the dashboard's C++ API connection setting.

## C++ API

### `GET /status/health`

Returns HTTP `200` with an empty response body when the backend is online. No schema header or authentication is required; this endpoint is reserved for liveness checks and must remain unauthenticated.

### `GET /status/info`

Returns diagnostic status information as JSON:

```json
{
  "status": "ok",
  "backend_version": "16361d171dabbef97f6017cef5ce2c537d36864c",
  "api_version": "v1",
  "schema_version": 1,
  "uptime_seconds": 120
}
```

`backend_version` is the Git commit hash embedded when the backend binary is built; the example hash above is the current commit and will change with later builds from different commits. `uptime_seconds` is the number of seconds since the backend process started. This endpoint currently has no authentication, like the rest of the API, but is intended to require backend authentication and authorization in the future. Unlike `/status/health`, it must not be treated as a public liveness endpoint.

## API schema version

All API calls except `GET /status/health` must send the `X-Archangel-Schema-Version` request header. The backend validates it and returns the supported schema version in the same response header. The current schema version is `1`; a missing or unsupported version is rejected with HTTP `400` and a JSON error response. JSON response bodies retain their documented shapes; the header versions those shapes independently of the `/api/v1` API route version.

The health endpoint is deliberately exempt so basic liveness remains available without schema negotiation or authentication.

## Current authentication status

The API currently has no authentication or authorization. As a planned security control, backend authentication and authorization will be enforced on every API call other than `/status/health`, including `/status/info`, reads, and mutations. The frontend login alone must never grant API access; every other request must carry credentials or a verifiable backend-issued credential. Mutating endpoints apply changes immediately. See [Security](../SECURITY.md) before enabling access beyond localhost.

## Backend CLI configuration

The backend supports one-shot export and startup import using a versioned JSON config. A config contains:

```json
{
  "format": "archangel-backend-config",
  "version": 1,
  "server": {
    "interface": "127.0.0.1",
    "port": 8080
  },
  "firewall": {
    "ruleset": {
      "nftables": [
        { "metainfo": { "json_schema_version": 1 } },
        { "table": { "family": "inet", "name": "filter" } },
        { "chain": { "family": "inet", "table": "filter", "name": "input" } },
        { "rule": { "family": "inet", "table": "filter", "chain": "input", "expr": [{ "accept": null }] } }
      ]
    }
  }
}
```

The example shows the structure only; exported configs contain the complete ruleset objects and expressions. `server.interface` is the backend bind hostname/address used by `--host` (not necessarily a network-device name). The `--port` and `--host` command-line options override the imported values when explicitly supplied.

- `--export-config PATH` writes the current bind settings and complete active nftables JSON ruleset to PATH, then exits. Unlike the dashboard's rules-only portable bundle, it preserves rules outside Archangel's structured API subset.
- `--import-config PATH --rules-mode merge` imports the config before the API starts and adds its objects/rules to the active ruleset.
- `--import-config PATH --rules-mode replace` flushes the entire active nftables ruleset, including tables not created by Archangel, then applies the imported ruleset.
- Import mode is required for each import; accepted values are `merge` and `replace`. Import and export cannot be combined. Imported and exported files are limited to 16 MiB.

Both modes apply the nftables operations in one libnftables input transaction; a rejected transaction is reported as a failure. Merge may fail if imported objects conflict with current objects or elements. Replace is destructive and may disconnect clients or lock out administrators; review the JSON file and ensure recovery access before use. The input must follow the supported nftables JSON output schema; arbitrary nftables command strings are not executed by the application.

### `GET /api/v1/rules`

Returns the nftables ruleset as JSON. The caller must have permission to query nftables.

### `GET /api/v1/stats`

Returns statistics computed by the selected firewall backend from its active ruleset:

```json
{
	"total_rules": 8,
	"total_tables": 2,
	"total_chains": 4,
	"rules_by_family": {"inet": 8},
	"rules_by_protocol": {"tcp": 5, "udp": 3},
	"rules_by_verdict": {"accept": 5, "drop": 2, "other": 1}
}
```

### `GET /api/v1/system`

Returns the gateway hostname, online CPU core count, 1/5/15-minute load averages, memory totals/usage, root filesystem totals/usage, and uptime. Usage values are in bytes with percentages for memory and disk.

The dashboard determines whether nftables has base chains attached to packet-processing hooks from the chain metadata in the ruleset response. This reports whether hooked chains exist; it does not assess whether their policies are restrictive or effective. The overview displays only the summarized status; individual rules are shown on the Firewall Configuration page.

### `GET /api/v1/logs`

Returns a `sources` array. Each source has a stable `id`, display `label`, boolean `available`, explanatory `detail`, and an `entries` array containing recent log lines, newest first. Current sources are:

- `archangel`: up to 100 entries from `./app.log`, the current C++ logger's working-directory-relative output file.
- `nftables`: up to 100 recent kernel-journal lines matching packet-log fields, only when the active ruleset contains nftables `log` statements. This source uses `journalctl`; if logging is not configured or journal access is unavailable, the source reports the reason and returns no entries.

This endpoint does not enable firewall logging. Results are bounded, long lines are truncated, and common credential-like fields are redacted. Logs may still contain sensitive system or network details. The API currently has no authentication, so keep it and the dashboard on localhost or a trusted, isolated management network. Add future sources as separate source objects with explicit availability and failure details.

### `POST /api/v1/rules`

Adds one rule to an existing family/table/chain. The request is JSON; raw nftables commands are not accepted.

```json
{
	"family": "inet",
	"table": "filter",
	"chain": "input",
	"protocol": "tcp",
	"source_address": "192.0.2.10",
	"destination_port": 443,
	"action": "accept"
}
```

`source_address`, `destination_address`, and `destination_port` are optional, but at least one match is required. Supported families are `ip`, `ip6`, and `inet`; protocols are `tcp` and `udp`; verdicts are `accept`, `drop`, and `reject`. Success returns HTTP `201`.

### `DELETE /api/v1/rules`

Deletes a rule by its family, table, chain, and numeric handle:

```json
{
	"family": "inet",
	"table": "filter",
	"chain": "input",
	"handle": 12
}
```
