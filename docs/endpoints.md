# Exposed Endpoints
The C++ API runs separately from the Flask dashboard. The intended deployment places the privileged API binary on the server whose firewall it manages and allows the portable, Dockerized dashboard to run on a separate management computer. Configure the dashboard with an API base URL routable to that server; do not assume localhost refers to the same machine in a split-host setup. Flask reads the API directly while rendering pages and does not expose API passthrough routes. The C++ API requires backend authentication on every route except `GET /status/health`, `POST /api/v1/auth/login`, and `POST /api/v1/auth/setup`. The dashboard obtains backend sessions through its login flow and sends them with protected calls. API traffic is still plain HTTP; keep both services on localhost or a trusted, isolated management network.

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

### `GET /config`

Shows the C++ API base URL the dashboard uses and where it came from (`ARCHANGEL_API_URL` or the built-in default). The page is read-only: the destination is fixed at deployment so browser users cannot redirect the backend credentials the dashboard holds, and `POST` returns HTTP `405`.

### `GET /healthz`

Returns an empty HTTP `204` without requiring a dashboard login. The container health check uses it; it does not contact the C++ API or create a session.

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

`backend_version` is the Git commit hash embedded when the backend binary is built; the example hash above is the current commit and will change with later builds from different commits. `uptime_seconds` is the number of seconds since the backend process started. Unlike `/status/health`, this endpoint requires an authenticated Bearer session.

### `POST /api/v1/auth/login`

Public endpoint for exchanging local account credentials for an opaque backend session. It requires the API schema header and a JSON body:

```json
{
  "username": "admin",
  "password": "operator-entered-password"
}
```

Success returns HTTP `200` with the token and identity:

```json
{
  "access_token": "opaque-session-token",
  "token_type": "Bearer",
  "identity": {
    "id": "backend-user-id",
    "username": "admin",
    "role": "administrator"
  }
}
```

Invalid credentials return HTTP `401`; malformed, oversized, or extra-field requests return HTTP `400`. Credentials are never included in responses or logs. Treat the token as a secret. The backend stores only a hash of the token.

### `POST /api/v1/auth/logout`

Requires a valid Bearer session and the API schema header. Revokes the caller's session and returns HTTP `204` with no body.

### `POST /api/v1/auth/setup`

Public, one-time account setup using a setup token issued by an administrator.
The request requires the API schema header and a JSON body:

```json
{
  "setup_token": "64-character-setup-token",
  "password": "new-account-password"
}
```

Success returns HTTP `204` with no body. Setup tokens are single-use, expire
after one hour, and are stored by the backend only as hashes. An account is
enabled after setup and must then sign in through `/api/v1/auth/login`.

### Account management

All account-management routes require an authenticated `administrator` and the
API schema header. Setup-token values are returned only in the create/issue
response; deliver them out-of-band and do not log or persist the plaintext.

`GET /api/v1/accounts` returns HTTP `200` with an `accounts` array. Account
objects contain `id`, `username`, `role`, `enabled`, and `setup_pending`.
`POST /api/v1/accounts` creates a pending account and returns HTTP `201` with
`account` and `setup_token`. Its JSON request contains `username` and `role`
(`viewer`, `operator`, or `administrator`). Usernames must be 3–64 ASCII
letters, digits, dots, underscores, or hyphens; names are case-insensitive
and cannot be reused, including after disablement.

`PATCH /api/v1/accounts` updates the username and/or role. Its JSON body
contains the account `id` and at least one of `username` or `role`. Success
returns HTTP `200` with an `account` object.

`POST /api/v1/accounts/disable` accepts `{"id": "backend-user-id"}`, disables
the account, revokes its sessions, and returns HTTP `204`.
`POST /api/v1/accounts/setup-token` accepts the same body and returns HTTP
`200` with `account` and `setup_token`. Issuing a new token invalidates
previous tokens and revokes existing sessions.

Invalid requests return HTTP `400`; missing accounts return `404`; username
conflicts and attempts to remove the last enabled administrator return `409`.
There is no hard-delete operation.

## API schema version

All API calls except `GET /status/health` must send the `X-Archangel-Schema-Version` request header, including the public login and one-time setup endpoints. The backend validates it and returns the supported schema version in the same response header. The current schema version is `1`; a missing or unsupported version is rejected with HTTP `400` and a JSON error response. JSON response bodies retain their documented shapes; the header versions those shapes independently of the `/api/v1` API route version.

The health endpoint is deliberately exempt so basic liveness remains available without schema negotiation or authentication.

## Authentication and authorization

Rate limits return HTTP `429` with a JSON error and `Retry-After`. The backend
limits API requests per source IP and authenticated identity, and applies an
additional per-minute limit to firewall mutations per source IP and identity.
Failed login attempts have a separate configurable per-source limit. Limits
use bounded in-memory state, reset on backend restart, and use the direct peer
address rather than forwarded headers. `GET /status/health` is exempt.

The backend applies authentication globally before route handling: all endpoints, including `/status/info` and future routes, require a valid Bearer session unless explicitly added to the narrow public allowlist. Each route declares its required access level where it is registered in `core/src/http/server.cpp`. An authenticated request to an unregistered method or path receives HTTP `404` with code `not_found`; unauthenticated requests to such paths receive `401`, so route existence is not disclosed. `HEAD` requests use the matching `GET` route's policy. Currently `GET /status/health`, `POST /api/v1/auth/login`, and
`POST /api/v1/auth/setup` are public. Missing, invalid, or expired sessions receive HTTP `401`; session-store failures fail closed with HTTP `500`.

All authenticated roles can use read endpoints. `POST /api/v1/rules` and `DELETE /api/v1/rules` require the `operator` or `administrator` role; viewers receive HTTP `403`. Bootstrap creates the initial administrator through `user bootstrap-admin`. The dashboard authenticates through the backend login route and keeps the backend credential in a server-side SQLite session store; every backend API call it makes includes that credential. When the backend rejects that credential with HTTP `401`, the dashboard clears its browser session and redirects to the login page. Bearer credentials travel over plain HTTP in the current backend; do not expose the API outside localhost or a trusted, isolated management network. Mutating endpoints apply changes immediately. See [Security](../SECURITY.md).

## Firewall ruleset bundle

The backend supports one-shot export and startup import using version 1 firewall config bundles. The bundle format is `archangel-firewall-config`; it contains firewall rules only and is independent of listener and other runtime settings described in the [runtime-config guide](runtime-config.md). V1 separates rules marked as Archangel-managed from other native nftables rules and objects:

```json
{
  "format": "archangel-firewall-config",
  "version": 1,
  "firewall": {
    "other_ruleset": {
      "nftables": [
        { "metainfo": { "json_schema_version": 1 } },
        { "table": { "family": "inet", "name": "filter" } },
        { "chain": { "family": "inet", "table": "filter", "name": "input" } },
        { "rule": { "family": "inet", "table": "filter", "chain": "input", "expr": [{ "accept": null }] } }
      ]
    },
    "archangel_rules": []
  }
}
```

Exported firewall bundles contain the complete ruleset objects and expressions, divided by the `archangel-managed` rule comment. Listener settings come only from the backend runtime config and `--host`/`--port`.

- `--export-firewall-config PATH` writes firewall bundle v1 with `firewall.other_ruleset` and `firewall.archangel_rules`. Rules created through Archangel's structured API have the nftables comment `archangel-managed` and are placed in `archangel_rules`; all other rules and nftables objects are placed in `other_ruleset`. This comment is a reserved ownership marker, not an access-control mechanism.
- `--import-firewall-config PATH --firewall-rules-mode merge` imports the bundle before the API starts and adds its objects/rules to the active ruleset.
- `--import-firewall-config PATH --firewall-rules-mode replace` atomically replaces only currently marked Archangel rules and leaves unmarked rules and other objects untouched; the referenced tables and chains must already exist.
- `--import-firewall-config PATH --firewall-rules-mode replace-all` explicitly flushes the entire active nftables ruleset, including tables not created by Archangel, then applies all imported objects and rules. This is destructive and can disconnect clients or lock out administrators.
- Import mode is required for each import; accepted values are `merge`, `replace`, and `replace-all`. Only firewall bundle format `archangel-firewall-config` version 1 is supported; older formats and versions are rejected. Import and export cannot be combined. Imported and exported files are limited to 16 MiB.

The v1 firewall section has this shape:

```json
{
  "other_ruleset": {
    "nftables": [
      { "table": { "family": "inet", "name": "filter" } },
      { "chain": { "family": "inet", "table": "filter", "name": "input" } },
      { "rule": { "family": "inet", "table": "filter", "chain": "input", "expr": [{ "accept": null }] } }
    ]
  },
  "archangel_rules": [
    { "rule": { "family": "inet", "table": "filter", "chain": "input", "comment": "archangel-managed", "expr": [{ "drop": null }] } }
  ]
}
```

Merge and replacement operations apply nftables changes through libnftables transactions; a rejected transaction is reported as a failure. Merge may fail if imported objects conflict with current objects or elements. Review all config files before import and ensure recovery access before using `replace-all`. The input must follow the supported nftables JSON output schema; arbitrary nftables command strings are not executed by the application.

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

- `archangel`: up to 100 entries from the current C++ logger's output file: `.archangel-dev/app.log` beside a debug binary, or `./app.log` in the working directory for release builds.
- `nftables`: up to 100 recent kernel-journal lines matching packet-log fields, only when the active ruleset contains nftables `log` statements. This source uses `journalctl`; if logging is not configured or journal access is unavailable, the source reports the reason and returns no entries.

This endpoint does not enable firewall logging. Results are bounded, long lines are truncated, and common credential-like fields are redacted. Logs may still contain sensitive system or network details. This endpoint requires a valid backend session; keep the API and dashboard on localhost or a trusted, isolated management network because API traffic is plain HTTP and the dashboard uses backend login with protected server-side sessions. Add future sources as separate source objects with explicit availability and failure details.

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
