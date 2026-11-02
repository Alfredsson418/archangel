# Exposed Endpoints
The C++ API runs separately from the Flask dashboard. The intended deployment places the privileged API binary on the server whose firewall it manages and allows the portable, Dockerized dashboard to run on a separate management computer. Configure the dashboard with an API base URL routable to that server; do not assume localhost refers to the same machine in a split-host setup. Flask reads the API directly while rendering pages and does not expose API passthrough routes. The C++ API requires backend authentication on every route except `GET /status/health`, `POST /api/v1/auth/login`, and `POST /api/v1/auth/setup`. The dashboard obtains backend sessions through its login flow and sends them with protected calls. API traffic is plain HTTP unless native TLS is enabled (see the [runtime config guide](runtime-config.md#tls)); keep both services on localhost or a trusted, isolated management network.

## Flask Dashboard

State-changing dashboard requests (sign-in, sign-out, and bundle import) are recorded in the dashboard audit log before they run. If that record cannot be written, the request is refused with HTTP `503`.

### `GET /`

Renders the server overview with nftables enforcement status, backend version/connectivity, host identity, uptime, CPU load, memory, and disk metrics. It does not display individual firewall rules.

### `GET /rules`

Fetches the C++ ruleset in Flask and renders individual firewall rules on the Firewall Configuration page with the `rules.html` template.

Rules can be filtered across family, table, chain, handle, and expression, and sorted by family, table, chain, handle, or expression in ascending or descending order. Each rule offers Edit and Duplicate if the rule form can represent it, and Delete. None of these change the firewall until the resulting pending changes are applied.

### `GET /rules/export`

Downloads `archangel-firewall-rules.json`, a versioned JSON snapshot containing only active rules that can be represented using Archangel's structured rule API:

```json
{
  "format": "archangel-firewall-rules",
  "version": 2,
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

The `omitted_unsupported_rules` count indicates rules from the active ruleset that cannot be represented by the structured API. Unsupported nftables expressions are omitted, not translated or preserved. Rule fields are the same as for [`POST /api/v1/rules`](#post-apiv1rules). Exported bundles do not include API URLs, service settings, or arbitrary nftables commands. The `X-Archangel-Skipped-Rules` response header provides the same count when nonzero.

### `GET, POST /rules/import`

`GET` renders the import page. `POST` with multipart form field `bundle_file` validates a JSON bundle and shows a preview; a separate submission with `action=add` and the `bundle` field adds its rules to pending changes. The importer accepts the bundle format above in version 2, or in version 1, which predates subnets, port ranges, interfaces, connection state, ICMP, and rules without a protocol. It accepts up to 512 KiB and 1,000 rules, and validates all rules before making backend requests. Bundles may contain zero rules, which is a no-op.

Import is additive: it adds rules and does not delete or replace existing ones. Because the rules join pending changes, they're reviewed with any other changes and apply in one transaction, so a failure leaves none of them applied. All rules must target chains that exist, or none are added. A preview warns about rules omitted during export. The bundle is a portable snapshot only; it is not loaded automatically on backend startup and does not make nftables rules persistent across restarts.

### `GET, POST /rules/new`

`GET` renders the rule form, which offers the chains in the active ruleset. With `family`, `table`, `chain`, and `handle` in the query string, it starts from that rule's values, for duplicating it. `POST` validates the submitted fields and either previews the rule in plain language or adds it to the signed-in user's pending changes. `form_action=add_another` returns to the form with the same values, to make adding many similar rules quick. None of these change the firewall.

### `GET, POST /rules/edit`

`GET` renders the rule form with an existing rule's values, identified by `family`, `table`, `chain`, and `handle`. `POST` previews the edit as before and new, or adds it to pending changes. An edit keeps the rule's position, handle, and comment, and can't move it to another chain. A rule that uses features the form can't represent can't be edited here, but can still be deleted. A rule can have only one pending change at a time.

### `GET, POST /rules/organize`

`GET` shows the rules of the chain named by `chain` in true order, including pending new rules. `POST` adds a new order to pending changes, replacing any pending order for that chain. The `order` fields list every rule once, as `handle:N` or `new:ID`; a list that no longer matches the chain is refused. With `form_action=move`, `move_rule` and `move_position` move one rule instead. This form doesn't need JavaScript. With JavaScript, rules can also be dragged, or moved with buttons.

### `GET, POST /firewall/structure`

`GET` lists tables and chains, and states what nftables can't change: tables can't be renamed, and a base chain's hook and priority are fixed. `POST` adds a change to pending changes, using `structure_action`: `create_table`, `delete_table`, `disable_table`, `enable_table`, `create_chain`, `rename_chain`, `set_chain_policy`, or `delete_chain`. Only `ip`, `ip6`, and `inet` tables can be managed, and new base chains use the `filter` type.

Applying requires the name typed as `confirm_name_<change id>` when deleting a table or a chain with rules, or when turning a table's enforcement off. A chain that other rules jump to can't be deleted, and a chain's rules can't change in the same list as renaming it or after deleting it. nftables applies a rename at the end of a transaction, so changes to that chain's rules must be applied first.

### `POST /rules/delete`

Adds a rule's deletion to pending changes, without changing the firewall. The fields are `family`, `table`, `chain`, and `handle`.

### `GET /changes`

Renders the review page: every pending change as `before -> new`, warnings, and any change flagged as a MANAGEMENT RISK because it could block the dashboard's connection to the API. It asks the API to check the list, and marks changes whose target has since changed.

### `POST /changes/apply`

Applies all pending changes in one transaction, after working out the review again. It requires `confirm=yes`, and `confirm_risk=yes` if the list contains a management risk or changes a rule Archangel doesn't manage. Success redirects to the rules page, which reports the result read back from the firewall.

### `POST /changes/remove`, `POST /changes/discard`, `POST /changes/refresh`

Remove one pending change by its `id`, discard them all, or record the current revisions of the chains they touch so that they can be reviewed against the firewall as it is now. Changes whose target rule has changed stay marked until removed.

Pending changes belong to one user and are kept for 24 hours after the last addition, up to 1,000 at a time. They survive an expired sign-in.

### `GET /system`

Renders the read-only System Management page with host resource information and Archangel backend version/process uptime. Restart controls are displayed as unavailable; this page does not issue service or host operations.

### `GET /system/logs`

Renders recent server-side logs grouped by source. It displays the Archangel application log and, when active nftables rules include `log` statements and the host kernel journal is readable, recent packet-log entries. Unavailable or unconfigured sources are shown with an explanation. Additional sources can be added independently.

### `GET /api-connection`

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
  "schema_version": 2,
  "uptime_seconds": 120,
  "client_address": "192.0.2.20",
  "api_port": 8080
}
```

`backend_version` is the Git commit hash embedded when the backend binary is built; the example hash above is the current commit and will change with later builds from different commits. `uptime_seconds` is the number of seconds since the backend process started. `client_address` and `api_port` are the caller's address and the listening port as the backend sees them. The dashboard uses them to check whether a firewall change could block its connection to the API. Unlike `/status/health`, this endpoint requires an authenticated Bearer session.

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
An invalid, expired, or used token returns HTTP `400` with error
`invalid_setup_token`. A password outside the configured length policy, or on
the operator's password blocklist, returns HTTP `400` with error
`invalid_request` and a reason; the token remains valid for another attempt.

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

## Request IDs and audit logging

Every response carries an `X-Request-ID` header with a random 32-character hexadecimal identifier. The same value appears as `request_id` in the backend's audit records, so a client can correlate its own logs with them.

The backend records every authorized request before running it. If that audit record cannot be written, the request is refused with HTTP `503` and code `audit_log_unavailable`; retry once the log is writable again. `GET /status/health` is never refused for this reason. See the [runtime config guide](runtime-config.md#backend-log) for the record fields.

## Authentication and authorization

Rate limits return HTTP `429` with a JSON error and `Retry-After`. The backend
limits API requests per source IP and authenticated identity, and applies an
additional per-minute limit to firewall mutations per source IP and identity.
Failed login attempts have a separate configurable per-source limit. Limits
use bounded in-memory state, reset on backend restart, and use the direct peer
address rather than forwarded headers. `GET /status/health` is exempt.

The backend applies authentication globally before route handling: all endpoints, including `/status/info` and future routes, require a valid Bearer session unless explicitly added to the narrow public allowlist. Each route declares its required access level where it is registered in `backend/src/http/server.cpp`. An authenticated request to an unregistered method or path receives HTTP `404` with code `not_found`; unauthenticated requests to such paths receive `401`, so route existence is not disclosed. `HEAD` requests use the matching `GET` route's policy. Currently `GET /status/health`, `POST /api/v1/auth/login`, and
`POST /api/v1/auth/setup` are public. Missing, invalid, or expired sessions receive HTTP `401`; session-store failures fail closed with HTTP `500`.

All authenticated roles can use read endpoints. `POST /api/v1/rules` and `DELETE /api/v1/rules` require the `operator` or `administrator` role; viewers receive HTTP `403`. Bootstrap creates the initial administrator through `user bootstrap-admin`. The dashboard authenticates through the backend login route and keeps the backend credential in a server-side SQLite session store; every backend API call it makes includes that credential. When the backend rejects that credential with HTTP `401`, the dashboard clears its browser session and redirects to the login page. Without TLS, Bearer credentials travel in plaintext; enable TLS when API traffic leaves the host, and do not expose the API outside a trusted, isolated management network. Mutating endpoints apply changes immediately. See [Security](../SECURITY.md).

## Firewall ruleset bundle

The backend supports one-shot export and import, which exit without starting the API, using version 1 firewall config bundles. The bundle format is `archangel-firewall-config`; it contains firewall rules only and is independent of listener and other runtime settings described in the [runtime-config guide](runtime-config.md). V1 separates rules marked as Archangel-managed from other native nftables rules and objects:

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
- `--import-firewall-config PATH --firewall-rules-mode merge` adds the bundle's objects/rules to the active ruleset.
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

`network_interfaces` lists the host's interface names, so that the dashboard can warn about a rule naming an interface that doesn't exist.

### `GET /api/v1/logs`

Returns a `sources` array. Each source has a stable `id`, display `label`, boolean `available`, explanatory `detail`, and an `entries` array containing recent log lines, newest first. Current sources are:

- `archangel`: up to 100 recent records from the backend JSONL log at `logging.path` (see the [runtime config guide](runtime-config.md#backend-log)), each rendered as `timestamp level category event key=value ...`.
- `nftables`: up to 100 recent kernel-journal lines matching packet-log fields, only when the active ruleset contains nftables `log` statements. This source uses `journalctl`; if logging is not configured or journal access is unavailable, the source reports the reason and returns no entries.

This endpoint does not enable firewall logging. Results are bounded, long lines are truncated, and common credential-like fields are redacted. Logs may still contain sensitive system or network details. This endpoint requires a valid backend session; keep the API and dashboard on localhost or a trusted, isolated management network because the entries can reveal host and network details. Add future sources as separate source objects with explicit availability and failure details.

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

Every field except `family`, `table`, `chain`, and `action` is optional, but at least one match is required.

| Field | Accepted values |
| --- | --- |
| `family` | `ip`, `ip6`, or `inet` |
| `protocol` | `tcp`, `udp`, `icmp`, or `icmpv6`. `icmp` needs the `ip` or `inet` family, and `icmpv6` needs `ip6` or `inet`. |
| `source_address`, `destination_address` | One address, or one subnet in CIDR form. A subnet with host bits set, such as `192.168.1.5/24`, is rejected, because nftables would otherwise store a different subnet. Both must use the same IP version, matching the family and protocol. |
| `destination_port` | A port from 1 to 65535. Requires `protocol` to be `tcp` or `udp`. |
| `destination_port_end` | The last port of a range starting at `destination_port`. |
| `input_interface`, `output_interface` | One interface name, of up to 15 letters, digits, `.`, `_`, or `-`. The interface doesn't have to exist yet, so a mistyped name is accepted. |
| `connection_states` | A list of `new`, `established`, `related`, and `invalid`. |
| `action` | `accept`, `drop`, or `reject` |

Unknown fields are rejected, so that a backend that doesn't understand a field can't create a broader rule than requested. Success returns HTTP `201`.

### `POST /api/v1/firewall/changes`

Applies an ordered list of up to 1,000 changes in one transaction, so that either all of them take effect or none do. The request is limited to 2 MiB and requires the `operator` or `administrator` role. It counts as one firewall mutation for rate limiting, however many changes it contains.

```json
{
	"expected_revisions": [
		{ "family": "inet", "table": "filter", "chain": "input", "revision": "4e07..." }
	],
	"changes": [
		{ "type": "add_rule", "rule": { "family": "inet", "table": "filter", "chain": "input", "protocol": "tcp", "destination_port": 443, "action": "accept" } },
		{ "type": "replace_rule", "handle": 9, "rule": { "family": "inet", "table": "filter", "chain": "input", "protocol": "tcp", "destination_port": 22, "action": "drop" } },
		{ "type": "delete_rule", "family": "inet", "table": "filter", "chain": "input", "handle": 12 }
	]
}
```

`add_rule` takes the same fields as `POST /api/v1/rules` and adds the rule at the end of its chain. It can also take an `id`, so that a later `set_rule_order` can place it. `replace_rule` takes `handle` and `rule`, and replaces that rule in place, keeping its position, handle, and comment. `rule`'s family, table, and chain identify the existing rule's chain.

These change a chain or table:

| Type | Fields |
| --- | --- |
| `set_rule_order` | `family`, `table`, `chain`, and `order`, which lists every rule once: a handle, or the `id` of a rule added earlier in the list. Moved rules get new handles, and keep their counters. A chain can't also be renamed or deleted in the same list. |
| `create_chain` | `family`, `table`, `name`, and for a base chain `base`: `type` (`filter`), `hook`, `priority` (-1000 to 1000), and `policy`. |
| `rename_chain` | `family`, `table`, `name`, and `new_name`. Rules that jump to the chain follow the new name. Its rules can't change later in the same list, under either name. |
| `set_chain_policy` | `family`, `table`, `name`, and `policy` (`accept` or `drop`). |
| `delete_chain` | `family`, `table`, and `name`. This also deletes its rules. It's rejected if other rules jump to it. |
| `create_table` | `family` and `name`. |
| `delete_table` | `family` and `name`. This deletes everything in the table. |
| `set_table_enabled` | `family`, `name`, and `enabled`. A table that isn't enabled stops enforcing all of its rules. |

A table can't be renamed, and a base chain's hook and priority can't be changed, because nftables doesn't support it. `expected_revisions` must include every existing chain a change touches, which for a change to a table means all of its chains. Chains the list itself creates have no revision.

| Status | Code | Meaning |
| --- | --- | --- |
| `200` | | `{"status":"applied","changes":2}`. |
| `400` | `invalid_request` | The request is malformed, too large, or missing a touched chain's revision. |
| `409` | `firewall_changed` | A chain no longer matches its expected revision. Nothing was applied. |
| `422` | `change_rejected` | The firewall rejected a change, identified by `change_index`. Nothing was applied. |

### `POST /api/v1/firewall/changes/check`

Takes the same request and reports what applying it would do, without changing anything: `{"status":"valid","changes":2}`, or the same errors as above. Passing a check doesn't guarantee that applying later succeeds. It requires the same roles, but doesn't count as a firewall mutation for rate limiting.

### `GET /api/v1/firewall/revisions`

Returns the current revision of every chain. A revision covers the chain's definition and its rules and handles, but not counter values, so traffic doesn't change it. Treat it as opaque text.

```json
{ "chains": [ { "family": "inet", "table": "filter", "chain": "input", "revision": "4e07..." } ] }
```

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
