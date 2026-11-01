# Backend Runtime Configuration

The backend runtime config is a versioned JSON file, separate from the
version 1 `archangel-firewall-config` firewall import/export bundle. Loading it
never imports or changes firewall rules.

Release builds look for `/etc/archangel/config.json` by default. Debug builds
compiled with `ARCHANGEL_DEV_BUILD` instead use the `.archangel-dev` directory
next to the executable for `config.json`, `archangel.db`, `backend.jsonl`, and
the current text log `app.log`. The private directory is created with mode
`0700` when it is first needed and must be owned by the user that runs the
binary.
`make debug` builds into `bin/`, so the debug state directory is
`bin/.archangel-dev`; the `make run`, `make bootstrap-admin`, and `make config`
targets run the binary as one consistent user (through `sudo` by
default). If the default config file is absent, built-in
defaults are used; if it exists but cannot be read or is invalid, startup
fails. `--config PATH` selects an explicit required file in either build.
The file must be a regular file owned by root or the service user, must not be
group/world writable, and cannot be a symbolic link. Files are limited to
1 MiB. Keep credentials and private-key contents out of this file; it may
contain paths to protected files.

## Supported fields

Unknown keys, unsupported versions, incorrect types, and values outside the
supported ranges are rejected. Sections and individual fields may be omitted;
omitted settings use the defaults defined by the central `AppConfig` type in
`core/include/config/app_config.hpp`. Runtime JSON is parsed into that same
effective-settings object; explicit CLI options then override its values.

| Section and field | Default | Description |
| --- | --- | --- |
| `server.bind_address` | `localhost` | API listener address. |
| `server.port` | `8080` | API listener port, 1–65535. |
| `auth.provider` | `local` | Currently only the local provider is supported. |
| `auth.database_path` | `/var/lib/archangel/archangel.db` (release); `.archangel-dev/archangel.db` beside the executable (debug) | Private SQLite account/session store path. |
| `auth.password_min_length` | `15` (release); `1` (debug) | Minimum Unicode code points; cannot be lower than 15 in release builds or 1 in debug builds. |
| `auth.password_max_length` | `128` | Maximum Unicode code points; cannot exceed 128. |
| `auth.argon2id.memory_kib` | `19456` | Argon2id memory cost; cannot be lower than 19 MiB or higher than 1 GiB. |
| `auth.argon2id.iterations` | `2` | Argon2id time cost; range 2–10. |
| `auth.argon2id.parallelism` | `1` | Argon2id parallelism; range 1–8. |
| `sessions.idle_timeout_seconds` | `900` | API session idle lifetime. |
| `sessions.absolute_timeout_seconds` | `28800` | Absolute session lifetime; must exceed the idle lifetime. |
| `tls.enabled` | `false` | Native API TLS setting. Enabling TLS currently fails startup because TLS support is not implemented. |
| `tls.certificate_file` | unset | Operator-provisioned certificate path. |
| `tls.private_key_file` | unset | Operator-provisioned private-key path; never put key contents in JSON. |
| `logging.sink` | `jsonl_file` | Planned backend log sink. |
| `logging.path` | `/var/log/archangel/backend.jsonl` (release); `.archangel-dev/backend.jsonl` beside the executable (debug) | Planned JSONL log destination. |
| `logging.level` | `INFO` | Planned minimum log level. |
| `rate_limits.failed_auth_attempts` | `5` | Maximum failed login attempts per source IP in the configured window. |
| `rate_limits.failed_auth_window_seconds` | `300` | Login-attempt window in seconds. |
| `rate_limits.api_requests_per_minute` | `120` | Maximum requests per minute for each source IP and authenticated identity. |
| `rate_limits.firewall_mutations_per_minute` | `30` | Additional maximum firewall mutations per minute for each source IP and authenticated identity. |

## Example

This example configures the currently supported listener and administrator
bootstrap settings:

```json
{
  "format": "archangel-runtime-config",
  "version": 1,
  "server": {
    "bind_address": "127.0.0.1",
    "port": 8080
  },
  "auth": {
    "provider": "local",
    "database_path": "/var/lib/archangel/archangel.db",
    "password_min_length": 15,
    "password_max_length": 128,
    "argon2id": {
      "memory_kib": 19456,
      "iterations": 2,
      "parallelism": 1
    }
  },
  "sessions": {
    "idle_timeout_seconds": 900,
    "absolute_timeout_seconds": 28800
  }
}
```

## Generate a config file

Generate a complete version 1 runtime config containing the current built-in
defaults:

```sh
./archangel config generate
```

By default, the command writes to the runtime config path for the current
build: `/etc/archangel/config.json` for release builds or `.archangel-dev/config.json`
beside the executable for debug builds. Use `--output PATH` to choose another
destination:

```sh
./archangel config generate --output ./config.json
```

The command creates missing parent directories, writes a config file with
mode `0644` (readable but not writable by group or others), and refuses to
overwrite an existing destination. Writing the release default under
`/etc/archangel` may require elevated privileges. It generates defaults
rather than reading or modifying an existing config. Edit the generated file
to customize supported settings. Generating TLS paths does
not enable TLS, and the current backend still rejects enabling TLS or
non-default custom logging because those capabilities are not implemented.

Create the initial administrator using the same runtime file. Put `--config`
before the `user` subcommand:

```sh
./archangel --config /etc/archangel/config.json user bootstrap-admin --username admin
```

## Current implementation boundary

The configuration loader and validation are implemented. The running service
uses the central application settings object, populated by runtime JSON and
then overridden by explicit CLI options. It uses the configured bind address
and port unless overridden by `--host` or `--port`. `user bootstrap-admin`
uses the configured local database path, password-length policy, and Argon2id
parameters; `--database PATH` overrides
the database path for that command. Argon2id settings have upper bounds to
avoid unbounded CPU and memory consumption.

The C++ API uses the local authentication provider to issue and validate
sessions. Authentication is required by default, except for bodyless
`GET /status/health`, `POST /api/v1/auth/login`, and one-time
`POST /api/v1/auth/setup`; firewall mutations also require an Operator or
Administrator role, and account-management routes require an Administrator.
Login attempts, API requests per source IP and authenticated identity, and
firewall mutations per source IP and identity are limited using the configured
thresholds. Rate-limit counters use bounded in-memory state and reset on
restart. Session settings control API session lifetimes.

Native TLS and configurable logging are not implemented. TLS cannot be
enabled; unsupported non-default TLS and logging settings are rejected rather
than silently ignored. The Flask dashboard integrates the backend login
contract and stores its opaque backend session on the server in a separate
SQLite session database. Production dashboard deployments must configure
`FLASK_SECRET_KEY`; see the deployment guidance for its session-store
settings. API traffic is plain HTTP. Keep both services restricted to
localhost or a trusted, isolated management network.

## Command-line precedence

`--host` and `--port` override runtime-config values. The firewall bundle
contains no listener settings and does not affect service binding.
`--database` overrides `auth.database_path` only for `user bootstrap-admin`.

Firewall import/export remain explicit operations:

```sh
./archangel --config /etc/archangel/config.json
./archangel --export-firewall-config firewall-config.json
./archangel --import-firewall-config firewall-config.json --firewall-rules-mode merge
```

An import remains a privileged, immediate firewall operation. Review bundles
carefully and select `--firewall-rules-mode` explicitly.
