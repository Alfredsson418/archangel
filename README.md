<p align="center">
    <img src="assets/archangel_poster.png" alt="Archangel">
</p>

<br>

<p align="center">
  <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/Alfredsson418/archangel?style=for-the-badge">
  <img alt="GitHub top language" src="https://img.shields.io/github/languages/top/Alfredsson418/archangel?style=for-the-badge&color=mediumaquamarine">
  <img alt="GitHub repo size" src="https://img.shields.io/github/repo-size/Alfredsson418/archangel?style=for-the-badge&color=darkorange">
  <img alt="GitHub code size in bytes" src="https://img.shields.io/github/languages/code-size/Alfredsson418/archangel?style=for-the-badge&color=slateblue">
  <!-- https://shields.io/badges/ -->
</p>
<br>

## Current Architecture

The firewall API is implemented in C++ under `core/src` with dependencies under `core/lib`. The Flask dashboard lives in `app/web` and reads C++ API data server-side when rendering pages, including a system overview, firewall configuration, and source-grouped system logs. These are independently deployable services: the privileged `archangel` binary is intended to run on the server whose firewall it manages, while the Dockerized webapp can run on a separate management computer and connect to that server's API. Keeping the webapp portable is an important design goal; its API base address must be configurable and reachable over the management network rather than tied to the managed server's local filesystem or loopback. See the [architecture guide](docs/architecture.md) for component boundaries and the [frontend design guide](docs/frontend-design.md) for dashboard styling and accessibility conventions.

The Firewall Configuration page can filter and sort active rules, and can export or preview-import versioned rules-only bundles. Import is additive and applies rules one at a time; it is not atomic and does not provide boot-time restoration. The API exposes an unauthenticated, bodyless `/status/health` liveness endpoint; `/status/info` is protected and reports the Git commit hash embedded into the binary during the Make build.

## Security

See [SECURITY.md](SECURITY.md) to report a suspected security flaw and [docs/security-concerns.md](docs/security-concerns.md) for the current security posture, deployment constraints, and planned controls. The C++ API now authenticates protected requests and enforces firewall roles, but the Flask dashboard has no login integration and the API does not provide TLS. Keep both services on localhost or a trusted, isolated management network.

The backend has local-account storage, API authentication, firewall role
enforcement, and an administrator bootstrap command. Bootstrap the initial
account interactively:

```sh
./archangel user bootstrap-admin --username admin
```

It reads and confirms the password through an interactive terminal and stores
the account under `/var/lib/archangel/archangel.db` by default. Use
`--database PATH` to select another private database location.

## Run

Build and run the C++ API (requires a C++20 compiler and the libnftables, SQLite, Argon2, and OpenSSL development files):

```sh
make debug
./archangel --host 127.0.0.1 --port 8080
```

See the [test and verification guide](docs/test.md) for prerequisites, test coverage, commands, expected output, and GitHub Actions behavior.

Backend runtime settings use a separate versioned JSON file at
`/etc/archangel/config.json`. If the implicit file is absent, built-in defaults
are used; `--config PATH` selects an explicit required file. The runtime config
does not import or modify firewall rules. Its format, file permissions,
supported settings, defaults, and current implementation limits are described
in the [backend runtime configuration guide](docs/runtime-config.md).

For local development, the API can be configured through command-line flags:

```sh
./archangel --config /etc/archangel/config.json --host 127.0.0.1 --port 8080
```

CLI bind settings override runtime-config values. `--import-firewall-config`
and `--export-firewall-config` are separate explicit firewall-bundle
operations.

The backend can export the complete active nftables ruleset in a versioned
firewall config bundle, or import a bundle before starting the API. Firewall
bundle v1 contains ruleset data only and separates rules created through
the structured API from other rules and nftables objects:

```sh
./archangel --export-firewall-config firewall-config.json
./archangel --import-firewall-config firewall-config.json --firewall-rules-mode merge
```

V1 contains the full native nftables ruleset, including expressions the
dashboard's structured portable bundle cannot represent, and separates rules
marked `archangel-managed` from other rules and nftables objects. `merge` adds
the imported firewall config. `replace` replaces only marked Archangel rules
and leaves the rest of the active ruleset untouched. Use
`--firewall-rules-mode replace-all` to explicitly flush the entire active ruleset; this
can sever network access or lock out administrators. Review configs before
importing. CLI `--host` and `--port` values override the corresponding JSON
settings; firewall bundles do not contain listener settings.

### Run the frontend in Docker

For a same-computer development setup on Linux, with the C++ API running on `127.0.0.1:8080`, start the containerized dashboard:

```sh
docker compose up --build -d
```

For a separate management computer, deploy the Dockerized webapp independently, configure the dashboard's API connection to the managed server's reachable management address, and make both services reachable only on a trusted management network. The Compose file's localhost defaults and host-network setup are for the same-computer quickstart, not a remote deployment recipe. The C++ API authenticates protected requests, but the dashboard does not yet provide login integration and API traffic is not protected by project-configured HTTPS. Do not expose either service to the public internet.

The web app writes request, backend, and configuration events to stdout. View them with `docker compose logs -f web`; set `WEB_LOG_LEVEL=DEBUG` before starting Compose for more detail. Request logs omit query strings and form values.

## Project goal

See [docs/goal.md](docs/goal.md) for the project's purpose, long-term architectural direction, and current open questions.

# Development roadmap

See the [development roadmap](docs/roadmap.md) for the current implementation baseline, sequenced work, completion criteria, and longer-term exploratory ideas.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and pull request guidance, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations and reporting concerns.

## FaQ
- Is this vibe coded?
Maybe somewhat, dependent on how you define "vibe coded". My role in this project is more of a system architect/product owner role. I of course have a big role on how the codebase is built, and design desisions, but due to time constraints, I dont generally write code myself.

- Will this project be completed?
I hope so, I plan on implement this solution for my own servers, but it will take some time to come to a stage where it is usable.

- Can I contribute to this project?
Yes! For the time being, create a feture request under "Issues" so we can discuss it!

- Why Archangel?
It is a refrence to Garrus nickname in Mass Effect 2, the name could change in the future!
