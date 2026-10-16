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

The firewall API is implemented in C++ under `core/src` with dependencies under `core/lib`. The Flask dashboard lives in `app/web` and reads C++ API data server-side when rendering pages, including a system overview, firewall configuration, and source-grouped system logs. These are independently deployable services: the privileged `archangel` binary is intended to run on the server whose firewall it manages, while the Dockerized webapp can run on a separate management computer and connect to that server's API. Keeping the webapp portable is an important design goal; its API base address must be configurable and reachable over the management network rather than tied to the managed server's local filesystem or loopback.

The Firewall Configuration page can filter and sort active rules, and can export or preview-import versioned rules-only bundles. Import is additive and applies rules one at a time; it is not atomic and does not provide boot-time restoration. The API exposes an unauthenticated, bodyless `/status/health` liveness endpoint and a separate diagnostic `/status/info` endpoint. The latter reports the Git commit hash embedded into the binary during the Make build.

## Security

See [SECURITY.md](SECURITY.md) to report a suspected security flaw and [docs/security-concerns.md](docs/security-concerns.md) for the current security posture, deployment constraints, and planned controls. The API and dashboard do not currently provide authentication or authorization; keep them on localhost or a trusted, isolated management network.

## Run

Build and run the C++ API (requires a C++20 compiler and libnftables development files):

```sh
make debug
./archangel --host 127.0.0.1 --port 8080
```

The backend can export the complete active nftables ruleset together with its
bind settings in a versioned JSON config, or import a config before starting
the API:

```sh
./archangel --export-config archangel-config.json
./archangel --import-config archangel-config.json --rules-mode merge
```

The JSON includes the API bind interface/address, port, and the full nftables
ruleset, including expressions the dashboard's structured portable bundle cannot
represent. Every import must explicitly select `--rules-mode merge` or
`--rules-mode replace`. Merge adds the imported configuration to the current
ruleset; replace flushes the entire active nftables ruleset, including tables
unrelated to Archangel, before applying the config. Replace can sever network
access or lock out administrators. Review configs before importing. CLI `--host`
and `--port` values override the corresponding JSON settings.

### Run the frontend in Docker

For a same-computer development setup on Linux, with the C++ API running on `127.0.0.1:8080`, start the containerized dashboard:

```sh
docker compose up --build -d
```

For a separate management computer, deploy the Dockerized webapp independently, configure the dashboard's API connection to the managed server's reachable management address, and make both services reachable only on a trusted management network. The Compose file's localhost defaults and host-network setup are for the same-computer quickstart, not a remote deployment recipe. The current API has no authentication or HTTPS, so do not expose either service to the public internet.

The web app writes request, backend, and configuration events to stdout. View them with `docker compose logs -f web`; set `WEB_LOG_LEVEL=DEBUG` before starting Compose for more detail. Request logs omit query strings and form values.

## Project goal

See [docs/goal.md](docs/goal.md) for the project's purpose, long-term architectural direction, and current open questions.

# Development roadmap

See the [development roadmap](docs/roadmap.md) for the current implementation baseline, sequenced work, completion criteria, and longer-term exploratory ideas.

## FaQ
- Is this vibe coded?
No, but it could include AI generated code, but I try to make a effort to note it in the commit message/description. This project is both a passion project for me, and also a way for me to extend my knowledge in C/C++.

- Will this project be completed?
I hope so, I plan on implement this solution for my own servers, but it will take some time to come to a stage where it is usable.

- Can I contribute to this project?
Yes! For the time being, create a feture request under "Issues" so we can discuss it!

- Why Archangel?
It is a refrence to Garrus nickname in Mass Effect 2, the name could change in the future!
