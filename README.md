<h1 align="center">Archangel</h1>

<h3 align="center">Project is written in Rust.</h3>
<br>

<p align="center">
  <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/Alfredsson418/archangel?style=for-the-badge">
  <img alt="GitHub top language" src="https://img.shields.io/github/languages/top/Alfredsson418/archangel?style=for-the-badge&color=mediumaquamarine">
  <img alt="GitHub repo size" src="https://img.shields.io/github/repo-size/Alfredsson418/archangel?style=for-the-badge&color=darkorange">
  <img alt="GitHub code size in bytes" src="https://img.shields.io/github/languages/code-size/Alfredsson418/archangel?style=for-the-badge&color=slateblue">
  <!-- https://shields.io/badges/ -->
</p>

<br>

# About

The goal of this project is to build a open source firewall that can rival the UniFi echosystem in user experience. This program is built as a backend for a seperate frondend project, so this program only exposes endpoints that other programs can get and post to (see [routes](docs/endpoints.md) for possible endpoints). This project is just in its infancy and I do this on my freetime so dont expect something good, just doing this for the fun of it.  


# Usage
Project is currently being developed on rust version 1.97.1

## Build
```bash
cargo build
```

## Usage
The program requires special permissions to run, so either run it as root (not recommended) or add the cap_net_admin+ep permission to the executable
```bash
sudo setcap cap_net_admin+ep target/debug/archangel   # needed to read/modify interfaces
./target/debug/archangel
```


# Software Features
- [ ] Basic firewall routing
- [ ] Basic DNS Resolver
- [ ] Basic DHCP Server
- [ ] Device discovery
- [ ] Deep Packet Inspection
- [ ] Device Enrollment (requires additional projects, like raspberry PI can act as a AP)
- [ ] Web based frontend
- [ ] Port discovery

And more...

## Dashboard Features
- [ ] Network Topology
- [ ] Iteractive firewall management
- [ ] Visual packet flow

And more...
