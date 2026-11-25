<div align="center">

# OBoard Agent

Node-side daemon and slim `oboard-sb` proxy kernel for OBoard.

**English** · [简体中文](README.zh-CN.md)

<p>
  <a href="https://github.com/obrdx/oboard-agent/releases"><img src="https://img.shields.io/github/v/release/obrdx/oboard-agent?include_prereleases&style=flat-square&logo=github&label=Release&color=2563eb" alt="Release"></a>
  <img src="https://img.shields.io/github/go-mod/go-version/obrdx/oboard-agent?style=flat-square&logo=go&logoColor=white&color=00ADD8" alt="Go">
  <img src="https://img.shields.io/badge/Kernel-oboard--sb%20%28sing--box%29-0ea5e9?style=flat-square" alt="oboard-sb">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-1e293b?style=flat-square&logo=linux&logoColor=white" alt="Platform">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/obrdx/oboard-agent?style=flat-square&logo=gnu&logoColor=white&label=License&color=16a34a" alt="License"></a>
</p>

<p>
  <a href="https://github.com/obrdx/oboard"><img src="https://img.shields.io/badge/Panel-obrdx%2Foboard-6366f1?style=flat-square&logo=github&logoColor=white" alt="OBoard"></a>
  <a href="https://obrdx.github.io/"><img src="https://img.shields.io/badge/Install%20%26%20Docs-obrdx.github.io-0ea5e9?style=flat-square&logo=readthedocs&logoColor=white" alt="Install and Docs"></a>
</p>

</div>

OBoard Agent runs on managed proxy nodes to communicate with the [OBoard control panel](https://github.com/obrdx/oboard), verify and apply signed configurations, coordinate networking services, and report node status. This repository also maintains `oboard-sb` (`kernel/oboard-sb`), a slim proxy kernel derived from [sing-box](https://github.com/SagerNet/sing-box).

## Features

- **Slim proxy kernel**: `oboard-sb` includes only supported protocols and required components to minimize binary size and memory usage, supporting runtime user updates and traffic rate limiting.
- **Adaptive resource management**: Automatically scales runtime profiles based on physical memory and cgroup limits to maintain stability and reduce OOM risk on constrained 128–256 MiB nodes.
- **Verified delivery and recovery**: Supports one-time token enrollment, release signature verification, automatic reconnection, and watchdog self-recovery.
- **Integrated networking**: Coordinates the proxy kernel alongside Realm / nftables port forwarding, transparent relays, WireGuard / SSH tunnels, and an isolated SSH proxy service.
- **Probing and diagnostics**: Provides node telemetry, latency and route probes, egress IP / MTU / DNS diagnostics, and HTTP-01 certificate issuance.
- **Local administration (`obag`)**: Includes an interactive and scriptable CLI to inspect service status, manage services, view logs, and verify panel connectivity.

## Compatibility

| Category | Supported |
| :--- | :--- |
| **Protocols** | VLESS (TLS / Reality), Hysteria2, AnyTLS, Shadowsocks (incl. UoT), Snell (v4 / v5 / v6), Mieru, SOCKS5, isolated SSH (`udpgw`) |
| **Exits & Networking** | Direct, chained proxies, WireGuard (WARP / external), HTTP / HTTPS proxy, VPNGate, Realm / nftables forwarding, SSH tunnels |
| **Platforms** | Linux (`amd64` / `arm64`, `systemd` / `OpenRC`) · Windows (`amd64`) |

## Deployment

Add a server in the OBoard control panel to obtain the generated installation command, or invoke the bootstrap script directly:

```sh
# Linux
curl -fsSL https://raw.githubusercontent.com/obrdx/oboard-agent/main/scripts/install.sh \
  | sudo env OBOARD_CONTROLLER_URL='https://panel.example.com' \
             OBOARD_ENROLL_TOKEN='<one-time-token>' sh
```

```powershell
# Windows (Elevated PowerShell)
$env:OBOARD_CONTROLLER_URL = 'https://panel.example.com'
$env:OBOARD_ENROLL_TOKEN   = '<one-time-token>'
& ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/obrdx/oboard-agent/main/scripts/install.ps1')))
```

> Set `OBOARD_ACTION=update` or `OBOARD_ACTION=uninstall` to upgrade or remove an installation.

## Local Administration (`obag`)

```sh
obag              # Open interactive management menu
obag status       # Show Agent and kernel status
obag restart      # Restart Agent and kernel services
obag logs agent   # View Agent logs (use `logs core` for oboard-sb)
obag check        # Verify connectivity to the control panel
```

## Build from Source

Requires Go 1.27 or later:

```sh
go build -o oboard-agent ./cmd/agent
./scripts/build-oboard-sb.sh
```

## License & Acknowledgements

Copyright 2026 OBoard contributors.

`oboard-sb` is derived from [sing-box](https://github.com/SagerNet/sing-box). Acknowledgements to the sing-box project and its contributors.

`oboard-agent` (including `kernel/oboard-sb`) is released under the [GNU GPL v3](LICENSE).
