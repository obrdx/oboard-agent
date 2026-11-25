<div align="center">

# OBoard Agent

Node-side agent and slim `oboard-sb` proxy kernel for OBoard.

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

OBoard Agent runs on each proxy server to connect with the [OBoard panel](https://github.com/obrdx/oboard), apply signed configs, manage networking, and report node status. This repo also maintains `oboard-sb` (`kernel/oboard-sb`), a slim proxy kernel built on [sing-box](https://github.com/SagerNet/sing-box).

## Highlights

- **Slim proxy kernel**: `oboard-sb` keeps only the needed protocols for a smaller binary and lower memory footprint, with hot user updates and traffic limits.
- **Low-memory friendly**: Automatically tunes resource limits from host RAM and cgroup caps, keeping small 128–256 MiB VPS nodes stable without OOM kills.
- **One-command setup**: Enroll with a one-time token from the panel, with signed release checks, automatic reconnects, and self-recovery.
- **Complete networking**: Handles Realm / nftables port forwarding, transparent relays, WireGuard / SSH tunnels, and an isolated SSH proxy (`udpgw`).
- **Built-in probes**: Reports server metrics, runs latency/route/egress/MTU/DNS checks, and handles HTTP-01 certificate challenges.
- **Local CLI (`obag`)**: Interactive menu and commands to check status, restart services, inspect logs, and test panel connectivity.

## What's Supported

| Category | Supported |
| :--- | :--- |
| **Protocols** | VLESS (TLS / Reality), Hysteria2, AnyTLS, Shadowsocks (incl. UoT), Snell (v4 / v5 / v6), Mieru, SOCKS5, isolated SSH (`udpgw`) |
| **Exits & Networking** | Direct, proxy chains, WireGuard (WARP / external), HTTP/HTTPS proxy, VPNGate, Realm / nftables forwarding, SSH tunnels |
| **Platforms** | Linux (`amd64` / `arm64`, `systemd` / `OpenRC`) · Windows (`amd64`) |

## Deployment

Add a server in the OBoard panel and run the generated command, or use the bootstrap scripts directly:

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

> Set `OBOARD_ACTION=update` or `OBOARD_ACTION=uninstall` to update or remove.

## Local CLI (`obag`)

```sh
obag              # Open interactive menu
obag status       # Check Agent and kernel status
obag restart      # Restart Agent and kernel
obag logs agent   # View Agent logs (use `logs core` for oboard-sb)
obag check        # Test connectivity to the panel
```

## Build from Source

Requires Go 1.27+:

```sh
go build -o oboard-agent ./cmd/agent
./scripts/build-oboard-sb.sh
```

## License & Thanks

Copyright 2026 OBoard contributors.

`oboard-sb` is based on [sing-box](https://github.com/SagerNet/sing-box). Thanks to the sing-box project and contributors.

`oboard-agent` (including `kernel/oboard-sb`) is released under the [GNU GPL v3](LICENSE).
