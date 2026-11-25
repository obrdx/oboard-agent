<div align="center">

# OBoard Agent

**Lightweight node-side agent and slim `oboard-sb` proxy kernel for OBoard networks.**

**English** · [简体中文](README.zh-CN.md)

<p>
  <a href="https://github.com/obrdx/oboard-agent/releases"><img src="https://img.shields.io/github/v/release/obrdx/oboard-agent?include_prereleases&style=flat-square&logo=github&label=Release&color=2563eb" alt="Release"></a>
  <img src="https://img.shields.io/github/go-mod/go-version/obrdx/oboard-agent?style=flat-square&logo=go&logoColor=white&color=00ADD8" alt="Go Version">
  <img src="https://img.shields.io/badge/Kernel-oboard--sb%20%28sing--box%29-0ea5e9?style=flat-square" alt="Kernel oboard-sb">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-1e293b?style=flat-square&logo=linux&logoColor=white" alt="Platform">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/obrdx/oboard-agent?style=flat-square&logo=gnu&logoColor=white&label=License&color=16a34a" alt="License"></a>
</p>

<p>
  <a href="https://github.com/obrdx/oboard"><img src="https://img.shields.io/badge/Control%20Plane-obrdx%2Foboard-6366f1?style=flat-square&logo=github&logoColor=white" alt="OBoard Controller"></a>
  <a href="https://obrdx.github.io/"><img src="https://img.shields.io/badge/Docs%20%26%20Install-obrdx.github.io-0ea5e9?style=flat-square&logo=readthedocs&logoColor=white" alt="Docs and Install"></a>
</p>

</div>

---

## ✨ Overview

**OBoard Agent** (`oboard-agent`) runs on managed proxy nodes to connect with the [OBoard Controller](https://github.com/obrdx/oboard), verify and apply signed deployments, run automated network probes, and supervise the data plane.

This repository also maintains **`oboard-sb`** as an independent Go module (`kernel/oboard-sb`) — a slim, purpose-built proxy kernel based on [sing-box](https://github.com/SagerNet/sing-box) tuned specifically for OBoard's protocol surface, low-memory VPS environments, and runtime authorization model.

---

## ⚡ Key Advantages

- **🪶 Slim Proxy Kernel (`oboard-sb`)**: Minimal curated sing-box protocol registry with lower binary size and memory overhead, plus native per-user runtime install, token-bucket rate/quota enforcement, DNS failover groups, and IPv4/IPv6 family selection.
- **🧠 Adaptive Anti-OOM Runtime**: Automatically profiles host memory and cgroup limits (from 96 MiB micro NAT VPS up to multi-GiB hosts), dynamically scaling `GOMAXPROCS`, `GOGC`, soft memory limits, idle page reclamation, and TCP socket buffer caps.
- **🔐 Zero-Trust Signed Operations**: One-time token enrollment, Ed25519-signed release verification, signature-v2 task validation, pre-apply kernel dry-runs (`-check`), post-restart operational-digest verification, and automatic watchdog self-healing.
- **🕸️ Full Node Networking**: Coordinates `oboard-sb`, Realm / nftables port forwarding, authenticated transparent chains (`trusted_forward_v1`), WireGuard & isolated SSH tunnels, and a built-in isolated restricted SSH proxy runtime (with `udpgw`, never touching system `sshd`).
- **📡 Built-in Probes & Telemetry**: Automated inbound, port-forward, egress IP, MTU, DNS, clock, and NextTrace route probes, HTTP-01 certificate challenges, and policy-controlled connection auditing.
- **🛠️ Local CLI (`obag`)**: Interactive and scriptable command-line console for service control, Agent/kernel logs, Controller connectivity diagnostics, and local remote-access hardening.

---

## 🔌 Protocol & Runtime Capabilities

| Layer | Supported Capabilities |
| :--- | :--- |
| **Inbounds (`oboard-sb`)** | `VLESS` (TLS / Reality), `Hysteria2`, `AnyTLS`, `Shadowsocks` (incl. UoT), `Snell` (v4 / v5 / v6 multi-PSK), `Mieru` (TCP / UDP, multi-port), `SOCKS5` |
| **Outbounds & Endpoints** | `Direct`, `Block`, `VLESS`, `Hysteria2`, `AnyTLS`, `Shadowsocks`, `Snell`, `Mieru`, `SOCKS5`, `HTTP / HTTPS CONNECT`, `WireGuard` (WARP & external), `VPNGate` Pool |
| **DNS Transports** | `UDP`, `TCP`, `DoT`, `DoH`, `DoQ`, and runtime failover groups (`oboard-dns-group`) |
| **Agent Networking** | `Realm` / `nftables` port forwarding, authenticated transparent forwarding, WireGuard & isolated SSH tunnels, restricted SSH proxy (`udpgw`) |
| **Platforms** | `linux/amd64`, `linux/arm64` (`systemd` & `OpenRC`) · `windows/amd64` |

---

## 🚀 Deployment

Add a server in your **OBoard Controller** Web panel and run the generated one-time enrollment command on the target host.

### Linux (`systemd` / `OpenRC`)

```sh
curl -fsSL https://raw.githubusercontent.com/obrdx/oboard-agent/main/scripts/install.sh \
  | sudo env OBOARD_CONTROLLER_URL='https://panel.example.com' \
             OBOARD_ENROLL_TOKEN='<one-time-token>' sh
```

### Windows (Elevated PowerShell)

```powershell
$env:OBOARD_CONTROLLER_URL = 'https://panel.example.com'
$env:OBOARD_ENROLL_TOKEN   = '<one-time-token>'
& ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/obrdx/oboard-agent/main/scripts/install.ps1')))
```

> Set `OBOARD_ACTION=update` or `OBOARD_ACTION=uninstall` to update or remove an existing installation.

---

## 🛠️ Local Management (`obag`)

| Command | Description |
| :--- | :--- |
| `obag` | Open the interactive local management menu |
| `obag status` | Show Agent and `oboard-sb` service status |
| `obag start \| stop \| restart` | Start, stop, or restart Agent and kernel services |
| `obag logs agent \| core` | Inspect Agent or `oboard-sb` logs |
| `obag check` | Test connectivity to the OBoard Controller |
| `obag remote-access status \| harden \| standard` | View or adjust local remote-access security policy |

---

## 🔨 Build from Source

Requires **Go 1.27+**. `oboard-agent` and `kernel/oboard-sb` are separate Go modules:

```bash
git clone https://github.com/obrdx/oboard-agent.git
cd oboard-agent

# Build the Agent binary
go build -o oboard-agent ./cmd/agent

# Build the slim oboard-sb kernel
./scripts/build-oboard-sb.sh
```

---

## 🔗 Related Repositories

- **[obrdx/oboard](https://github.com/obrdx/oboard)** — OBoard Controller, Web panel, subscriptions, MCP, and signed asset distribution.

---

## 📄 License & Acknowledgements

Copyright 2026 OBoard contributors.

`oboard-sb` is derived from [sing-box](https://github.com/SagerNet/sing-box) — special thanks to the sing-box project and contributors.

`oboard-agent` (including `kernel/oboard-sb`) is released under the [GNU General Public License v3.0](LICENSE).
