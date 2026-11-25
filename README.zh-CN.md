<div align="center">

# OBoard Agent

**面向 OBoard 代理网络的轻量级节点 Agent 与精简 `oboard-sb` 代理内核。**

[English](README.md) · **简体中文**

<p>
  <a href="https://github.com/obrdx/oboard-agent/releases"><img src="https://img.shields.io/github/v/release/obrdx/oboard-agent?include_prereleases&style=flat-square&logo=github&label=Release&color=2563eb" alt="Release"></a>
  <img src="https://img.shields.io/github/go-mod/go-version/obrdx/oboard-agent?style=flat-square&logo=go&logoColor=white&color=00ADD8" alt="Go Version">
  <img src="https://img.shields.io/badge/Kernel-oboard--sb%20%28sing--box%29-0ea5e9?style=flat-square" alt="Kernel oboard-sb">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-1e293b?style=flat-square&logo=linux&logoColor=white" alt="Platform">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/obrdx/oboard-agent?style=flat-square&logo=gnu&logoColor=white&label=License&color=16a34a" alt="License"></a>
</p>

<p>
  <a href="https://github.com/obrdx/oboard"><img src="https://img.shields.io/badge/%E4%B8%BB%E6%8E%A7%E9%9D%A2%E6%9D%BF-obrdx%2Foboard-6366f1?style=flat-square&logo=github&logoColor=white" alt="OBoard Controller"></a>
  <a href="https://obrdx.github.io/"><img src="https://img.shields.io/badge/%E6%96%87%E6%A1%A3%E4%B8%8E%E5%AE%89%E8%A3%85-obrdx.github.io-0ea5e9?style=flat-square&logo=readthedocs&logoColor=white" alt="文档与安装"></a>
</p>

</div>

---

## ✨ 项目简介

**OBoard Agent**（`oboard-agent`）运行在受管代理节点上，负责与 [OBoard 主控面板](https://github.com/obrdx/oboard) 安全通信、校验并应用已签名配置、执行探测与运维任务，并守护节点数据面运行。

本仓库同时以独立 Go 模块（`kernel/oboard-sb`）维护精简代理内核 **`oboard-sb`** —— 基于 [sing-box](https://github.com/SagerNet/sing-box) 深度裁剪与定制，面向 OBoard 协议集合、小内存 VPS 与运行时动态授权场景专门优化。

---

## ⚡ 核心优势

- **🪶 精简代理内核（`oboard-sb`）**：仅保留 OBoard 所需的最小协议注册表，体积更小、常驻内存更低；原生支持运行时用户热安装、令牌桶限速与配额控制、DNS 故障转移组及 IPv4 / IPv6 分流选择。
- **🧠 资源自适应与防 OOM**：自动识别宿主机物理内存与 cgroup 限额（覆盖 96 MiB 微型 NAT 机到多 GiB 服务器），动态调节 `GOMAXPROCS`、`GOGC`、软内存上限、空闲内存回收与 TCP Socket 缓冲区水位，兼顾性能与稳定性。
- **🔐 签名校验与自愈守护**：一次性令牌接入、Ed25519 发行包验签、v2 任务签名校验、变更前内核预检（`-check`）、重启后运行态摘要核验，以及配置漂移与异常退出自动恢复。
- **🕸️ 完整节点组网能力**：统一调度 `oboard-sb`、Realm / nftables 端口转发、可信透明转发（`trusted_forward_v1`）、WireGuard / 独立 SSH 隧道，以及内置隔离的受限 SSH 代理服务（支持 `udpgw`，不复用系统 `sshd`）。
- **📡 探针监测与诊断**：内置入站、端口转发、出口 IP、MTU、DNS、时钟与 NextTrace 路由探测，支持 HTTP-01 证书签发以及受策略控制的连接审计与状态回报。
- **🛠️ 本地运维工具（`obag`）**：提供交互式菜单与命令行子命令，一键查看状态、启停服务、查阅 Agent / 内核日志、检测主控连通性及调整本地远程访问安全策略。

---

## 🔌 协议与运行能力

| 层级 | 支持能力 |
| :--- | :--- |
| **内核入站（`oboard-sb`）** | `VLESS`（TLS / Reality）、`Hysteria2`、`AnyTLS`、`Shadowsocks`（含 UoT）、`Snell`（v4 / v5 / v6 多 PSK）、`Mieru`（TCP / UDP 多端口）、`SOCKS5` |
| **内核出站与端点** | `Direct`、`Block`、`VLESS`、`Hysteria2`、`AnyTLS`、`Shadowsocks`、`Snell`、`Mieru`、`SOCKS5`、`HTTP / HTTPS CONNECT`、`WireGuard`（WARP 及外部节点）、`VPNGate` 出口池 |
| **DNS 传输** | `UDP`、`TCP`、`DoT`、`DoH`、`DoQ` 与运行时故障转移组（`oboard-dns-group`） |
| **Agent 组网** | `Realm` / `nftables` 端口转发、可信透明转发、WireGuard 与独立 SSH 隧道、受限 SSH 代理（`udpgw`） |
| **支持平台** | `linux/amd64`、`linux/arm64`（`systemd` 与 `OpenRC`）· `windows/amd64` |

---

## 🚀 节点部署

推荐直接在 **OBoard 主控面板** 中添加服务器并复制生成的一次性安装命令。

### Linux（`systemd` / `OpenRC`）

```sh
curl -fsSL https://raw.githubusercontent.com/obrdx/oboard-agent/main/scripts/install.sh \
  | sudo env OBOARD_CONTROLLER_URL='https://panel.example.com' \
             OBOARD_ENROLL_TOKEN='<一次性安装令牌>' sh
```

### Windows（管理员 PowerShell）

```powershell
$env:OBOARD_CONTROLLER_URL = 'https://panel.example.com'
$env:OBOARD_ENROLL_TOKEN   = '<一次性安装令牌>'
& ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/obrdx/oboard-agent/main/scripts/install.ps1')))
```

> 设置 `OBOARD_ACTION=update` 或 `OBOARD_ACTION=uninstall` 可执行节点更新或卸载。

---

## 🛠️ 本地运维命令（`obag`）

| 命令 | 说明 |
| :--- | :--- |
| `obag` | 打开交互式本地管理菜单 |
| `obag status` | 查看 Agent 与 `oboard-sb` 运行状态 |
| `obag start \| stop \| restart` | 启动、停止或重启 Agent 与内核服务 |
| `obag logs agent \| core` | 查看 Agent 或 `oboard-sb` 运行日志 |
| `obag check` | 检测与 OBoard 主控的连接状态 |
| `obag remote-access status \| harden \| standard` | 查看或调整节点远程访问安全级别 |

---

## 🔨 从源码构建

需要 **Go 1.27+**。`oboard-agent` 与 `kernel/oboard-sb` 为独立 Go 模块：

```bash
git clone https://github.com/obrdx/oboard-agent.git
cd oboard-agent

# 构建 Agent 主程序
go build -o oboard-agent ./cmd/agent

# 构建精简内核 oboard-sb
./scripts/build-oboard-sb.sh
```

---

## 🔗 相关仓库

- **[obrdx/oboard](https://github.com/obrdx/oboard)** — OBoard 控制平面主控面板、Web 界面、多格式订阅、MCP 与已签名资产分发。

---

## 📄 许可证与致谢

Copyright 2026 OBoard contributors.

`oboard-sb` 基于 [sing-box](https://github.com/SagerNet/sing-box) 进行修改，谨向 sing-box 项目及贡献者致谢。

`oboard-agent`（包含 `kernel/oboard-sb`）基于 [GNU General Public License v3.0](LICENSE) 许可证发布。
