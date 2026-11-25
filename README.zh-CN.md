<div align="center">

# OBoard Agent

OBoard 节点侧守护程序与精简代理内核 `oboard-sb`。

[English](README.md) · **简体中文**

<p>
  <a href="https://github.com/obrdx/oboard-agent/releases"><img src="https://img.shields.io/github/v/release/obrdx/oboard-agent?include_prereleases&style=flat-square&logo=github&label=Release&color=2563eb" alt="Release"></a>
  <img src="https://img.shields.io/github/go-mod/go-version/obrdx/oboard-agent?style=flat-square&logo=go&logoColor=white&color=00ADD8" alt="Go">
  <img src="https://img.shields.io/badge/Kernel-oboard--sb%20%28sing--box%29-0ea5e9?style=flat-square" alt="oboard-sb">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-1e293b?style=flat-square&logo=linux&logoColor=white" alt="Platform">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/obrdx/oboard-agent?style=flat-square&logo=gnu&logoColor=white&label=License&color=16a34a" alt="License"></a>
</p>

<p>
  <a href="https://github.com/obrdx/oboard"><img src="https://img.shields.io/badge/%E6%8E%A7%E5%88%B6%E9%9D%A2%E6%9D%BF-obrdx%2Foboard-6366f1?style=flat-square&logo=github&logoColor=white" alt="OBoard"></a>
  <a href="https://obrdx.github.io/"><img src="https://img.shields.io/badge/%E5%AE%89%E8%A3%85%E4%B8%8E%E6%96%87%E6%A1%A3-obrdx.github.io-0ea5e9?style=flat-square&logo=readthedocs&logoColor=white" alt="安装与文档"></a>
</p>

</div>

OBoard Agent 部署于代理节点，负责与 [OBoard 控制面板](https://github.com/obrdx/oboard) 建立安全通信、校验并应用签名配置、维护网络与转发服务并上报节点状态。本仓库同时以独立模块（`kernel/oboard-sb`）维护基于 [sing-box](https://github.com/SagerNet/sing-box) 裁剪的精简代理内核 `oboard-sb`。

## 核心特性

- **精简代理内核**：`oboard-sb` 仅保留受支持的协议与核心组件，降低二进制体积与内存占用，并支持运行时用户热更新与流量限速。
- **资源自适应**：依据宿主机物理内存与容器 cgroup 限额自动调整运行参数，保障 128 MiB / 256 MiB 等低内存节点的长期稳定运行，降低 OOM 风险。
- **签名校验与自恢复**：通过面板签发的一次性令牌完成接入，内置发行包签名验证、断线自动重连以及服务异常自愈机制。
- **完整组网能力**：统一调度代理内核、Realm / nftables 端口转发、透明中转、WireGuard / SSH 隧道及独立隔离的 SSH 代理服务。
- **探测与诊断**：支持节点状态上报、延迟与路由探测、出口 IP / MTU / DNS 检测及 HTTP-01 证书签发。
- **本地运维工具**：提供 `obag` 命令行工具，支持在节点本地查看服务状态、启停服务、查阅日志及测试面板连通性。

## 支持范围

| 分类 | 支持项 |
| :--- | :--- |
| **代理协议** | VLESS (TLS / Reality)、Hysteria2、AnyTLS、Shadowsocks (含 UoT)、Snell (v4 / v5 / v6)、Mieru、SOCKS5、独立 SSH (`udpgw`) |
| **出口与组网** | 直连、链式代理、WireGuard (WARP / 外部节点)、HTTP / HTTPS 代理、VPNGate、Realm / nftables 转发、SSH 隧道 |
| **运行平台** | Linux (`amd64` / `arm64`，`systemd` / `OpenRC`) · Windows (`amd64`) |

## 部署

建议在 OBoard 控制面板中添加服务器后直接执行生成的安装命令，亦可手动运行引导脚本：

```sh
# Linux
curl -fsSL https://raw.githubusercontent.com/obrdx/oboard-agent/main/scripts/install.sh \
  | sudo env OBOARD_CONTROLLER_URL='https://panel.example.com' \
             OBOARD_ENROLL_TOKEN='<一次性令牌>' sh
```

```powershell
# Windows（以管理员身份运行 PowerShell）
$env:OBOARD_CONTROLLER_URL = 'https://panel.example.com'
$env:OBOARD_ENROLL_TOKEN   = '<一次性令牌>'
& ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/obrdx/oboard-agent/main/scripts/install.ps1')))
```

> 通过设置 `OBOARD_ACTION=update` 或 `OBOARD_ACTION=uninstall` 可执行升级或卸载操作。

## 本地管理 (`obag`)

```sh
obag              # 进入交互式管理菜单
obag status       # 查看 Agent 与内核运行状态
obag restart      # 重启 Agent 与内核服务
obag logs agent   # 查看 Agent 日志（查看内核日志使用 logs core）
obag check        # 检测与控制面板的连通性
```

## 源码构建

需要 Go 1.27 及以上版本：

```sh
go build -o oboard-agent ./cmd/agent
./scripts/build-oboard-sb.sh
```

## 许可证与致谢

Copyright 2026 OBoard contributors.

`oboard-sb` 基于 [sing-box](https://github.com/SagerNet/sing-box) 构建，谨向 sing-box 项目及贡献者致谢。

`oboard-agent`（含 `kernel/oboard-sb`）遵循 [GNU GPL v3](LICENSE) 许可证发布。
