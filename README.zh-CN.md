<div align="center">

# OBoard Agent

OBoard 节点端程序与精简代理内核 `oboard-sb`。

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

OBoard Agent 运行在代理节点上，负责对接 [OBoard 控制面板](https://github.com/obrdx/oboard)、同步配置、维护代理服务并上报节点状态。仓库内的 `kernel/oboard-sb` 同时维护基于 [sing-box](https://github.com/SagerNet/sing-box) 裁剪的精简代理内核 `oboard-sb`。

## 核心特点

- **精简内核**：`oboard-sb` 仅保留常用协议与必要功能，体积更小、内存占用更低，支持用户热更新与流量限速。
- **小内存友好**：根据机器实际内存和容器限额自动调节资源策略，128M / 256M 小内存机器也能稳跑，不容易 OOM。
- **一键接入**：在面板生成一次性安装命令即可上线，自动验签、断线重连并在异常时自恢复。
- **组网齐全**：除代理内核外，支持 Realm / nftables 端口转发、透明中转、WireGuard / SSH 隧道以及独立 SSH 代理。
- **内置探针**：支持服务器状态回报、延迟与路由测试、出口 IP / MTU / DNS 诊断和 HTTP-01 证书申请。
- **本地工具**：自带 `obag` 命令行菜单，方便在节点本地查看状态、启停服务、看日志和排查连通性。

## 支持能力

| 分类 | 支持项 |
| :--- | :--- |
| **代理协议** | VLESS (TLS / Reality)、Hysteria2、AnyTLS、Shadowsocks (含 UoT)、Snell (v4 / v5 / v6)、Mieru、SOCKS5、独立 SSH (`udpgw`) |
| **出口与组网** | 直连、链式代理、WireGuard (WARP / 外部节点)、HTTP/HTTPS 代理、VPNGate、Realm / nftables 转发、SSH 隧道 |
| **系统平台** | Linux (`amd64` / `arm64`，`systemd` / `OpenRC`) · Windows (`amd64`) |

## 部署

推荐直接在 OBoard 面板里添加服务器并复制安装命令。也可以手动运行引导脚本：

```sh
# Linux
curl -fsSL https://raw.githubusercontent.com/obrdx/oboard-agent/main/scripts/install.sh \
  | sudo env OBOARD_CONTROLLER_URL='https://panel.example.com' \
             OBOARD_ENROLL_TOKEN='<一次性令牌>' sh
```

```powershell
# Windows (管理员 PowerShell)
$env:OBOARD_CONTROLLER_URL = 'https://panel.example.com'
$env:OBOARD_ENROLL_TOKEN   = '<一次性令牌>'
& ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/obrdx/oboard-agent/main/scripts/install.ps1')))
```

> 更新或卸载时设置 `OBOARD_ACTION=update` 或 `OBOARD_ACTION=uninstall` 即可。

## 本地管理 (`obag`)

```sh
obag              # 打开交互菜单
obag status       # 查看运行状态
obag restart      # 重启 Agent 和内核
obag logs agent   # 查看 Agent 日志（查看内核用 logs core）
obag check        # 检测与面板的连接
```

## 源码构建

需要 Go 1.27+：

```sh
go build -o oboard-agent ./cmd/agent
./scripts/build-oboard-sb.sh
```

## 许可证与致谢

Copyright 2026 OBoard contributors.

`oboard-sb` 基于 [sing-box](https://github.com/SagerNet/sing-box) 修改，感谢 sing-box 项目及贡献者。

`oboard-agent`（含 `kernel/oboard-sb`）基于 [GNU GPL v3](LICENSE) 开源。
