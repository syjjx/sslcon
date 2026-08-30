# sslcon 更新通知（供其他智能体/协作者使用）

sslcon 项目已完成更新并推送到 GitHub（仓库地址：`https://github.com/syjjx/sslcon.git`，main 分支），本次更新主要新增了对 **Cisco AnyConnect / ASA** 服务器的支持：修复了认证阶段 XML 协议兼容问题（`device-id` 改为带平台文本、增加 `group-access`、移除多余的 `mac-address-list`、`group-select` 按需输出、认证响应 Cookie 回传、User-Agent 对齐为 `AnyConnect <version>` 格式、ASA 错误响应显式报错），对齐了 CONNECT 隧道请求头（`X-CSTP-Address-Type` / `X-CSTP-Version` / `X-CSTP-Protocol` / `X-CSTP-Hostname`），修复了 macOS 路由安装时"本机局域网路由已存在（EEXIST）导致连接中断"的问题，并增强了动态域名分流（如 salesforce.com 按 DNS 解析结果动态添加隧道路由）及可观测性（status 可查看域名→IP 映射、Debug 日志输出嗅探记录）。该版本已在 **Cisco ASA 5545 (v9.14)** 上全流程实测通过（认证 → TLS 隧道 → DTLS → 路由 → DNS → 动态分流），且 **ocserv 服务器连接也已测试通过**。

## 第二期新增功能（同样已实测通过）

- **数据压缩**：协商 `X-CSTP-Accept-Encoding: oc-lz4,lzs`，压缩数据帧（类型 0x08）在 TLS/DTLS 通道收发。LZS 编解码为 openconnect `lzs.c` 的逐位移植（已用 C 实现黄金向量验证一致），LZ4 使用标准 block 格式。由服务端决定是否启用（配置项 `compression`，默认 true）。deflate 暂未实现。
- **会话超时/租期处理**：解析 `X-CSTP-Idle-Timeout` / `X-CSTP-Lease-Duration` / `X-CSTP-Session-Timeout(-Remaining)`，status 暴露 `idle_timeout` / `auth_expiration`，到期前输出告警日志（配置项 `auto_reconnect` 开启时配合自动重连）。
- **自动重连增强**：异常断线后指数退避自动重连（1s 起，翻倍至 60s 封顶），用户主动断开不触发（配置项 `auto_reconnect`，默认 true）。

## 任务

从该仓库拉取最新 main 分支代码并完成编译。

## 编译要求

- 项目要求 **Go 1.26.2**（go.mod 已声明；本机版本较低时，`GOTOOLCHAIN` 会自动下载对应工具链）
- 在项目根目录**分别执行**（两个入口文件各自含 main，必须分开编译）：

```bash
go build -o sslcon sslcon.go
go build -o vpnagent vpnagent.go
```

- 可选：`go test ./...` 验证单元测试（含 LZS 黄金向量、压缩往返、会话解析等）

## 平台说明

- 认证、隧道、DTLS、压缩、动态分流等核心功能**全平台有效**（Windows / Linux / macOS / Android / iOS），`device-id` 平台标识按系统自动映射（`win` / `linux-64` / `mac-intel` / `android` / `apple-ios`）
- macOS 路由 EEXIST 修复仅涉及 `utils/vpnc/vpnc_darwin.go`；Linux / Windows 的路由代码原本就忽略"路由已存在"错误，无需该修复

## 使用提示

- 连接 Cisco ASA 时若服务器发布多个用户组，需用 `-g` 参数指定组名（组不对会报 `Login failed`）
- 压缩需要服务端开启（ASA 在 group-policy → webvpn 下配置 `compression lzs`，默认 deflate 不在客户端协商列表内）
- `-l Debug` 可输出完整认证日志（密码已打码）
- 老 ASA 仅支持 DTLS 1.0 时可用 `no_dtls: true` 配置保持纯 TLS 隧道
