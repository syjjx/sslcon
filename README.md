> 本仓库目前处于安全维护模式，后续开发将在 https://github.com/bjdgyc/sslcon 继续进行

## sslcon

这是 [OpenConnect VPN 协议](https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-04) 的 Golang 客户端实现，供客户端侧开发使用。

发布的二进制包含一个命令行程序（sslcon）和一个 VPN 服务代理（vpnagent）。vpnagent 应以 root 权限作为独立的后台服务运行，这样前端 UI 每次启动时都不需要管理员授权。

API 通过 WebSocket 和 JSON-RPC 2.0 协议暴露，开发者可以方便地定制符合自己需求的图形界面。

**[这里](https://github.com/tlslink/anylink-client) 有一个 GUI 客户端示例，展示了如何使用本项目。**

目前支持以下服务器：

- [AnyLink](https://github.com/bjdgyc/anylink)
- [OpenConnect VPN server](https://gitlab.com/openconnect/ocserv)
- [Cisco AnyConnect / ASA / FTD](https://www.cisco.com/site/us/en/products/security/secure-client/index.html)

## CLI

```
$ ./sslcon
支持 OpenConnect SSL VPN 协议的命令行应用。
更多信息请访问 https://github.com/tlslink/sslcon

Usage:
  sslcon [flags]
  sslcon [command]

Available Commands:
  connect     Connect to the VPN server
  disconnect  Disconnect from the VPN server
  status      Get VPN connection information

Flags:
  -h, --help   help for sslcon

Use "sslcon [command] --help" for more information about a command.
```

### 安装

```shell
sudo ./vpnagent install
# 卸载
sudo ./vpnagent uninstall
```

Linux systemd 服务管理：

```
sudo systemctl stop/start/restart sslcon.service
sudo systemctl disable/enable sslcon.service
```

OpenWrt 服务管理：

```
/etc/init.d/sslcon stop/start/restart/status
```

### 连接

```bash
./sslcon connect -s test.com -u vpn -g default -k key
```

### Cisco AnyConnect / ASA 使用说明

- 认证时服务器可能会下发用户组列表，需要用 `-g` 参数指定隧道组，例如
  `./sslcon connect -s vpn.example.com -u user -g RA`。组不正确或缺失会导致
  `Login failed`。
- 客户端上报身份为 `AnyConnect <version>`（默认 `4.10.07062`），可通过配置项
  `agent_name` / `agent_version` 覆盖。
- 较老的 ASA 只支持 DTLS 1.0，本客户端未实现该版本；可设置 `no_dtls: true`
  保持纯 TLS 隧道。
- `-l Debug` 会输出完整的 XML 认证交互日志（密码已打码）。

### 断开

```
./sslcon disconnect
```

### 状态

```
./sslcon status
```

## API

可以使用任意 WebSocket 工具测试 API。

ws://127.0.0.1:6210/rpc

### status

```json
{
  "jsonrpc": "2.0",
  "method": "status",
  "id": 0
}
```

### config

```json
{
  "jsonrpc": "2.0",
  "method": "config",
  "params": {
    "log_level": "Debug",
    "log_path": "",
    "skip_verify": true,
    "no_dtls": false,
    "agent_name": "AnyConnect",
    "agent_version": "4.10.07062",
    "compression": true,
    "auto_reconnect": true
  },
  "id": 1
}
```

配置项说明：

- `compression`：是否协商数据压缩（oc-lz4 / lzs，由服务端决定是否启用，默认开启）
- `auto_reconnect`：异常断线时自动重连（1s 起指数退避至 60s，默认开启）
- `no_dtls`：禁用 DTLS，仅使用 TLS 隧道（老 ASA 只支持 DTLS 1.0 时使用）
- `skip_verify`：跳过 TLS 证书校验（默认 true，生产环境建议配合证书指纹校验）

### connect

```json
{
  "jsonrpc": "2.0",
  "method": "connect",
  "params": {
    "host": "vpn.test.com",
    "username": "vpn",
    "password": "123456",
    "group": "",
    "secret": ""
  },
  "id": 2
}
```

### disconnect

```json
{
  "jsonrpc": "2.0",
  "method": "disconnect",
  "id": 3
}
```

### reconnect

```json
{
  "jsonrpc": "2.0",
  "method": "reconnect",
  "id": 4
}
```

### stat

```json
{
  "jsonrpc": "2.0",
  "method": "stat",
  "id": 7
}
```

## 建议

> 除非有不得不用的理由，建议远离 Electron
>
> 安装包体积不是问题，关键是它会在硬盘 cache 目录拉一坨，一坨还好，那一坨又一坨呢？
