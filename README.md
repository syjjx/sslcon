> This repository is now in security-maintenance mode. Future development will continue at https://github.com/bjdgyc/sslcon

## sslcon

This is a Golang implementation of the [OpenConnect VPN Protocol](https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-04) for client side development. 

The released binaries contain a command line program(sslcon) and a VPN service agent(vpnagent), the latter of which should be run as a separate background service with root privileges, so that the front-end UI does not require an administrator authorization every time it starts. 

The API is exposed through the WebSocket and JSON-RPC 2.0 protocols, so developers can easily customize a graphical interface that meets their needs.

**[There](https://github.com/tlslink/anylink-client) is a GUI client example showing how to use this project.**

Currently the following servers are supported,

- [AnyLink](https://github.com/bjdgyc/anylink)
- [OpenConnect VPN server](https://gitlab.com/openconnect/ocserv)
- [Cisco AnyConnect / ASA / FTD](https://www.cisco.com/site/us/en/products/security/secure-client/index.html)

## CLI

```
$ ./sslcon
A CLI application that supports the OpenConnect SSL VPN protocol.
For more information, please visit https://github.com/tlslink/sslcon

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

### install

```shell
sudo ./vpnagent install
# uninstall
sudo ./vpnagent uninstall
```
the installed service on systemd linux

```
sudo systemctl stop/start/restart sslcon.service
sudo systemctl disable/enable sslcon.service
```

the installed service on OpenWrt

```
/etc/init.d/sslcon stop/start/restart/status
```

### connect

```bash
./sslcon connect -s test.com -u vpn -g default -k key
```

### Cisco AnyConnect / ASA notes

- The server may publish a group list during authentication; use the `-g` flag
  to select the tunnel group, e.g. `./sslcon connect -s vpn.example.com -u user -g RA`.
  A wrong or missing group results in `Login failed`.
- The client reports itself as `AnyConnect <version>` (default `4.10.07062`),
  overridable with the `agent_name` / `agent_version` config fields.
- Older ASA versions only support DTLS 1.0, which this client does not implement;
  set `no_dtls: true` in the config to keep a pure TLS tunnel in that case.
- Debug logs (`-l Debug`) print the full XML auth exchange; the password is masked.

### disconnect

```
./sslcon disconnect
```

### status

```
./sslcon status
```

## APIs

You can use any WebSocket tool to test the API.

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
    "agent_version": "4.10.07062"
  },
  "id": 1
}
```

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
