# gosingbox

Remnawave 面板的节点端（Go 实现），数据面 **sing-box 内嵌库**。
保留面板通信协议（HTTPS REST + JWT + mTLS），把数据面从 Xray-core 替换为
sing-box，并做到**用户增删不重启监听器**（`UpdatableInbound` 无感热插拔）。

> 支持的入站：**VLESS + Reality + xtls-rprx-vision (TCP)** 与
> **Shadowsocks 2022 (`2022-blake3-aes-256-gcm`)**。

## 特性

- **单静态二进制**（sing-box 内嵌，无 Node / glibc / 子进程依赖），Alpine 3.21 + 128MB LXC 可跑。
- **无感热插拔用户**：VLESS 走 `UpdateUsers()`、SS2022 走 `UpdateUsersByOptions()`，
  增删不重启监听器、不中断其他连接。
- 统计走 v2ray_api gRPC；在线用户/单用户 IP/最后活动时间走 clash_api `/connections`（`userId` = 用户 email）。
- **断连（connection-drop）**：`drop-ips` / `drop-users-connections` 走 clash_api
  `DELETE /connections/:id` 关闭匹配连接，无需 `sockdestroy`/`CAP_NET_ADMIN`。
- **preStart**：`cleanupSockets` 在每次 sing-box (re)start 前清理遗留 unix socket。
- 一键安装/升级/卸载（Alpine / OpenRC）。
- geo 检测（内置 geocheck）、ASN shared lists、nftables ingress/egress filter。

## 一键安装（Alpine / OpenRC）

```bash
wget -qO- https://raw.githubusercontent.com/rwnode/rwnode-gosingbox/main/scripts/install-gosingbox.sh | sh
```

或带参数：

```bash
# 查看安装器版本（判断 CDN 是否缓存旧版）
wget -qO- https://raw.githubusercontent.com/rwnode/rwnode-gosingbox/main/scripts/install-gosingbox.sh | sh -s -- --version
```

脚本会询问 `NODE_PORT`（默认 2222）与 `SECRET_KEY`（面板下发），并安装
`curl nftables`、下载解包二进制、写 env、生成 OpenRC 服务并自启。

## 构建

```bash
./scripts/build-gosingbox.sh
# 产物 dist-go/gosingbox-<ver>-linux-amd64.tar.gz
```

需要 `git`/`curl`/`go`（sing-box 经 `replace` 引用 fork `rwnode/sing-box-fork`）。

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `NODE_PORT` | `2222` | 面板连接端口 |
| `SECRET_KEY` | — | 面板下发（含节点证书/JWT 公钥），serve 模式必填 |
| `LOG_LEVEL` | `info` | 节点自身日志级别（debug/info/warn/error） |
| `SINGBOX_STATS_ADDRESS` | `127.0.0.1:6450` | 内嵌 v2ray_api gRPC 统计地址 |
| `SINGBOX_CLASH_ADDRESS` | `127.0.0.1:9090` | 内嵌 clash_api 地址（在线用户/断连用） |
| `SINGBOX_LOG_LEVEL` | `warn` | sing-box 日志级别 |
| `SINGBOX_DEBOUNCE_MS` | `5000` | 用户变更 debounce 窗口（热插拔合批） |
| `SINGBOX_LISTEN` | 空（双栈） | 监听地址覆盖；`0.0.0.0` 强制 IPv4 |
| `SINGBOX_GEO_DIR` | — | geosite/geoip rule-set(.srs) 下载缓存目录 |
| `ASN_INDEX_PATH` | — | asn-prefixes.json（remnawave/asn-index，ASN shared list 用） |

其余见 `scripts/go-standalone/env.example`。

## 功能边界

sing-box 数据面固有的缺口（torrent 实时检测）见
[`UNIMPLEMENTED.md`](UNIMPLEMENTED.md)。

## 命名

项目名 `gosingbox` = Go + sing-box。对外包名/二进制/服务名统一为 `gosingbox`，
Go module 为 `github.com/rwnode/rwnode-gosingbox`。