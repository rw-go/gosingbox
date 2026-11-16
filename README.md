# gosingbox

Remnawave 面板的节点端（Go 实现），数据面 **sing-box 内嵌库**。
保留面板通信协议（HTTPS REST + JWT + mTLS），把数据面从 Xray-core 替换为
sing-box，并做到**用户增删不重启监听器**（`UpdatableInbound` 无感热插拔）。

> 原生模式支持 **AnyTLS（普通 TLS）**、**TCP VLESS（保留 TLS/Reality 和 flow）**、
> **SS2022 AES-128/256-GCM 多用户**；Xray 输入继续沿用原有转译行为。

当前发布版本 **3.4.1.20**，内嵌 sing-box **1.14.3**，Panel 上报 `nodeVersion=3.4.1`。
原生集成包含 [节点能力扩展 v1](docs/node-capabilities.md)、
[按入站管理用户及 AnyTLS 生命周期](docs/user-lifecycle.md) 和
[原生配置入口](docs/native-config.md)。已与配套修改版 Panel 完成原生 Profile、权限、
用户同步、订阅及实际 AnyTLS/VLESS 连接验证；官方 Xray 格式输入保留原有转译路径。
原生配置需要支持该扩展的 Panel；仅升级节点不会给官方 Panel 增加配置编辑能力。

本次发布渠道为 **Docker Hub 与 Bitbucket**，GitHub 尚未同步。请使用下方 Bitbucket
安装入口或 `rwnode/gosingbox:3.4.1.20`。本版新增 AnyTLS 按 SNI 共用 TCP 443，
配置与兼容边界见 [3.4.1.20 发布说明](docs/releases/3.4.1.20.md)。

## 特性

- **单静态二进制**（sing-box 内嵌，无 Node / glibc / 子进程依赖），Alpine 3.21 + 128MB LXC 可跑。
- **无感热插拔用户**：VLESS/AnyTLS 走 `UpdateUsers()`、SS2022 走 `UpdateUsersByOptions()`，
  增删不重启监听器、不中断其他连接；且热插拔用户实时同步进入统计白名单。
- **AnyTLS 共用端口**：原生入站通过 `shared_listener` 按客户端 SNI 共用一个 TCP 监听端口，
  各入站独立认证、授权和路由，保留真实源 IP，无需 Nginx。
- **Xray 转译模式的协议与域名嗅探（Sniffing 对齐）**：当入站开启 `sniffing` 或规则包含域名匹配时，自动注入 sing-box 1.14 `action: sniff` 动作，解决客户端预解析 IP 导致域名分流规则漏匹配的问题。
- 统计走 v2ray_api gRPC；在线用户/单用户 IP/最后活动时间走 clash_api `/connections`（`userId` = 用户 email）。
- **断连（connection-drop）**：`drop-ips` / `drop-users-connections` 走 clash_api
  `DELETE /connections/:id` 关闭匹配连接，无需 `sockdestroy`/`CAP_NET_ADMIN`；支持
  `connectionDrop.whitelistIps` 白名单 + 默认忽略 IP（回环/未指定/广播）。
- **私有 SNI 校验**：`SNI_VERIFICATION=true` 时按 SECRET_KEY 派生的私有 SNI 校验 mTLS
  握手（HKDF-SHA256，对齐官方 `decode-servername.util.ts`）。
- **preStart**：`cleanupSockets` 在每次 sing-box (re)start 前清理遗留 unix socket。
- **postStart**（官方 3.4.2）：core 成功启动后发送 `service.core_started` webhook。
- **单实例锁**：抽象 unix socket 防止同机多实例。
- 一键安装/升级/卸载（OpenRC / systemd）。
- geo 检测（内置 geocheck）、ASN shared lists、nftables ingress/egress filter
  （含 `NFTABLES_ACCEPT_REPLY_TRAFFIC` 回程流量放行）。

## 一键安装（OpenRC / systemd）

### Bitbucket 安装（本次发布渠道）

```bash
wget -qO- https://bitbucket.org/rwnode/rwnode-gosingbox/raw/main/scripts/install-gosingbox.sh | sh
```

GitHub 仓库仍保留旧版本；本次原生集成暂不从 GitHub 安装。

或带参数：

```bash
# 查看安装器版本（判断 CDN 是否缓存旧版）
wget -qO- https://bitbucket.org/rwnode/rwnode-gosingbox/raw/main/scripts/install-gosingbox.sh | sh -s -- --version
```

脚本会询问 `NODE_PORT`（默认 2222）与 `SECRET_KEY`（面板下发），自动检测 init
系统（OpenRC / systemd）、安装 `curl nftables`、下载解包二进制、写 env、生成服务并自启。
Alpine 用 OpenRC，Debian/Ubuntu/Arch 等用 systemd。

## Docker 安装（推荐用于通用 Linux）

Docker 版使用单进程 Alpine 镜像（内嵌 sing-box，不包含 Node.js、Xray 或 s6），默认镜像：
`rwnode/gosingbox:latest`。生产部署可固定为 `rwnode/gosingbox:3.4.1.20`。

一键安装（从 Bitbucket）：

```bash
wget -qO- https://bitbucket.org/rwnode/rwnode-gosingbox/raw/main/scripts/install-gosingbox-docker.sh | sh
```

升级或卸载：

```bash
wget -qO- https://bitbucket.org/rwnode/rwnode-gosingbox/raw/main/scripts/install-gosingbox-docker.sh | sh -s -- upgrade
wget -qO- https://bitbucket.org/rwnode/rwnode-gosingbox/raw/main/scripts/install-gosingbox-docker.sh | sh -s -- uninstall
# 连同配置和数据卷全部删除：
wget -qO- https://bitbucket.org/rwnode/rwnode-gosingbox/raw/main/scripts/install-gosingbox-docker.sh | sh -s -- uninstall-full
```

手动使用 Compose：

```bash
export NODE_PORT=2222
export SECRET_KEY='面板下发的 SECRET_KEY'
docker compose up -d
docker logs -f gosingbox
```

Docker 版固定使用 `network_mode: host`，因为 Panel 会动态下发用户入站端口，且在线 IP
统计需要保留真实源地址。启用 nftables 插件时需要 `NET_ADMIN`；compose 已默认添加。镜像
不设置硬内存上限，生产环境如需限制建议不低于 512MB。

## 构建

```bash
./scripts/build-gosingbox.sh
# 产物 dist-go/gosingbox-<ver>-linux-amd64.tar.gz
```

需要 `git`/`curl`/`go`（sing-box 1.14.3 经 `replace` 引用
`bitbucket.org/rwnode/sing-box-fork` 的 `v1.14.3-updatable.1` 补丁版本）。

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `NODE_PORT` | `2222` | 面板连接端口 |
| `SECRET_KEY` | — | 面板下发（含节点证书/JWT 公钥），serve 模式必填 |
| `INTERNAL_SOCKET_PATH` | — | internal API 使用的 Unix socket 路径，serve 模式必填 |
| `INTERNAL_REST_TOKEN` | — | internal API 的 query token，serve 模式必填 |
| `LOG_LEVEL` | `info` | 节点自身日志级别（debug/info/warn/error） |
| `SINGBOX_STATS_ADDRESS` | `127.0.0.1:6450` | 内嵌 v2ray_api gRPC 统计地址 |
| `SINGBOX_CLASH_ADDRESS` | `127.0.0.1:9090` | 内嵌 clash_api 地址（在线用户/断连用） |
| `SINGBOX_LOG_LEVEL` | `warn` | Xray 转译时 sing-box 日志级别；原生配置保留自身 log |
| `SINGBOX_DEBOUNCE_MS` | `5000` | 兼容保留，用户变更现为同步应用 |
| `SINGBOX_LISTEN` | 空（双栈） | Xray 转译时监听地址覆盖；`0.0.0.0` 强制 IPv4 |
| `SINGBOX_GEO_DIR` | — | geosite/geoip rule-set(.srs) 下载缓存目录 |
| `ASN_INDEX_PATH` | — | asn-prefixes.json（remnawave/asn-index，ASN shared list 用） |
| `SNI_VERIFICATION` | `false` | 按 SECRET_KEY 派生私有 SNI 并校验 mTLS 握手 |
| `NFTABLES_ACCEPT_REPLY_TRAFFIC` | `false` | egress filter 放行已有连接的回程流量（conntrack established/related） |

其余见 `scripts/go-standalone/env.example`。gosingbox 使用内嵌 sing-box，不使用外部
sing-box 可执行文件、外部配置文件或独立 sing-box 日志目录。

## 功能边界

sing-box 数据面固有的缺口（torrent 实时检测）见
[`UNIMPLEMENTED.md`](UNIMPLEMENTED.md)。

## 命名

项目名 `gosingbox` = Go + sing-box。对外包名/二进制/服务名统一为 `gosingbox`，
Go module 为 `github.com/rwnode/rwnode-gosingbox`。
