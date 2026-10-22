# 未实现 / 降级功能

本文档记录 `gosingbox`（Go 版节点，sing-box 数据面）相对官方 remnawave/node 的功能
差距与暂不实现项。对照基准为**官方 3.4.3** 的 Panel-facing contract。

分三类：**未实现**、**类似实现**、**sing-box 下无需实现**。

## 一、未实现

### torrent-blocker 实时检测 —— 搁置

- **现状**：`/node/plugin/torrent-blocker/collect` 恒返回空报告；`/internal/webhook` 返回 501 降级
  响应（不再伪装成功）。
- **原因**：官方 BT 检测靠 **Xray 内核** sniffing + webhook 推送命中事件，nftables 只负责
  最终封 IP；sing-box 无等价能力。
- **实现路径**（均不划算）：nftables raw payload 匹配明文 BT 握手（漏 MSE/PE 加密）；或
  给 sing-box 打 DPI 补丁等价 webhook（维护随内核升级持续）。
- **结论**：个人自用不启用；如需再按上述任一方案补。

## 二、协议能力差异（数据面固有）

sing-box 数据面仅支持 **VLESS + Reality + xtls-rprx-vision** 与
**Shadowsocks 2022 (`2022-blake3-aes-256-gcm`)**。官方 Xray 数据面额外支持的
VMess / Trojan / 老式 SS / Hysteria / Hysteria2 及 ws·grpc·xhttp 等传输在本项目
**不支持**（by design，无本地需求，故不实现）。

## 三、类似实现（等价但细节差异，均不影响 Panel 对接）

| 官方 | gosingbox | 影响 |
|---|---|---|
| nftables `NFTABLES_LOGGING`（默认 true，规则带 log 前缀） | 无 | 低（仅审计日志） |
| 请求体上限 `bodyParser 1000mb` | 64MB | 低（xrayConfig 远小于 64MB） |
| 响应 `compression()` + `helmet()` | 无 | 低（非 contract） |
| zod 全量 schema 校验（UUID/字段类型/端口范围） | 手动 json decode，校验较松 | 中（畸形请求可能到 sing-box 才报错） |
| `drop-ips`/`drop-users` 响应 `GenericResponseModel {success}` | `{success, error}` | 低（多字段，Panel zod 会 strip） |
| handler 内部 inbound-tag 生命周期（`addXtlsConfigInbound`/`removeUserFromInbound`/`addUserToInbound`） | state + debounce 热插拔 | 无（机制不同、效果等价） |
| `DISABLE_HASHED_SET_CHECK`（按 `internals.hashes` 决定是否重启 core） | `bytes.Equal` + `forceRestart` | 低（热插拔本就避免重启） |
| HTTP 超时（handshake 10s / keepAlive 60s / headers 61s） | `ReadHeaderTimeout` 10s / `IdleTimeout` 60s | 低（近似） |

## 四、sing-box 下无需实现（架构不适用 / 负收益 / 无需求）

| 官方能力 | 原因 |
|---|---|
| `XTLS_API_SOCKET_PATH` | Xray 进程专用，内嵌 sing-box 无此概念 |
| custom core 下载/切换（`core-loader`：Panel 下发 Xray core URL+SHA256 原子切换/回滚） | 内核为内嵌 sing-box，Panel 下发的 core 是 Xray 二进制，无等价物 |
| geodata assets 下载（`geodata.service`：按 Panel 下载 geo 文件 + 空 stub） | sing-box 走 remote rule_set（`.srs`），无需 `geoip.dat`/`geosite.dat` |
| `sockdestroy`（官方断连实现） | 已用 clash_api `DELETE /connections` 等价替代，且免 `CAP_NET_ADMIN`，更优 |
| `nftables-napi`（官方 native 绑定） | 需 CGO/预编译 `.so`，破坏「无 CGO 单静态二进制」定位；`nft` CLI 已覆盖 |
| ASN LMDB（官方 asn-lmdb 模块） | JSON index 已够用（可选加载），LMDB 需 CGO |
| Xray stats 高级字段（如 `sumAvg` 等） | v2ray_api 已覆盖主要计数器；除非 Panel 因缺字段报错再补 |

## 五、已实现（对照 3.4.3）

### 端点

| 控制器 | 端点 | 状态 |
|---|---|---|
| xray | start / stop / healthcheck | ✅ |
| stats | get-users-stats | ✅ v2ray_api QueryStats 聚合（VLESS + SS2022） |
| stats | get-system-stats | ✅（含 xrayInfo + system stats；xrayInfo 空时按官方返回 500） |
| stats | get-inbound/outbound-stats | ✅ |
| stats | get-all-inbounds/outbounds-stats | ✅ |
| stats | get-combined-stats | ✅ |
| stats | get-user-ip-list / get-users-ip-list | ✅ clash_api `/connections`（`userId`=email） |
| stats | get-user-online-status | ✅ clash_api `/connections` |
| stats | get-geocheck | ✅ 内置 geocheck 二进制 |
| handler | add-user / add-users / remove-user / remove-users | ✅ 无感热插拔（VLESS + SS2022，debounce + `UpdateUsers`） |
| handler | drop-users-connections / drop-ips | ✅ clash_api `DELETE /connections/:id`（按 email / sourceIP 匹配；跳过白名单 + 默认忽略 IP） |
| plugin | sync（sharedLists + ingress/egress filter + connection-drop + preStart + postStart） | ✅（`ipList`/`asList` 解析，`ext:` 展开，cleanupSockets，connection-drop 白名单，postStart webhook） |
| plugin | nftables block-ips / unblock-ips / recreate-tables | ✅ `nft` CLI（含 `NFTABLES_ACCEPT_REPLY_TRAFFIC`） |
| internal | get-config | ✅ |

### 其他能力

- **私有 SNI 派生 + `SNI_VERIFICATION`**：`internal/payload/sni.go` 复刻官方
  `decode-servername.util.ts` 的 HKDF-SHA256 派生；`SNI_VERIFICATION=true` 时在 mTLS 握手
  阶段校验客户端 SNI（默认 `false`，与官方一致）。
- **connection-drop（断连）**：clash_api `DELETE /connections/:id` 关闭匹配连接（等价官方
  `sockdestroy` 效果，无需 CAP_NET_ADMIN）；实现 `connectionDrop.whitelistIps` 白名单 +
  `DEFAULT_IGNORED_IPS`（回环/未指定/广播及 CIDR 形式）。
- **单实例锁**：抽象 unix socket `\0rwnode-lock` 防多实例（对齐官方 `acquire-instance-lock`，
  获取失败仅告警不退出）。
- **ASN shared lists**：`internal/asn` 读 `asn-prefixes.json`（remnawave/asn-index JSON 资产），
  需 env `ASN_INDEX_PATH` 指定，未配置时 `asList` 解析降级跳过。
- **在线用户 / 单用户 IP / 最后活动时间**：clash_api `/connections`（fork `rwnode/sing-box-fork`
  内置 `user` 字段补丁，无需 build 时单独打 patch）。
- **preStart cleanupSockets**：`plugin.sync` 缓存 `preStart.cleanupSockets` 配置，在每次
  sing-box (re)start 前清理遗留 unix socket 文件（glob 展开 + socket 类型校验）。
- **postStart webhook**（官方 3.4.2）：`plugin.sync` 缓存 `postStart.webhook` 配置，每次
  `xray/start` 成功后异步发送 `service.core_started` webhook（5 秒超时，失败仅告警），
  payload 与官方 `PostStartService.sendCoreStartedWebhook` 一致（含 `internals.metadata` 透传）。
- **SS2022 无感热插拔**：`UpdatableShadowsocksInbound.UpdateUsersByOptions`（fork 补丁），
  用户增删不重启 listener；SS 用户流量并入 v2ray_api `stats.users` 统计。
- **域名嗅探 (Sniffing)**：入站 `sniffing.enabled` 或域名规则自动映射至 sing-box 1.14 `route.rules` 的 `{"action": "sniff"}`，支持客户端 IP 连接下的 SNI 域名嗅探与分流。

## 六、契约同步记录

- 已对齐官方 **3.4.0**：移除 `get-inbound-users` / `get-inbound-users-count` 两个端点
  （官方 3.4.0 从 handler contract 删除）。
- 已对齐官方 **3.4.1**：`add-user` 在 `prevVlessUuid` 存在（UUID 轮换）时，移除旧用户并
  通过 clash_api 断开其现网连接（官方 3.4.1 addUser 的 `DropConnectionsEvent` 逻辑）。
- 已对齐官方 **3.4.2**：新增 postStart 插件——`plugin.sync` 接受 `postStart` 段并在每次
  core 成功启动后发送 `service.core_started` webhook（`internals.metadata` 随 `/node/xray/start`
  请求透传）；contract 移除 `CipherType.NONE` 枚举值。
- 已对齐官方 **3.4.3**：官方为纯维护版本（`src/` 与 `libs/` contract 零变更，仅 version
  bump + Docker 基础镜像 node:24.20→24.22），无代码同步项；`nodeVersion` 基线切换为 3.4.3。
- **已知差异·空插件推送清理**：官方收到 `plugin == null` 时 `resetPlugins()` 重置全部插件
  状态（含 postStart/preStart/connectionDrop 白名单）并停 Xray；gosingbox 仅重建 nft 表，
  已缓存的 postStart webhook / preStart cleanupSockets / drop 白名单不清空（下次
  `plugin.sync` 才覆盖）。面板删除插件配置后 webhook 会多发一轮，影响极低，暂按近似实现
  保留。
