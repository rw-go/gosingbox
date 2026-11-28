# 未实现 / 降级功能

本文档记录 `gosingbox`（Go 版节点，sing-box 数据面）相对官方 remnawave/node 的功能
差距与暂不实现项。对照基准为**官方 3.4.6** 的 Panel-facing contract。

分三类：**未实现**、**类似实现**、**sing-box 下无需实现**。

## 原生 sing-box 下发与 AnyTLS —— 已实现范围

- 节点原生 `coreType=singbox` 启动、管理 API 注入、失败回滚和配置查询已接通；具备管理 API 的构建声明原生输入和 AnyTLS。
- 已完成按入站用户管理、AnyTLS 热更新、鉴权并发安全和旧会话撤销；公开 handler 的真实 TLS/代理测试及 race 回归通过。
- 配套修改版 Panel 的数据库/Profile、权限、用户同步、前端与订阅已接通，并通过部署与生产数据副本联调。原生能力需要配套 Panel；长期高负载及任意客户端组合不在已验证范围。
- 协议与失败语义见 [节点能力扩展 v1](docs/node-capabilities.md)、[原生配置入口](docs/native-config.md) 和 [用户生命周期](docs/user-lifecycle.md)。

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

本节点纳管协议为 **TCP VLESS**（原生保留 TLS/Reality 和 flow）、**SS2022 AES-128/256-GCM 多用户**、**普通 TLS 的 AnyTLS**。Xray 输入沿用原有转译限制。

VMess / Trojan / 老式 SS / Hysteria / Hysteria2 及 ws·grpc·xhttp 等传输当前不在本项目纳管范围，原生路径明确拒绝。仅允许回环 `direct` 辅助入站，非空 endpoints/services 暂不支持。这是本项目管理范围限制，不代表上游 sing-box 不支持这些能力。

## 三、实现与行为差异

| 官方 | gosingbox | 影响 |
|---|---|---|
| nftables `NFTABLES_LOGGING`（默认 true，规则带 log 前缀） | 无 | 低（仅审计日志） |
| 请求体上限 `bodyParser 1000mb` | 64MB | 低（xrayConfig 远小于 64MB） |
| 响应 `compression()` + `helmet()` | 无 | 低（非 contract） |
| zod 全量 schema 校验（UUID/字段类型/端口范围） | 手动 json decode，校验较松 | 中（畸形请求可能到 sing-box 才报错） |
| `drop-ips`/`drop-users` 响应 `GenericResponseModel {success}` | `{success, error}` | 低（多字段，Panel zod 会 strip） |
| handler 内部 inbound-tag 生命周期（`addXtlsConfigInbound`/`removeUserFromInbound`/`addUserToInbound`） | 按 tag 与稳定用户 ID 保存授权，串行同步热更新 | 单／批量替换授权集合；多入站应用非瞬时原子，失败恢复详见用户生命周期文档 |
| `DISABLE_HASHED_SET_CHECK`（按 `internals.hashes` 决定是否重启 core） | 比较输入格式及有效基础配置；用户变化热更新，`forceRestart` 强制重建 | 低（热插拔本就避免重启） |
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
| Xray `routing.script`（官方 3.4.5 保留项） | Xray 专属脚本路由扩展，sing-box 1.14 路由引擎无等价字段 |

## 五、已实现（对照 3.4.6）

### 端点

| 控制器 | 端点 | 状态 |
|---|---|---|
| xray | start / stop / healthcheck | ✅ |
| stats | get-users-stats | ✅ v2ray_api QueryStats 聚合（VLESS + SS2022 + AnyTLS） |
| stats | get-system-stats | ✅（含 xrayInfo + system stats；xrayInfo 空时按官方返回 500） |
| stats | get-inbound/outbound-stats | ✅ |
| stats | get-all-inbounds/outbounds-stats | ✅ |
| stats | get-combined-stats | ✅ |
| stats | get-user-ip-list / get-users-ip-list | ✅ clash_api `/connections`（`userId`=email） |
| stats | get-user-online-status | ✅ clash_api `/connections` |
| stats | get-geocheck | ✅ 内置 geocheck 二进制 |
| handler | add-user / add-users / remove-user / remove-users | ✅ 同步热插拔（VLESS + SS2022 + AnyTLS，按入站管理） |
| handler | drop-users-connections / drop-ips | ✅ clash_api `DELETE /connections/:id`（按 email / sourceIP 匹配；跳过白名单 + 默认忽略 IP） |
| plugin | sync（sharedLists + ingress/egress filter + connection-drop + preStart + postStart） | ✅（`ipList`/`asList` 解析，`ext:` 展开，cleanupSockets，connection-drop 白名单，postStart webhook） |
| plugin | nftables block-ips / unblock-ips / recreate-tables | ✅ `nft` CLI（含 `NFTABLES_TABLE_NAME`、`NFTABLES_ACCEPT_REPLY_TRAFFIC`） |
| internal | get-config | ✅ |

### 其他能力

- **私有 SNI 派生 + `SNI_VERIFICATION`**：`internal/payload/sni.go` 复刻官方
  `decode-servername.util.ts` 的 HKDF-SHA256 派生；`SNI_VERIFICATION=true` 时在 mTLS 握手
  阶段校验客户端 SNI（默认 `false`，与官方一致）。
- **connection-drop（断连）**：clash_api `DELETE /connections/:id` 关闭匹配连接（等价官方
  `sockdestroy` 效果，无需 CAP_NET_ADMIN）；实现 `connectionDrop.whitelistIps` 白名单 +
  `DEFAULT_IGNORED_IPS`（回环/未指定/广播及 CIDR 形式）。
- **单实例锁**：抽象 unix socket `\0rwnode-lock` 防误启动重复实例破坏现有 nftables/监听端口
  （默认获取失败在初始化 nftables 前直接报错退出；显式设置 `SUPPRESS_DUPLICATE_INSTANCE_WARNING=true`
  时放行锁冲突，便于配合独立 `NFTABLES_TABLE_NAME` 同机多实例部署）。
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
- 已对齐官方 **3.4.4–3.4.6**：同步官方 3.4.5（`103fb8fc`）新增的 `NFTABLES_TABLE_NAME`
  （默认 `remnanode`，空值/纯空白回退默认，严格校验 `^[A-Za-z_][A-Za-z0-9_-]{0,62}$` 防止
  `nft` 参数/脚本注入）与 `SUPPRESS_DUPLICATE_INSTANCE_WARNING`；3.4.5 的 Xray `routing.script`
  保留项属 Xray 专属能力（记录于上表），3.4.4 与 3.4.6 均为依赖/内核维护版本，无额外 contract 变更。
- **已知差异·空插件推送清理**：官方收到 `plugin == null` 时 `resetPlugins()` 重置全部插件
  状态（含 postStart/preStart/connectionDrop 白名单）并停 Xray；gosingbox 仅重建 nft 表，
  已缓存的 postStart webhook / preStart cleanupSockets / drop 白名单不清空（下次
  `plugin.sync` 才覆盖）。面板删除插件配置后 webhook 会多发一轮，影响极低，暂按近似实现
  保留。
