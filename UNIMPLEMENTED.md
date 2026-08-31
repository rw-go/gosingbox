# 未实现 / 降级功能

本文档记录 `gosingbox`（Go 版节点，sing-box 数据面）相对官方 remnawave/node 的功能
差距与暂不实现项。对照基准为**官方 3.4.0** 的 Panel-facing contract。

## 一、未实现的官方功能

### 1. torrent-blocker 实时检测 —— 搁置
- **现状**：`/node/plugin/torrent-blocker/collect` 恒返回空报告；`/internal/webhook` 为 no-op。
- **原因**：官方 BT 检测靠 **Xray 内核** sniffing + webhook 推送命中事件，nftables 只负责
  最终封 IP；sing-box 无等价能力。
- **实现路径**（均不划算）：nftables raw payload 匹配明文 BT 握手（漏 MSE/PE 加密）；或
  给 sing-box 打 DPI 补丁等价 webhook（维护随内核升级持续）。
- **结论**：个人自用不启用；如需再按上述任一方案补。

### 2. connection-drop 断连 —— 空实现
- **现状**：`/node/handler/drop-users-connections`、`/node/handler/drop-ips` 恒返回
  `{success:true}` 但不实际断开连接。
- **原因**：官方靠 `sockdestroy`（需 `CAP_NET_ADMIN`，直接操作内核 socket）。
- **可选路径**：clash_api `DELETE /connections/:id`（已内嵌启用 clash_api）；或接入
  `sockdestroy` 同层能力。**低优先级**。

### 3. preStart plugin（socket 清理）—— 未实现
- **现状**：`plugin.sync` 中 `preStart`（`cleanupSockets`）字段被忽略。
- **原因**：官方在节点启动前清理遗留 unix socket 文件；sing-box 内嵌模式下无此需求。
- **结论**：可忽略，必要时按需补。

### 4. Shadowsocks 2022 无感热插拔 —— 未接入
- **现状**：用户无感热插拔仅覆盖 **VLESS**（`UpdatableInbound[option.VLESSUser]`）；
  SS2022 用户变更走全量 reload（`ApplyConfig`，短暂断连）。
- fork 中 `UpdatableShadowsocksInbound` 补丁已就位，可按需接入 `UpdateUsersByOptions`。

## 二、协议能力差异（数据面固有）

sing-box 数据面仅支持 **VLESS + Reality + xtls-rprx-vision** 与
**Shadowsocks 2022 (`2022-blake3-aes-256-gcm`)**。官方 Xray 数据面额外支持的
VMess / Trojan / 老式 SS / ws·grpc·xhttp 等传输在本项目**不支持**（by design）。

## 三、已实现的官方功能（对照 3.4.0）

| 控制器 | 端点 | 状态 |
|---|---|---|
| xray | start / stop / healthcheck | ✅ |
| stats | get-users-stats | ✅ v2ray_api QueryStats 聚合 |
| stats | get-system-stats | ✅（含 xrayInfo + system stats；xrayInfo 空时按官方返回 500） |
| stats | get-inbound/outbound-stats | ✅ |
| stats | get-all-inbounds/outbounds-stats | ✅ |
| stats | get-combined-stats | ✅ |
| stats | get-user-ip-list / get-users-ip-list | ✅ clash_api `/connections` |
| stats | get-user-online-status | ✅ clash_api `/connections` |
| stats | get-geocheck | ✅ 内置 geocheck 二进制 |
| handler | add-user / add-users / remove-user / remove-users | ✅ 无感热插拔（debounce + `UpdateUsers`） |
| plugin | sync（sharedLists + ingress/egress filter） | ✅（`ipList`/`asList` 解析，`ext:` 展开） |
| plugin | nftables block-ips / unblock-ips / recreate-tables | ✅ `nft` CLI |
| internal | get-config | ✅ |

其他已实现能力：
- **ASN shared lists**：`internal/asn` 读 `asn-prefixes.json`（remnawave/asn-index JSON 资产），
  需 env `ASN_INDEX_PATH` 指定，未配置时 `asList` 解析降级跳过。
- **在线用户 / 单用户 IP / 最后活动时间**：clash_api `/connections`（fork `rwnode/sing-box-fork`
  内置 `user` 字段补丁，无需 build 时单独打 patch）。

## 四、契约同步记录

- 已对齐官方 **3.4.0**：移除 `get-inbound-users` / `get-inbound-users-count` 两个端点
  （官方 3.4.0 从 handler contract 删除）。