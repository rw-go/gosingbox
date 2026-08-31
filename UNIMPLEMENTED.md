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

## 二、协议能力差异（数据面固有）

sing-box 数据面仅支持 **VLESS + Reality + xtls-rprx-vision** 与
**Shadowsocks 2022 (`2022-blake3-aes-256-gcm`)**。官方 Xray 数据面额外支持的
VMess / Trojan / 老式 SS / ws·grpc·xhttp 等传输在本项目**不支持**（by design）。

## 三、已实现的官方功能（对照 3.4.0）

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
| handler | drop-users-connections / drop-ips | ✅ clash_api `DELETE /connections/:id`（按 email / sourceIP 匹配） |
| plugin | sync（sharedLists + ingress/egress filter + preStart） | ✅（`ipList`/`asList` 解析，`ext:` 展开，cleanupSockets） |
| plugin | nftables block-ips / unblock-ips / recreate-tables | ✅ `nft` CLI |
| internal | get-config | ✅ |

其他已实现能力：
- **ASN shared lists**：`internal/asn` 读 `asn-prefixes.json`（remnawave/asn-index JSON 资产），
  需 env `ASN_INDEX_PATH` 指定，未配置时 `asList` 解析降级跳过。
- **在线用户 / 单用户 IP / 最后活动时间**：clash_api `/connections`（fork `rwnode/sing-box-fork`
  内置 `user` 字段补丁，无需 build 时单独打 patch）。
- **connection-drop（断连）**：`drop-ips` / `drop-users-connections` 通过 clash_api
  `DELETE /connections/:id` 关闭匹配连接（等价官方 `sockdestroy` 效果，无需 CAP_NET_ADMIN）。
- **preStart cleanupSockets**：`plugin.sync` 缓存 `preStart.cleanupSockets` 配置，在每次
  sing-box (re)start 前清理遗留 unix socket 文件（glob 展开 + socket 类型校验）。
- **SS2022 无感热插拔**：`UpdatableShadowsocksInbound.UpdateUsersByOptions`（fork 补丁），
  用户增删不重启 listener；SS 用户流量并入 v2ray_api `stats.users` 统计。

## 四、契约同步记录

- 已对齐官方 **3.4.0**：移除 `get-inbound-users` / `get-inbound-users-count` 两个端点
  （官方 3.4.0 从 handler contract 删除）。