# 未实现 / 降级功能

本文档记录 `gosn`（Go 版节点，sing-box 数据面）相对官方 Node 版的功能差距与
暂不实现项。维护原则见根目录 `AGENTS.md`：三种后端一起维护但不强求功能对齐。

## 一、数据面能力缺口（sing-box 内核限制）

### 1. torrent-blocker 实时检测 —— 搁置
- **现状**：`/node/plugin/torrent-blocker/collect` 恒返回空报告列表。
- **原因**：官方的 BT 检测靠 **Xray 内核** sniffing + webhook（`xray-webhook.handler`）
  推送命中事件，nftables 只负责最终封 IP。sing-box 没有等价能力。
- **实现路径**（均不划算）：
  - nftables raw payload 匹配明文 BT 握手（只能抓非加密 BT，会漏 MSE/PE）；
  - 给 sing-box 打 DPI 补丁，等价 Xray webhook（维护成本随内核升级持续）。
- **结论**：个人自用、低频场景不启用；如需启用再按上面任一方案补。

### 2. connection drop 断连 —— 空实现
- **现状**：`/node/handler/drop-users-connections`、`/node/handler/drop-ips` 恒返回
  `{success:true}` 但**不实际断开连接**。
- **原因**：官方靠 `sockdestroy`（需 `CAP_NET_ADMIN`，直接操作内核 socket）实现。
- **可选路径**：clash_api `DELETE /connections/:id`（已内嵌启用 clash_api），或接入
  `sockdestroy` 同层能力。**低优先级**。

### 3. per-user 无感热插拔（无重启）—— 已实现
- **现状**：用户增删已改为「debounce 5s → `UpdatableInbound.UpdateUsers()`」热插拔，
  不再重启监听器。sing-box 已由 spawn 子进程改为**内嵌库**（见 `internal/singbox/engine.go`），
  依赖 fork `rwnode/sing-box-fork`（tag `v1.13.20-updatable.1`，含 `UpdatableInbound` 补丁）。
- **已知注意**：热插拔当前只覆盖 VLESS；Shadowsocks 2022 的用户变更会走全量 reload
  （`ApplyConfig`）。内嵌后 `UpdatableShadowsocksInbound` 补丁已就位，可按需接入。

## 二、官方对等但本项目不复刻

### 4. ACME / 域名证书自动签发 —— 不需要
- 官方 Node 版**也没有**该能力：节点证书全部来自面板 `SECRET_KEY` 下发的 mTLS
  证书，入站仅为 VLESS Reality / Shadowsocks 2022，均不依赖域名证书。
- sing-box 虽编译了 `with_acme`（certificate provider），但未在 transpiler 暴露，
  个人 Reality/SS 场景用不上。

## 三、已实现能力（对照）

- 在线用户 / 单用户 IP / 最后活动时间：已通过 clash_api `/connections` 实现（需
  build 脚本内置的 `singbox-clashapi-user.patch`）。
- **ASN shared lists**：已通过 `internal/asn`（读 `asn-prefixes.json`）实现；需 env
  `ASN_INDEX_PATH` 指向官方 `asn-index` JSON 资产，未配置时 `asList` 解析降级。
- geo 检测（geocheck）：已通过内置 `geocheck` 二进制实现。
- ingress / egress filter（IP + 端口）：已通过 `nft` CLI 实现。