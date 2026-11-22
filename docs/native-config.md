# 原生 sing-box 配置入口

节点现在支持显式的 `coreType: "singbox"`，直接准备并加载原生 JSON，保留 Xray 配置转译路径。仍使用 `POST /node/xray/start` 和 `xrayConfig` 字段；它们是兼容字段名。配套修改版 Panel 已接通 Profile、权限、用户下发和订阅；官方 Panel 仍需相应扩展才能使用原生模式。

## 请求与构建

发布构建必须包含 `with_clash_api,with_v2ray_api`，否则能力端点只声明 Xray 输入，拒绝原生启动。现有打包使用的完整标签是 `with_clash_api,with_v2ray_api,with_utls,with_acme,with_quic`。这里的能力声明针对当前编译出的节点，与安装包版本无关。

以下是请求结构示例。证书路径位于节点本机，UUID 和域名是示例值；直接复制不能替代证书配置和面板鉴权。

```json
{
  "coreType": "singbox",
  "internals": { "forceRestart": false },
  "xrayConfig": {
    "log": { "level": "warn" },
    "inbounds": [{
      "type": "anytls",
      "tag": "anytls-in",
      "listen": "::",
      "listen_port": 443,
      "users": [{
        "name": "1001",
        "password": "11111111-1111-4111-8111-111111111111"
      }],
      "tls": {
        "enabled": true,
        "server_name": "node.example.com",
        "certificate_path": "/etc/gosingbox/tls/fullchain.pem",
        "key_path": "/etc/gosingbox/tls/privkey.pem"
      }
    }],
    "outbounds": [{ "type": "direct", "tag": "direct" }],
    "route": { "final": "direct" }
  }
}
```

省略 `coreType` 或指定 `xray` 进入原有转译器；不会从 JSON 内容猜测格式。未知值、空字符串、显式 null 返回 HTTP 400；有效格式中的无效配置返回官方启动失败外壳。新面板在原生下发前必须验证能力，旧节点的 404 不构成原生支持证明。

## 管理范围

| 原生入站类型 | 规则 |
| --- | --- |
| `anytls` | 普通 TLS；用户 `name` 为稳定 ID，`password` 为当前凭据；配套面板统一注入用户的 `vlessUuid`。拒绝 Reality。 |
| `vless` | TCP，无额外 transport 包装；保留 TLS/Reality 参数及每个用户的 flow。空 flow 保持为空。 |
| `shadowsocks` | SS2022 AES-128/256-GCM；与 Xray 模式统一密码规则——0 授权用户时（无论省略 `users`、`users: []` 或附带 `managed: true`）运行单密码 PSK 中转模式，授权用户数 `> 0` 时运行多用户 EIH 模式。检查服务端与用户密钥。 |
| `direct` | 辅助入站，必须显式绑定回环 IP，无 users，不参与用户同步。 |

必须至少有一个主入站（`anytls`、`vless` 或 `shadowsocks`，不能仅有辅助 `direct` 入站），所有入站 tag 非空且唯一。其他入站以及非空 `endpoints`、`services` 当前明确拒绝，不能绕过用户管理边界。VLESS/AnyTLS 省略 `users` 等同空列表；SS2022 在 0 用户时统一剥离 `users` 与 `managed` 以运行单密码 PSK 模式，在有用户时携带 `users` 并移除 `managed` 以运行多用户 EIH 模式。

原生 `coreType: "singbox"` 与旧 Xray 转译路径（`coreType: "xray"` 或省略）遵循完全一致的 SS2022 动态模式切换语义：当 SS2022 入站绑定/授权用户数为 0 时，始终仅使用入站 `password` 进行服务端间单密码 PSK 中转，计入节点入站流量（`v2ray_api.stats.inbounds`）而不计入任何个人用户流量；当通过全量 `/node/xray/start` 或增量 `add-user(s)` 下发授权用户（`> 0` 用户）时，自动切换为多用户 EIH（`<serverPSK>:<userKey>`）模式并拒绝裸服务端 PSK；当最后一个授权用户通过全量推送或增量 `remove-user(s)` 撤销（回到 0 用户）时，立即关闭原 EIH 连接并恢复单密码 PSK 中转模式。

所有配置仍须通过锁定内嵌版本的实际 option schema 和实例启动校验。接受 VLESS/Reality 配置不等于已验收其所有客户端组合；真实流量覆盖普通 AnyTLS、空 flow 的 TCP VLESS 和 SS2022；后续部署联调另已验证实际订阅生成的原生 VLESS Reality Vision，以及既有 Xray Reality 转译路径。

## 保留字段和管理接口

DNS、路由、出站、日志、有效原生字段及 `experimental` 其他配置原样保留。原生输入不自动注入 Xray 转译器的 sniff 规则、Geo 规则改写或监听覆盖；需要嗅探时在原生 route 中显式配置。

节点覆盖以下运行时管理字段，其他同级字段保留：

- `experimental.v2ray_api.listen`：使用节点的 `SINGBOX_STATS_ADDRESS`。
- `experimental.v2ray_api.stats.enabled/users/inbounds/outbounds`：开启计数，用户列表来自当前各纳管入站；`inbounds` 合并纳管 tag、0 用户单密码 SS2022 入站与配置原有列表；`outbounds` 自动收集非 `block`/`dns` 出站（含省略出站时的默认 `direct` 及无 tag 显式出站的序号命名 `"0"`, `"1"`, ...）并合并配置原有列表。
- `experimental.clash_api.external_controller/secret`：使用节点的 `SINGBOX_CLASH_ADDRESS` 和每个 Engine 实例生成的随机密钥，同时剥离 `external_ui` 等外部下载/静态目录项；在线查询及连接关闭自动带 Bearer 鉴权。
- 本地路径边界：拒绝 `log.output` 与 `tls.acme.data_directory`；`experimental.cache_file.path` 仅允许 `/var/lib/gosingbox`（及 `SINGBOX_GEO_DIR`）下的规范 `.db` 文件；`tls.certificate_path` / `tls.key_path` 仅允许位于 `/etc/gosingbox`、`/var/lib/gosingbox`、`/etc/ssl`、`/etc/letsencrypt`、`/etc/pki`、`/tls` 下的常规文件（允许目录树内部如 Let's Encrypt `live -> archive` 软链，拒绝越界软链）。

原生模式下两个管理地址必须是明确的回环 IP 和非零端口，不能使用公开地址或主机名；它们不能相同。配置中提供的监听地址或 secret 按上述规则覆盖，类型错误明确失败。gRPC 统计接口没有新增鉴权，依靠回环限制；Clash 同时具有回环限制和随机密钥。密钥在同一节点进程的重建和回滚中保持不变，不写入保存的输入配置。

原生直出在实际拨号时保护统计和 Clash 的 TCP 端口。目标是回环地址、未指定地址，或域名任何一个候选地址属于以上范围时，节点会拒绝该连接。公网地址的同号端口仍可用。节点管理客户端继续通过配置的回环地址读取统计和管理连接。

独立 AnyTLS 入站和共享 SNI 入站在一个进程内共用 128 个待认证名额。TLS 握手完成后，读取首个 AnyTLS 认证记录的时限为 10 秒。完成认证即归还名额，已建立会话可继续使用。

## 应用、回滚及配置查询

先检查原生结构、纳管协议、用户身份、凭据和实际内核 schema，再允许替换运行中的实例。普通 TLS 的内联 PEM／本地文件证书及私钥会提前校验；空内联列表遵循内核规则回退到文件路径。Reality 和证书 provider/ACME 的进一步验证交给内核；本阶段没有测试公网证书签发。

与用户更新共用串行控制锁。相同格式且只改变用户的全量推送走热更新，原始请求即使与历史记录相同也会恢复其权威用户集合。基础配置或格式变化、`forceRestart=true` 则重建实例。

运行期绑定端口、资源加载等失败后尝试恢复最近成功配置，其中包含已成功应用的增量用户变更。重建与回滚会中断已有连接；回滚不能恢复原 TCP 会话。若恢复也失败，错误明确包含 `core is offline`，健康检查报告离线，后续用户增量失败，必须用有效全量配置恢复。保留的配置快照表示最近成功状态，不代表内核仍在线。

`GET /internal/get-config` 继续受原内部接口 token 鉴权，响应保持 JSON 配置本体，增加 `X-Config-Format: xray|singbox`。Xray 返回原有保存内容；原生返回保存的原生字段加当前用户快照，SS2022 处于 0 用户单密码模式时会清理保存配置中的旧用户（原配置含 `users` 时置为 `[]`，省略 `users` 时保持省略）并移除 `managed` 标记。不会返回节点注入的管理密钥；这是可重新准备的配置视图，并非包含运行时注入值的完整 dump。此接口包含用户凭据和可能的内联私钥，仍只面向有权访问内部接口的管理者。

测试见 `internal/nativeconfig/prepare_test.go` 和 `internal/controller/native_integration_test.go`；用户权限与会话撤销语义见[用户生命周期](user-lifecycle.md)。
