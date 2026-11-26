# 节点能力扩展 v1

这是本项目在官方 Node contract 3.4.1 外增加的通信扩展。已完成格式判别、能力查询，以及[按入站用户管理和 AnyTLS 内核适配](user-lifecycle.md)；[原生配置入口](native-config.md)现已接通；配套修改版 Panel 已接通 Profile、权限、用户下发和 AnyTLS 订阅业务流程。

## 能力查询

`GET /node/capabilities` 挂载在原 Panel HTTPS 服务，沿用原有 mTLS、私有 SNI（若开启）和 JWT 鉴权，不放到内部 REST socket。只接受 GET，其他方法返回 405。

包含 `with_clash_api,with_v2ray_api` 的构建响应（现有发布标签已包含二者）：

```json
{
  "response": {
    "contractVersion": 1,
    "runtimeCore": "singbox",
    "acceptedConfigFormats": ["xray", "singbox"],
    "managedProtocols": ["vless", "shadowsocks22", "anytls"],
    "hotUserUpdateProtocols": ["vless", "shadowsocks22", "anytls"],
    "anytlsSharedListener": true,
    "staticShadowsocks2022": true,
    "dynamicShadowsocks2022": true
  }
}
```

- `contractVersion` 是这个扩展的版本，与 Node 上报 semver、安装包版本无关。
- `runtimeCore` 是实际数据面内核；`acceptedConfigFormats` 是当前控制器接受的输入格式。运行 sing-box 不等于接受原生 sing-box JSON。
- 协议名称使用 Node handler 的 `type`：`shadowsocks22` 表示已有 SS2022 管理路径，不是 sing-box JSON 中的 `shadowsocks` 类型名。
- 原生 `vless` 支持 TCP、保留 TLS/Reality 和用户 flow；Xray 转译路径仍遵循原有约束。能力列表不证明任意传输或客户端组合均受支持。
- 热更新列表必须是纳管协议列表的子集；它不代表完整 Panel／订阅流程已通过端到端验收。
- `staticShadowsocks2022` 从 3.4.1.21 起声明原生固定密码 SS2022 支持；面板在包含这类辅助入站的全量下发前必须验证它，旧节点缺失此标记时明确拒绝。它不表示托管空用户端口会回退为单密码。
- `dynamicShadowsocks2022` 声明原生托管 SS2022 入站在保留 `"users": []` 时支持 `0 <-> N` 动态切换（0 用户时以服务端单密码 PSK 中转运行，通过增量用户更新新增首个用户时自动晋升为多用户 EIH 模式，移除最后一个用户时降级回单密码 PSK 模式）；缺失该标记的旧版节点（`3.4.1.21`–`.23`）在 `0 <-> N` 模式切换时需由面板触发全量配置下发。

未包含上述任一管理 API 标签的构建仅声明 `["xray"]` 及 VLESS/SS2022，不声明 AnyTLS，拒绝原生启动。

## 启动请求

保留 `POST /node/xray/start`、`xrayConfig` 和官方响应结构，新增可选 `coreType`：

| `coreType` | 当前处理 |
| --- | --- |
| 省略 | 沿用 Xray 输入转译路径 |
| `"xray"` | 同上 |
| `"singbox"` | 具备管理 API 的构建直接准备原生配置并校验、应用；失败返回 `isStarted: false`，不退回 Xray 转译 |
| `null`、空字符串、非字符串、未知值 | HTTP 400，现有无效请求响应 |

`isStarted: false` 描述此次启动请求失败，不表示已停止此前运行的内核。

面板查询能力遇到 404，只能解释为节点未声明扩展：旧 Xray 流程可以继续，原生下发必须拒绝。401/403、TLS、网络、超时、无效响应及未知扩展版本均不得降级为“支持原生”。

## 用户请求

`/node/handler/add-user` 和 `/node/handler/add-users` 在任何用户修改前检查整个请求的协议和入站集合。不支持的协议整批返回业务失败，例如：

```json
{
  "response": {
    "success": false,
    "error": "unsupported user protocol: \"unknown\""
  }
}
```

使用 HTTP 200 和官方业务失败结构。包括混合协议请求：不得先移除旧 UUID 或添加部分用户，再忽略不支持的剩余项。单个与批量 SS2022 密码处理的既有差异保持不变。

AnyTLS handler 用于已经通过原生配置创建的 AnyTLS 入站；未知入站或协议不匹配会明确失败，不会被当作 VLESS 执行。成功响应现在表示用户变更已同步应用；多入站失败恢复、会话撤销和统计验证见[生命周期文档](user-lifecycle.md)。

## 验证

- `internal/controller/capabilities_test.go`：实际 HTTP handler 的能力、格式拒绝、保留已有状态及混合用户请求预检查。
- `internal/server/server_test.go`：实际能力路由经现有 JWT middleware 的缺失、错误及有效 RS256 token 验证。
- `internal/controller/native_integration_test.go`：公开启动 handler、真实代理流量、管理 API 鉴权、热更新、格式切换及实际回滚。
- 完整构建、vet、测试及发布标签 race 测试按项目构建约定执行。

生命周期测试覆盖隔离 TLS/AnyTLS 真实代理流量；另在实际部署中验证了 Panel/mTLS、数据库/队列、生成订阅的客户端连接及重启恢复。使用原生能力时仍需配套修改版 Panel。
