# 3.4.1.19 — 原生 sing-box 与 AnyTLS

发布渠道：Docker Hub `rwnode/gosingbox`、Bitbucket `rwnode/rwnode-gosingbox`。GitHub 本次不更新。Linux amd64；内嵌 sing-box 1.14.3。

## 版本标识

本版本按工作区四段 `3.4.1.N` 命名规范续发为 `3.4.1.19`，Panel 上报纯 semver `3.4.1`。仓库历史上还发布过 `3.4.3.1`；本版本沿用其源码并增加原生集成，不删除该版本已有的 postStart 等功能。`latest.txt` 和 Docker `latest` 指向本次发布，不能仅按四段字符串大小判断新旧。

## 新增能力

- 节点能力查询 `/node/capabilities`，显式区分 Xray 转译与原生 sing-box 输入。
- 原生 AnyTLS（普通 TLS）、TCP VLESS（TLS/Reality/Vision）与 SS2022 AES-128/256-GCM 多用户配置。
- 按入站 tag 隔离用户与权限，支持 AnyTLS 用户热更新、撤权时关闭会话、流量统计及在线 IP 查询。
- 管理 API 采用回环地址与随机 Clash 密钥；非法配置和不支持的能力明确失败，配置更新失败支持回滚。
- 内置经并发与真实连接测试的 AnyTLS 依赖补丁；构建包含本地 `third_party/sing-anytls`。

## 配合面板与升级

原生模式需要支持此契约扩展的修改版 Panel。既有官方 Xray 格式请求继续走原有转译路径；不会因此把此前不支持的 Xray 入站转换为可用协议。不要把原生 Profile 绑定到尚未升级的旧节点。

Docker 使用 `rwnode/gosingbox:3.4.1.19`（固定版本）或更新后的 `latest`。已有 Docker 安装保留 SECRET_KEY、环境文件、挂载目录与网络设置，仅替换镜像并重建该节点容器。升级节点进程会短暂中断该节点现有连接。

裸机包通过 Bitbucket `release` 分支的 `latest.txt` 解析版本；同目录提供 tar.gz 和 SHA256。安装脚本路径及配置格式保持原样。

## 已验证范围

实现阶段已验证配套 Panel 的原生下发、权限、用户增删/禁用恢复、AnyTLS 实际连接、流量、在线 IP、重启恢复，以及 Xray 格式 Reality 和原生 VLESS Reality Vision 连接。原生输入不是对全部 sing-box 功能的无限制兼容声明；具体协议限制见 `docs/native-config.md` 与 `UNIMPLEMENTED.md`。

TLS 证书由部署者准备。原客户端订阅模板的版本兼容需独立处理。共享固定账号、单 443 多模式路由及其他节点的自动升级不在本次节点发布范围。
