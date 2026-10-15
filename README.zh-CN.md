# Filestash Auth OIDC

[English](README.md) | [简体中文](README.zh-CN.md)

[![Go checks](https://github.com/eaopen/filestash-auth-oidc/actions/workflows/test.yml/badge.svg)](https://github.com/eaopen/filestash-auth-oidc/actions/workflows/test.yml)

面向 [Filestash CE](https://github.com/mickael-kerjean/filestash) 的社区 OpenID Connect 认证中间件。

适用于需要标准 OIDC 认证的自托管 Filestash，无需修改 Filestash 核心。Authentik 是主要测试的身份提供方，实现保持提供方中立。

> 本项目由社区独立维护，与 Filestash 无隶属关系，不复制、解锁或依赖 Filestash Enterprise 认证代码，使用公开的 `IAuthentication` 插件接口。

## 状态

早期社区实现，最初面向 2026-09-29 的 Filestash CE `master` 和采用标准 OIDC Authorization Code Flow 的 Authentik。

已实现：

- OIDC discovery 与 Authorization Code Flow
- PKCE S256、加密安全随机 `state`、OIDC `nonce`
- 一次性、有过期时间的 state 校验
- 经 `go-oidc` 校验 ID token 签名、issuer、audience 和有效期
- 可选 UserInfo 声明合并，并校验 subject 一致性
- 可配置用户名与群组声明名
- 向 Filestash 暴露 `sub`、`user`、`username`、`groups`、`groups_json`、`raw_claims` 及扁平化声明

按设计不包含：

- SAML / LDAP
- refresh-token 持久化
- SCIM / 用户预配
- Filestash 授权 / ACL 逻辑
- 多实例 Filestash 的分布式 state 存储

## 架构

```text
浏览器
   |
   v
Filestash CE
   |
   | plg_authenticate_oidc
   v
OIDC 提供方（Authentik / Keycloak / Dex / ...）
   |
   | 已验证声明
   v
Filestash 属性映射
   |
   v
SMB / SFTP / WebDAV / S3 / ...
```

插件只负责确定**用户身份**。文件授权应由 Filestash 属性映射和／或存储后端执行。

## Filestash 集成

Filestash 认证中间件在编译时注册。将模块加入 Filestash 构建，并在 `server/plugin/index.go` 中匿名导入：

```bash
go get github.com/eaopen/filestash-auth-oidc@main
```

在以下文件的 import 列表加入：

```go
_ "github.com/eaopen/filestash-auth-oidc"
```

```text
server/plugin/index.go
```

然后正常重新构建 Filestash。

Filestash 源码构建在编译前生成 `server/pkg/env/constants_generated.go`。在 Filestash 检出目录运行 `go generate ./server/pkg/env`（或其正常构建命令），再构建集成后的二进制。

本仓 Dockerfile 获取固定版本的 Filestash 源码并将插件编译进服务端，适用于本地容器构建：

```bash
docker build -t filestash-auth-oidc:local .
```

该镜像用于开发，生产使用前须按 digest 固定。

插件注册名为：

```text
oidc
```

无需修改 Filestash 会话处理器或认证核心。

## 配置

在 Filestash 身份提供方中配置：

| 字段 | 示例 | 说明 |
| --- | --- | --- |
| `issuer` | `https://auth.example.com/application/o/filestash/` | 精确 OIDC issuer，不要填写 discovery URL。 |
| `client_id` | `...` | 机密 OIDC 客户端 ID。 |
| `client_secret` | `...` | 机密 OIDC 客户端密钥。 |
| `redirect_uri` | `https://files.example.com/api/session/auth/` | 必须与 IdP 注册值完全一致；除 localhost 外要求 HTTPS。 |
| `scopes` | `openid profile email` | 空格或逗号分隔，始终包含 `openid`。 |
| `username_claim` | `preferred_username` | 暴露为 `.user` 和 `.username`，缺省回退至 `sub`。 |
| `groups_claim` | `groups` | 暴露为逗号分隔的 `.groups` 及 JSON 格式的 `.groups_json`。 |
| `userinfo` | `false` | 可选额外 UserInfo 请求，优先采用 ID token 声明。 |

属性映射可使用：

```text
{{ .user }}
{{ .email }}
{{ .groups }}
{{ .sub }}
```

## 安全属性

- `state` 为随机、短期、一次性值，保存在服务端。
- PKCE 使用 S256。
- 每次登录生成 `nonce`，并与已验证 ID token 核对。
- 使用 `github.com/coreos/go-oidc/v3` 和提供方 discovery 返回的 JWKS 验证 ID token。
- `go-oidc` 执行 issuer 和 audience 校验。
- 启用 UserInfo 时，其 `sub` 必须与 ID token 一致。
- access token、refresh token 和 ID token 不暴露给 Filestash 属性映射。
- 除 localhost 开发环境外，重定向 URI 必须使用 HTTPS。
- 选择 OIDC 时阻止通过 `POST /api/session` 直接进行存储登录。
- 既有 Filestash 会话（含 bearer token）最多 15 分钟过期；IdP 移除群组成员后，至迟在该窗口结束后的下一次登录生效。只读参考配置应禁用分享链接。

### 多实例说明

待完成 OIDC 事务在内存中保存 10 分钟。部署多个 Filestash 应用实例时，认证期间使用粘性路由，或将 state 存储扩展到共享后端。常见单实例部署不引入 Redis。

## Authentik

参见 [Authentik 配置指南（英文，中文译文待补充）](docs/AUTHENTIK.md)。

## 兼容性

首版实现基于 Filestash `master` 的公开 `IAuthentication` API，对应提交 `2ea4bae7f66b46ea51c7e81506afc7c6e0b75364`（2026-09-29）。

本文记录的 Filestash 构建使用 Go 1.26，CI 同样采用 Go 1.26。

## 许可

本仓原创代码采用 MIT 许可证（`MIT`）。Filestash CE 独立采用 AGPL-3.0。插件编译进 Filestash 二进制后，组合程序的分发与网络使用必须遵守 Filestash 的 AGPL 条款。本仓不改变 Filestash 或任何第三方依赖的许可证。

Filestash 是独立项目，保留自身许可证与商标。
