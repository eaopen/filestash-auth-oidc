# Filestash Auth OIDC

[![Go checks](https://github.com/eaopen/filestash-auth-oidc/actions/workflows/test.yml/badge.svg)](https://github.com/eaopen/filestash-auth-oidc/actions/workflows/test.yml)

Community OpenID Connect authentication middleware for [Filestash CE](https://github.com/mickael-kerjean/filestash).

The plugin is designed for self-hosted Filestash deployments that need standards-based OIDC authentication without modifying Filestash core. Authentik is the primary tested identity provider, while the implementation intentionally stays provider-neutral.

> This is an independent community project. It is not affiliated with Filestash and does not copy, unlock, or depend on Filestash Enterprise authentication code. It uses Filestash's public `IAuthentication` plugin interface.

## Status

Early community implementation. The initial target is Filestash CE `master` as of 2026-09-29 and Authentik using standard OIDC Authorization Code Flow.

Implemented:

- OIDC discovery
- Authorization Code Flow
- PKCE S256
- cryptographically random `state`
- OIDC `nonce`
- one-time, expiring state validation
- ID token signature / issuer / audience / expiry verification through `go-oidc`
- optional UserInfo claim merge with subject consistency check
- configurable username and groups claim names
- Filestash attribute exposure: `sub`, `user`, `username`, `groups`, `groups_json`, `raw_claims`, plus flattened claims

Not implemented by design:

- SAML / LDAP
- refresh-token persistence
- SCIM / user provisioning
- Filestash authorization / ACL logic
- distributed state storage for multi-instance Filestash

## Architecture

```text
Browser
   |
   v
Filestash CE
   |
   | plg_authenticate_oidc
   v
OIDC Provider (Authentik / Keycloak / Dex / ...)
   |
   | verified claims
   v
Filestash attribute mapping
   |
   v
SMB / SFTP / WebDAV / S3 / ...
```

This plugin only answers **who the user is**. File authorization should stay in Filestash attribute mapping and/or the storage backend.

## Filestash integration

Filestash authentication middleware is registered at compile time. Add this module to the Filestash build and blank-import it from `server/plugin/index.go`.

```bash
go get github.com/eaopen/filestash-auth-oidc@main
```

Add:

```go
_ "github.com/eaopen/filestash-auth-oidc"
```

to the import list in:

```text
server/plugin/index.go
```

Then rebuild Filestash normally.

Filestash's source build generates `server/pkg/env/constants_generated.go` before
compilation. Run `go generate ./server/pkg/env` in the Filestash checkout (or use
its normal build command) before building the combined binary.

The plugin registers itself as:

```text
oidc
```

No changes are required to Filestash session handlers or authentication core.

## Configuration

Configure the Filestash identity provider with:

| Field | Example | Notes |
|---|---|---|
| `issuer` | `https://auth.example.com/application/o/filestash/` | Exact OIDC issuer. Do not paste the discovery URL. |
| `client_id` | `...` | Confidential OIDC client ID. |
| `client_secret` | `...` | Confidential OIDC client secret. |
| `redirect_uri` | `https://files.example.com/api/session/auth/` | Must exactly match the IdP registration. HTTPS required except localhost. |
| `scopes` | `openid profile email` | Space/comma separated. `openid` is always included. |
| `username_claim` | `preferred_username` | Exposed as `.user` and `.username`; falls back to `sub`. |
| `groups_claim` | `groups` | Exposed as comma-separated `.groups` and JSON `.groups_json`. |
| `userinfo` | `false` | Optional extra UserInfo request. ID-token claims are preferred. |

Example attribute mapping can use values such as:

```text
{{ .user }}
{{ .email }}
{{ .groups }}
{{ .sub }}
```

## Security properties

- `state` is random, short-lived, one-time use, and held server-side.
- PKCE uses S256.
- `nonce` is generated per login and checked against the verified ID token.
- ID tokens are verified with the provider's discovered JWKS using `github.com/coreos/go-oidc/v3`.
- Issuer and audience checks are performed by `go-oidc`.
- UserInfo, when enabled, must return the same `sub` as the ID token.
- Access tokens, refresh tokens, and ID tokens are not exposed to Filestash attribute mapping.
- Redirect URIs must be HTTPS except for localhost development.

### Multi-instance note

Pending OIDC transactions are stored in memory for 10 minutes. For more than one Filestash application instance, use sticky routing during authentication or extend the state store to a shared backend. The plugin deliberately does not introduce Redis for the common single-instance deployment.

## Authentik

See [docs/AUTHENTIK.md](docs/AUTHENTIK.md).

## Compatibility

The first implementation tracks Filestash's public `IAuthentication` API on `master` at commit `2ea4bae7f66b46ea51c7e81506afc7c6e0b75364` (2026-09-29).

Filestash currently builds with Go 1.26, so CI follows Go 1.26 as well.

## License

The original code in this repository is licensed under the MIT License (`MIT`).
Filestash CE is licensed separately under AGPL-3.0. When this plugin is compiled
into a Filestash binary, distribution and network use of that combined program
must comply with Filestash's AGPL terms. This repository does not relicense
Filestash or any third-party dependency.

Filestash is a separate project and has its own license and trademarks.
