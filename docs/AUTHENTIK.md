# Authentik setup

This plugin treats Authentik as a standards-compliant OpenID Connect provider.

## 1. Create the provider

In Authentik, create an OAuth2/OpenID Provider for Filestash.

Recommended settings:

```text
Flow: Authorization Code
Client type: Confidential
Redirect URI: https://files.example.com/api/session/auth/
```

Use a strict redirect URI. The value must exactly match the `redirect_uri` configured in Filestash.

## 2. Create the application

Create an Authentik application and bind it to the provider, for example:

```text
Name: Filestash
Slug: filestash
```

Use Authentik policies/groups for coarse application admission such as a `filestash-users` group.

Do not mirror every storage ACL into Authentik groups. Storage ACLs should remain owned by the storage system or Filestash authorization layer.

## 3. Claims

The plugin works best with these claims:

```json
{
  "sub": "stable-subject-id",
  "preferred_username": "alice",
  "email": "alice@example.com",
  "name": "Alice",
  "groups": ["filestash-users", "engineering"]
}
```

`sub` is the stable identity. `preferred_username` is a display/login mapping and may change over time.

If you need group-aware Filestash attribute mapping, configure an Authentik scope/property mapping that emits a `groups` claim.

## 4. Filestash plugin settings

Typical settings:

```text
issuer=https://auth.example.com/application/o/filestash/
client_id=<client id>
client_secret=<client secret>
redirect_uri=https://files.example.com/api/session/auth/
scopes=openid profile email
username_claim=preferred_username
groups_claim=groups
userinfo=false
```

The `issuer` is the issuer value returned by Authentik's discovery document. It is not the discovery document URL itself.

For example, the discovery document is typically located under an issuer at:

```text
<issuer>/.well-known/openid-configuration
```

## 5. Attribute mapping

After successful OIDC login, the plugin exposes verified values to Filestash attribute mapping.

Common fields:

```text
.sub
.user
.username
.preferred_username
.email
.name
.groups
.groups_json
.raw_claims
```

`groups` is comma-separated for simple templates. `groups_json` preserves the list as JSON text.

## 6. Logout

Version 0.1 handles Filestash session logout only. It does not initiate Authentik RP-initiated logout / end-session flow.

That is intentional: logout federation should be added separately once the desired organization-wide SSO logout behavior is clear.
