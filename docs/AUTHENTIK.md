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

Bind a dedicated group such as `reference-project` to the Filestash application.
With a single read-only reference library, this makes group membership the
application admission boundary. Users outside the group must not receive an
authorization code. Each additional library needs its own verified storage
and authorization boundary; a shared SFTP credential does not preserve user ACLs.

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

Filestash's encrypted session token normally remains valid after an Authentik
group change. While `oidc` is selected, this plugin rejects sessions older than
15 minutes and blocks direct storage login through `POST /api/session`. Set
Filestash's cookie timeout to 15 minutes or less, and disable share links for a
read-only reference profile. Group removal can take up to 15 minutes to affect
an existing Filestash session; logout alone does not revoke a copied token.
