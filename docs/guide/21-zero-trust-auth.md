# Zero-trust access with an external IdP

By default the console and API authenticate with API keys that Certadillo
hashes and stores. That makes Certadillo an identity store, and a stored key is
a long-lived secret someone can steal. The alternative is to trust short-lived
tokens minted by the organization's own identity provider, so access follows
the same controls as everything else the bank runs: multi-factor
authentication, conditional access, device posture, and session revocation. A
token that expires in an hour is not worth stealing, and there is no shared
secret in Certadillo's database.

Certadillo validates OpenID Connect / JWT bearer tokens from any standard
issuer, with presets for Microsoft Entra ID and HashiCorp Vault's OIDC
provider. It is off until you configure an issuer; when you do, tokens and API
keys work side by side, so you can migrate without a flag day.

## How a request is authenticated

```
client ──► Authorization: Bearer <JWT> ──►  Certadillo
                                            1. fetch the issuer's public keys (JWKS), cached
                                            2. verify signature, issuer, audience, exp/nbf/iat
                                            3. map the role/group claim to a Certadillo role
                                            4. for an app token, resolve the app claim to an onboarded app
```

Every check fails closed: a bad signature, the wrong issuer or audience, an
expired token, an algorithm that is not allowed (including `none`), or a role
claim that maps to nothing all result in 401, and the reason is logged. The
signature and claim checks are done by the PyJWT library rather than
hand-written, because that is where a validator usually goes wrong.

The authenticator runs as a chain: the OIDC token first, then the API key. A
machine that cannot get a token still uses a key; a user or workload that can
present a token never needs one.

## Microsoft Entra ID

```bash
CERTADILLO_OIDC_PROVIDER=entra
CERTADILLO_OIDC_ENTRA_TENANT=<tenant id or domain>
CERTADILLO_OIDC_AUDIENCE=api://certadillo          # the app registration's Application ID URI
CERTADILLO_OIDC_ROLE_CLAIM=roles                    # Entra app roles; use "groups" for group claims
CERTADILLO_OIDC_ROLE_MAP="PKI.Admin=admin;PKI.Approver=approver;PKI.Operator=operator;PKI.Auditor=auditor"
```

The preset builds the issuer (`https://login.microsoftonline.com/<tenant>/v2.0`)
and the JWKS URL for you. Register Certadillo as an app in Entra, define app
roles (PKI.Admin and so on), and assign them to users or groups. A user signs
in, gets a token with a `roles` claim, and calls the API with it.

Workload identity federation covers machines: a GitHub Actions job or a
Kubernetes pod presents a federated token from its own platform, Entra
exchanges it for an access token, and Certadillo accepts that. No key is stored
in the pipeline.

## HashiCorp Vault

```bash
CERTADILLO_OIDC_PROVIDER=vault
CERTADILLO_OIDC_VAULT_ISSUER=https://vault.bank.internal/v1/identity/oidc/provider/certadillo
CERTADILLO_OIDC_AUDIENCE=certadillo
CERTADILLO_OIDC_ROLE_CLAIM=roles
CERTADILLO_OIDC_ROLE_MAP="pki-admin=admin;pki-operator=operator"
```

A workload that already authenticates to Vault asks Vault's OIDC provider for
an identity token and presents it to Certadillo. Vault policy decides which
workloads may get a token with which role claim, so Vault stays the single
place identity is managed. The preset points the JWKS URL at the provider's
`/.well-known/keys`.

## App tokens

An app credential (used to request certificates for one onboarded app) maps to
a token whose role claim is `app` and which names the app in the `app` claim
(the app's name or numeric id):

```bash
CERTADILLO_OIDC_APP_CLAIM=app
CERTADILLO_OIDC_ROLE_MAP="...;App-Cards=app"
```

The token is scoped exactly like a key-based app credential: it can only
request certificates for the app it names, and only while that app is active. A
token with the `app` role but no resolvable app claim is refused.

## A generic OIDC issuer

Without a preset, point Certadillo at the issuer and its JWKS directly:

```bash
CERTADILLO_OIDC_ISSUER=https://idp.bank.internal/
CERTADILLO_OIDC_JWKS_URI=https://idp.bank.internal/.well-known/jwks.json
CERTADILLO_OIDC_AUDIENCE=certadillo
CERTADILLO_OIDC_ALGORITHMS=RS256,ES256      # allowed signature algorithms; never "none"
CERTADILLO_OIDC_USERNAME_CLAIM=sub          # what becomes the audit actor
CERTADILLO_OIDC_ROLE_CLAIM=roles
CERTADILLO_OIDC_ROLE_MAP="pki-admins=admin"
CERTADILLO_OIDC_CLOCK_SKEW=60               # seconds of leeway on exp/nbf/iat
```

## What stays the same

Dual control, per-app scope, the policy engine and the audit trail are
unchanged. The only difference is who the actor is: an audit event from a token
records `idp:<subject>` (the IdP's `sub`, or the claim named by
`OIDC_USERNAME_CLAIM`) instead of a principal name, so the audit trail ties
each action to the person or workload the IdP authenticated.

## Notes

- Certadillo fetches the issuer's JWKS over HTTPS and caches it, refetching when
  it sees a new key id (so key rotation needs no restart). The host running
  Certadillo must be able to reach the issuer's JWKS URL.
- Console single sign-on (a browser login flow) builds on this token validation
  and is tracked in the roadmap; today the token is presented on the API.
- Keep at least one break-glass admin API key for the case where the IdP is
  unreachable.
