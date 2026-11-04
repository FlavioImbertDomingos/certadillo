# Upstream issuers

Certadillo signs with its own CAs by default. It can also put another CA
behind its registration authority: a public ACME CA for internet-facing names,
DigiCert CertCentral for publicly trusted OV/EV certificates, AWS Private CA
for workloads in AWS, or an existing EJBCA. Onboarding, scope checks, profiles,
the policy tree, approvals, audit, inventory, alerts, renewal and push
provisioning are the same whichever CA signs. Only the signing call differs.

## Configure issuers

Issuers live in the policy file (`CERTADILLO_POLICY_FILE`), next to the
profiles. Credentials are references (`env:`, `file:`, `vault:`), never values.

```yaml
issuers:
  public-acme:
    type: acme
    directory: https://acme-v02.api.letsencrypt.org/directory
    contact: mailto:pki-team@bank.example
    # eab: {kid: "...", hmac_ref: "vault:secret/data/certadillo/zerossl#hmac"}   # CAs that require EAB
    dns:
      provider: rfc2136                 # or http-hook
      server: 10.1.0.53
      zone: bank.example.
      tsig_name: certadillo-acme.
      tsig_secret_ref: vault:secret/data/certadillo/dns#tsig
    propagation_seconds: 20

  digicert:
    type: digicert
    product: ssl_basic                  # the CertCentral product id
    organization_id: 123456             # a pre-validated organization
    api_key_ref: vault:secret/data/certadillo/digicert#api_key

  aws-pca:
    type: aws-pca
    ca_arn: arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/...
    region: us-east-1
    signing_algorithm: SHA256WITHECDSA

  ejbca:
    type: ejbca
    url: https://ejbca.bank.internal/ejbca/ejbca-rest-api
    ca_name: Bank Issuing CA
    certificate_profile: TLS_SERVER
    end_entity_profile: CERTADILLO
    client_cert_ref: file:/run/secrets/ejbca-client.crt
    client_key_ref: file:/run/secrets/ejbca-client.key
```

A misconfigured issuer stops Certadillo at startup with the reason.

## Route certificates to an issuer

Either name the issuer in a profile (`issuer: digicert`), or set it on a policy
folder so every app below it uses it:

```bash
curl -s "${A[@]}" -X POST $S/api/v1/folders -d '{
  "name": "Internet facing",
  "settings": {"issuer": {"value": "public-acme", "locked": true},
               "allowed_zones": {"value": ["bank.example"], "locked": true}}}'
```

The folder setting accepts `local` or a configured issuer name, and is refused
otherwise.

## What each driver does

| type | Issues with | Revokes with | Notes |
| --- | --- | --- | --- |
| `acme` | RFC 8555 order, dns-01 through the DNS provider, finalize with the app's CSR | `revokeCert` with the account key | DNS names only. The account key is created once, stored in the data directory encrypted with the key passphrase. TXT records are removed after validation |
| `digicert` | `POST /order/certificate/{product}` with `skip_approval`; immediate issuance with pre-validated org and domains, otherwise polled | `PUT /certificate/{id}/revoke` | Certadillo already ran policy and dual control, so CertCentral's own approval queue is skipped |
| `aws-pca` | `IssueCertificate` with the validity the policy decided, then `GetCertificate` | `RevokeCertificate` | Standard AWS credential chain |
| `ejbca` | `pkcs10enroll` with the configured CA and profiles | `PUT /v1/certificate/{issuer}/{serial}/revoke` | Client-certificate authentication |

## Seeing what is configured

The console's Issuers tab, and `GET /api/v1/issuers` (admin, operator,
approver, auditor), list every CA that can sign: the built-in CAs, AD CS
through the gateway, Vault PKI and each upstream issuer, with the profiles and
policy folders that route to it and how many certificates it has issued.
Configuration is shown without secrets; a credential appears only as the kind
of reference that holds it (`env reference`, `vault reference`).

## Trust, but check

Certadillo does not take the upstream CA's word for it. Before a certificate
from an upstream issuer is stored or returned, its public key must be the one
in the request and it must carry no DNS name the policy did not approve. A CA
that changes either is treated as a failure and nothing is issued to the app.

The certificate's chain from the upstream CA is stored with it and returned as
`chain_pem`, and push provisioning installs that chain. OCSP and CRLs for these
certificates come from the upstream CA, not from Certadillo.

## DNS providers for ACME

| provider | Settings | For |
| --- | --- | --- |
| `rfc2136` | `server`, `port`, `zone`, `tsig_name`, `tsig_secret_ref`, `tsig_algorithm` (default hmac-sha256), `ttl` | BIND, Infoblox, PowerDNS, Windows DNS with secure dynamic updates |
| `http-hook` | `set_url`, `clear_url`, optional `token_ref` (sent as a bearer token) | an in-house DNS automation API: Certadillo posts `{"host", "value"}` to set and `{"host"}` to clear |

## How it is tested

The ACME driver is tested against Pebble, Let's Encrypt's test CA, with real
dns-01 through Pebble's DNS test server, including revocation. AWS Private CA
runs against moto. DigiCert CertCentral and EJBCA run against fakes of their
REST APIs that sign with a throwaway CA, which also check that a CA adding a
name or swapping the key is refused.
