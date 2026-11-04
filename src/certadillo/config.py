"""Runtime settings. Everything comes from environment variables so the same
image runs in dev, CI and production without code changes."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(f"CERTADILLO_{name}", default)


def _list(name: str) -> list[str]:
    raw = _env(name, "") or ""
    return [v.strip() for v in raw.split(",") if v.strip()]


def _pairs(name: str) -> dict[str, str]:
    """Parse "a=b;c=d" into {a: b, c: d}."""
    out: dict[str, str] = {}
    for item in (_env(name, "") or "").split(";"):
        if "=" in item:
            k, v = item.split("=", 1)
            if k.strip() and v.strip():
                out[k.strip()] = v.strip()
    return out


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(_env("DATA_DIR", "./.certadillo")))
    db_url: str | None = field(default_factory=lambda: _env("DB_URL"))
    policy_file: str | None = field(default_factory=lambda: _env("POLICY_FILE"))
    # software | pkcs11 | vault-transit (where new CA keys are generated; existing keys
    # keep loading from wherever their key_ref says they live)
    signer: str = field(default_factory=lambda: _env("SIGNER", "software"))
    # Protects software CA keys and derives the seal and field-encryption keys.
    # Unset: a random one is generated on first start and kept in
    # <data_dir>/key-passphrase (mode 0600). Placeholders and short values are refused.
    key_passphrase: str | None = field(default_factory=lambda: _env("KEY_PASSPHRASE"))
    pkcs11_lib: str | None = field(default_factory=lambda: _env("PKCS11_LIB"))
    pkcs11_token: str = field(default_factory=lambda: _env("PKCS11_TOKEN", "certadillo"))
    pkcs11_pin: str | None = field(default_factory=lambda: _env("PKCS11_PIN"))
    org_name: str = field(default_factory=lambda: _env("ORG_NAME", "Example Bank"))
    base_url: str = field(default_factory=lambda: _env("BASE_URL", "http://localhost:8080"))
    bootstrap_admin_key: str | None = field(default_factory=lambda: _env("BOOTSTRAP_ADMIN_KEY"))
    bootstrap_approver_key: str | None = field(default_factory=lambda: _env("BOOTSTRAP_APPROVER_KEY"))
    auto_init_ca: bool = field(default_factory=lambda: (_env("AUTO_INIT_CA", "true") or "").lower() == "true")
    alert_interval_seconds: int = field(default_factory=lambda: int(_env("ALERT_INTERVAL", "300") or 300))
    expiry_warning_days: int = field(default_factory=lambda: int(_env("EXPIRY_WARNING_DAYS", "30") or 30))
    expiry_critical_days: int = field(default_factory=lambda: int(_env("EXPIRY_CRITICAL_DAYS", "7") or 7))
    webhook_urls: list[str] = field(default_factory=lambda: _list("WEBHOOK_URLS"))
    slack_webhook_urls: list[str] = field(default_factory=lambda: _list("SLACK_WEBHOOK_URLS"))
    jira_url: str | None = field(default_factory=lambda: _env("JIRA_URL"))
    jira_user: str | None = field(default_factory=lambda: _env("JIRA_USER"))
    jira_token: str | None = field(default_factory=lambda: _env("JIRA_TOKEN"))
    jira_project: str = field(default_factory=lambda: _env("JIRA_PROJECT", "PKI"))
    snow_url: str | None = field(default_factory=lambda: _env("SNOW_URL"))
    snow_user: str | None = field(default_factory=lambda: _env("SNOW_USER"))
    snow_password: str | None = field(default_factory=lambda: _env("SNOW_PASSWORD"))
    snow_assignment_group: str = field(default_factory=lambda: _env("SNOW_ASSIGNMENT_GROUP", "PKI Operations"))
    scep_allow_des: bool = field(default_factory=lambda: (_env("SCEP_ALLOW_DES", "false") or "").lower() == "true")
    crl_interval_hours: int = field(default_factory=lambda: int(_env("CRL_INTERVAL_HOURS", "12") or 12))
    # ACME dns-01: resolvers used for _acme-challenge lookups. ACME_DNS_VIEWS maps
    # zones to resolvers for split-horizon DNS, longest suffix wins:
    #   "bank.internal=10.1.0.53,10.2.0.53;example.com=1.1.1.1"
    acme_dns_resolvers: list[str] = field(default_factory=lambda: _list("ACME_DNS_RESOLVERS"))
    acme_dns_views: str = field(default_factory=lambda: _env("ACME_DNS_VIEWS", "") or "")
    acme_dns_timeout: float = field(default_factory=lambda: float(_env("ACME_DNS_TIMEOUT", "8") or 8))
    # ARI (RFC 9773): how often clients should poll renewalInfo
    ari_retry_after_seconds: int = field(default_factory=lambda: int(_env("ARI_RETRY_AFTER", "21600") or 21600))
    # SCEP validation webhook (Intune-style): called before a challenge is accepted,
    # then notified of success or failure. Used by apps with options.scep_validation = "webhook".
    scep_validation_url: str | None = field(default_factory=lambda: _env("SCEP_VALIDATION_URL"))
    scep_validation_token: str | None = field(default_factory=lambda: _env("SCEP_VALIDATION_TOKEN"))
    # EST behind a TLS-terminating load balancer: the client certificate arrives in a
    # header, which is trusted only from these proxy addresses (CIDRs).
    est_client_cert_header: str = field(default_factory=lambda: _env("EST_CLIENT_CERT_HEADER", "") or "")
    est_trusted_proxies: list[str] = field(default_factory=lambda: _list("EST_TRUSTED_PROXIES"))
    # or: a secret the load balancer adds as X-Certadillo-Proxy-Auth (works behind uvicorn's proxy headers)
    est_proxy_secret: str | None = field(default_factory=lambda: _env("EST_PROXY_SECRET"))
    # Zero-trust access: validate short-lived OIDC/JWT tokens from an external
    # IdP instead of (or alongside) local API keys. Set a provider preset, or
    # the issuer and JWKS URI directly. Nothing here is a stored credential.
    oidc_provider: str | None = field(default_factory=lambda: _env("OIDC_PROVIDER"))  # entra | vault | generic
    oidc_issuer: str | None = field(default_factory=lambda: _env("OIDC_ISSUER"))
    oidc_jwks_uri: str | None = field(default_factory=lambda: _env("OIDC_JWKS_URI"))
    oidc_audience: str | None = field(default_factory=lambda: _env("OIDC_AUDIENCE"))
    oidc_algorithms: list[str] = field(default_factory=lambda: _list("OIDC_ALGORITHMS") or ["RS256", "ES256"])
    oidc_username_claim: str = field(default_factory=lambda: _env("OIDC_USERNAME_CLAIM", "sub"))
    oidc_role_claim: str = field(default_factory=lambda: _env("OIDC_ROLE_CLAIM", "roles"))
    oidc_app_claim: str = field(default_factory=lambda: _env("OIDC_APP_CLAIM", "app"))
    # "claimvalue=role;claimvalue=role", e.g. "PKI-Admins=admin;PKI-Approvers=approver"
    oidc_role_map: dict[str, str] = field(default_factory=lambda: _pairs("OIDC_ROLE_MAP"))
    oidc_clock_skew: int = field(default_factory=lambda: int(_env("OIDC_CLOCK_SKEW", "60") or 60))
    oidc_entra_tenant: str | None = field(default_factory=lambda: _env("OIDC_ENTRA_TENANT"))
    oidc_vault_issuer: str | None = field(default_factory=lambda: _env("OIDC_VAULT_ISSUER"))
    # Integrity seals: HMAC key for principals, approvals and certificate status.
    # Not stored in the database. Hex or base64; if unset it is derived from
    # KEY_PASSPHRASE. SEAL_KEY_PREVIOUS lets `certadillo integrity reseal` rotate it.
    seal_key: str | None = field(default_factory=lambda: _env("SEAL_KEY"))
    seal_key_previous: str | None = field(default_factory=lambda: _env("SEAL_KEY_PREVIOUS"))
    # Audit chain anchoring: the chain head is sent here once a day.
    audit_anchor_url: str | None = field(default_factory=lambda: _env("AUDIT_ANCHOR_URL"))
    audit_anchor_file: str | None = field(default_factory=lambda: _env("AUDIT_ANCHOR_FILE"))
    audit_anchor_hours: int = field(default_factory=lambda: int(_env("AUDIT_ANCHOR_HOURS", "24") or 24))
    # Audit shipping: every audit event, with its chain hashes and a MAC under the
    # seal key, sent to these sinks (comma-separated). See certadillo.audit.shipping.
    #   file:/var/log/certadillo/audit.jsonl   syslog+tls://siem:6514   syslog+tcp://host:514
    #   splunk+https://splunk:8088            https://collector/ingest  s3://bucket/prefix
    audit_ship: list[str] = field(default_factory=lambda: _list("AUDIT_SHIP"))
    audit_ship_interval: int = field(default_factory=lambda: int(_env("AUDIT_SHIP_INTERVAL", "15") or 15))
    audit_ship_token_ref: str | None = field(default_factory=lambda: _env("AUDIT_SHIP_TOKEN_REF"))
    audit_ship_cacert: str | None = field(default_factory=lambda: _env("AUDIT_SHIP_CACERT"))
    audit_ship_s3_retention_days: int = field(default_factory=lambda: int(_env("AUDIT_SHIP_S3_RETENTION_DAYS", "2555") or 2555))
    audit_ship_splunk_index: str | None = field(default_factory=lambda: _env("AUDIT_SHIP_SPLUNK_INDEX"))
    # Field encryption for secret columns: "local" (key derived from KEY_PASSPHRASE)
    # or "vault" (HashiCorp Vault Transit; the key never leaves Vault).
    field_cipher: str = field(default_factory=lambda: _env("FIELD_CIPHER", "local") or "local")
    vault_addr: str | None = field(default_factory=lambda: _env("VAULT_ADDR"))
    vault_token: str | None = field(default_factory=lambda: _env("VAULT_TOKEN"))
    vault_namespace: str | None = field(default_factory=lambda: _env("VAULT_NAMESPACE"))
    # a file Vault Agent keeps a fresh token in; read on every call, preferred over VAULT_TOKEN
    vault_token_file: str | None = field(default_factory=lambda: _env("VAULT_TOKEN_FILE"))
    vault_cacert: str | None = field(default_factory=lambda: _env("VAULT_CACERT"))  # CA bundle for Vault's TLS
    # CA keys in Vault Transit (CERTADILLO_SIGNER=vault-transit): key name is <prefix><CA name>
    vault_signer_mount: str = field(default_factory=lambda: _env("VAULT_SIGNER_MOUNT", "transit") or "transit")
    vault_key_prefix: str = field(default_factory=lambda: _env("VAULT_KEY_PREFIX", "certadillo-") or "certadillo-")
    vault_transit_mount: str = field(default_factory=lambda: _env("VAULT_TRANSIT_MOUNT", "transit") or "transit")
    vault_transit_key: str = field(default_factory=lambda: _env("VAULT_TRANSIT_KEY", "certadillo-fields") or "certadillo-fields")
    # Name constraints written into new issuing and subordinate CAs (RFC 5280
    # 4.2.1.10), so a stolen CA key can only mint for these names.
    ca_permitted_dns: list[str] = field(default_factory=lambda: _list("CA_PERMITTED_DNS"))
    ca_excluded_dns: list[str] = field(default_factory=lambda: _list("CA_EXCLUDED_DNS"))
    ca_permitted_email: list[str] = field(default_factory=lambda: _list("CA_PERMITTED_EMAIL"))
    # AD CS template audit: the live LDAP collector reads the Configuration
    # naming context. Read-only; a bind account with default domain read is enough.
    adcs_ldap_url: str | None = field(default_factory=lambda: _env("ADCS_LDAP_URL"))
    adcs_ldap_user: str | None = field(default_factory=lambda: _env("ADCS_LDAP_USER"))
    adcs_ldap_password: str | None = field(default_factory=lambda: _env("ADCS_LDAP_PASSWORD"))
    adcs_ldap_base: str | None = field(default_factory=lambda: _env("ADCS_LDAP_BASE"))
    # Settings-driven maker-checker actions. Sub-CA creation always needs a
    # second person, and per-profile issuance approval is the profile's
    # `dual_control: true` flag.
    # Zones reserved for non-production names. A dev or test app is activated
    # without a second person only when its whole scope lies inside these zones;
    # any other scope needs approval whatever environment the app claims, since
    # the environment label alone does not stop a "dev" app naming prod hosts.
    dev_domains: list[str] = field(default_factory=lambda: _list("DEV_DOMAINS"))
    dual_control_actions: list[str] = field(
        default_factory=lambda: _list("DUAL_CONTROL") or ["onboard_prod_app", "policy_change"]
    )

    def __post_init__(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.key_passphrase = _resolve_passphrase(self.key_passphrase, self.data_dir)
        if not self.db_url:
            self.db_url = f"sqlite:///{(self.data_dir / 'certadillo.db').resolve()}"


# Values that have appeared in docs and examples. Anyone can read them, so
# keys protected by them are not protected at all.
KNOWN_PLACEHOLDERS = {"change-me-dev-only", "replace-me", "change-me", "changeme", "password", "secret"}
MIN_PASSPHRASE = 16


def _resolve_passphrase(value: str | None, data_dir: Path) -> str:
    import secrets

    if value is not None:
        if value.strip().lower() in KNOWN_PLACEHOLDERS or len(value) < MIN_PASSPHRASE:
            raise ValueError(
                "CERTADILLO_KEY_PASSPHRASE is a placeholder or shorter than "
                f"{MIN_PASSPHRASE} characters; generate one with: openssl rand -base64 32"
            )
        return value
    path = data_dir / "key-passphrase"
    if path.exists():
        return path.read_text().strip()
    if (data_dir / "keys").exists():
        # Created before this check existed, with the old built-in dev passphrase.
        # That value is public, so those keys are not worth keeping.
        raise ValueError(
            f"{data_dir} holds CA keys but no key-passphrase file: it was created with the old public "
            "dev default. Move the directory aside and start fresh; if it was created with your own "
            "passphrase, set CERTADILLO_KEY_PASSPHRASE to it.")
    generated = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(generated + "\n")
    return generated


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
