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
    # software | pkcs11
    signer: str = field(default_factory=lambda: _env("SIGNER", "software"))
    key_passphrase: str = field(default_factory=lambda: _env("KEY_PASSPHRASE", "change-me-dev-only"))
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
    # AD CS template audit: the live LDAP collector reads the Configuration
    # naming context. Read-only; a bind account with default domain read is enough.
    adcs_ldap_url: str | None = field(default_factory=lambda: _env("ADCS_LDAP_URL"))
    adcs_ldap_user: str | None = field(default_factory=lambda: _env("ADCS_LDAP_USER"))
    adcs_ldap_password: str | None = field(default_factory=lambda: _env("ADCS_LDAP_PASSWORD"))
    adcs_ldap_base: str | None = field(default_factory=lambda: _env("ADCS_LDAP_BASE"))
    # Settings-driven maker-checker actions. Sub-CA creation always needs a
    # second person, and per-profile issuance approval is the profile's
    # `dual_control: true` flag.
    dual_control_actions: list[str] = field(
        default_factory=lambda: _list("DUAL_CONTROL") or ["onboard_prod_app"]
    )

    def __post_init__(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if not self.db_url:
            self.db_url = f"sqlite:///{(self.data_dir / 'certadillo.db').resolve()}"


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
