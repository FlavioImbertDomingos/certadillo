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
    crl_interval_hours: int = field(default_factory=lambda: int(_env("CRL_INTERVAL_HOURS", "12") or 12))
    # Operations that require a second person (maker-checker).
    dual_control_actions: list[str] = field(
        default_factory=lambda: _list("DUAL_CONTROL") or ["onboard_prod_app", "issue_code_signing", "create_ca"]
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
