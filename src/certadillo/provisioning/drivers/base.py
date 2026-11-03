from __future__ import annotations

import re
from dataclasses import dataclass, field


class ProvisioningError(Exception):
    pass


@dataclass
class InstallBundle:
    """What gets installed. key_pem is None when the key was generated on the
    device and never left it."""

    common_name: str
    cert_pem: str
    chain_pem: str
    key_pem: bytes | None
    serial_hex: str
    fingerprint: str
    steps: list[str] = field(default_factory=list)


class Driver:
    """One kind of target. config is the target's (set by an admin); params are
    the installation's placement inside it (set by the app owner, checked
    against what the target allows)."""

    kind = ""
    key_locations: tuple[str, ...] = ("central",)

    def __init__(self, config: dict, secret: str | None, settings=None, transport=None):
        self.config = config
        self.secret = secret
        self.settings = settings
        self.transport = transport  # tests inject an httpx transport

    @classmethod
    def check_config(cls, config: dict) -> dict:
        return config

    def check_params(self, params: dict) -> dict:
        return params

    def device_csr(self, params: dict, common_name: str, sans: list[str], key_type: str) -> str:
        raise ProvisioningError(f"{self.kind} targets do not generate keys on the device")

    def install(self, params: dict, bundle: InstallBundle) -> None:
        raise NotImplementedError

    # helpers ----------------------------------------------------------
    @staticmethod
    def require(config: dict, *keys: str) -> None:
        missing = [k for k in keys if not config.get(k)]
        if missing:
            raise ValueError(f"target config needs {', '.join(missing)}")


NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")


def safe_name(value: str, what: str) -> str:
    if not isinstance(value, str) or not NAME.match(value):
        raise ValueError(f"{what} {value!r} may only use letters, digits, '.', '_' and '-'")
    return value
