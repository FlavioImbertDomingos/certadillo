from __future__ import annotations

from certadillo.provisioning.drivers.base import Driver, InstallBundle, ProvisioningError

_DRIVERS: dict[str, type[Driver]] = {}


def register(cls: type[Driver]) -> type[Driver]:
    _DRIVERS[cls.kind] = cls
    return cls


def driver_for(kind: str) -> type[Driver]:
    from certadillo.provisioning.drivers import aws_acm, f5, kubernetes, ssh  # noqa: F401 - registers

    if kind not in _DRIVERS:
        raise ValueError(f"unknown target kind {kind!r}; one of {sorted(_DRIVERS)}")
    return _DRIVERS[kind]


def kinds() -> list[str]:
    from certadillo.provisioning.drivers import aws_acm, f5, kubernetes, ssh  # noqa: F401

    return sorted(_DRIVERS)


__all__ = ["Driver", "InstallBundle", "ProvisioningError", "driver_for", "kinds", "register"]
