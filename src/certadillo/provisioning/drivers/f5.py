"""F5 BIG-IP through iControl REST. The key and certificate are installed as
new, serial-named objects and only then is the client-SSL profile switched to
them, so traffic never sees a half-installed pair. The old objects stay until
an operator cleans them up, which keeps a rollback one profile change away."""
from __future__ import annotations

import ssl

import httpx

from certadillo.provisioning.drivers import register
from certadillo.provisioning.drivers.base import Driver, InstallBundle, ProvisioningError, safe_name


@register
class F5Driver(Driver):
    kind = "f5"

    @classmethod
    def check_config(cls, config: dict) -> dict:
        cls.require(config, "host", "username")
        if not str(config["host"]).startswith("https://"):
            raise ValueError("host must be https://")
        safe_name(config.get("partition", "Common"), "partition")
        return config

    def check_params(self, params: dict) -> dict:
        return {"profile": safe_name(params.get("profile", ""), "profile"),
                "object_prefix": safe_name(params.get("object_prefix", params.get("profile", "")), "object_prefix")}

    def _client(self) -> httpx.Client:
        verify: bool | ssl.SSLContext = True
        if self.config.get("ca_cert"):
            verify = ssl.create_default_context(cadata=self.config["ca_cert"])
        return httpx.Client(base_url=self.config["host"], verify=verify, timeout=30, transport=self.transport)

    def _login(self, c: httpx.Client) -> None:
        r = c.post("/mgmt/shared/authn/login", json={"username": self.config["username"], "password": self.secret,
                                                       "loginProviderName": "tmos"})
        if r.status_code != 200:
            raise ProvisioningError(f"BIG-IP login failed ({r.status_code})")
        c.headers["X-F5-Auth-Token"] = r.json()["token"]["token"]

    @staticmethod
    def _upload(c: httpx.Client, name: str, data: bytes) -> str:
        r = c.post(f"/mgmt/shared/file-transfer/uploads/{name}", content=data,
                   headers={"Content-Type": "application/octet-stream",
                            "Content-Range": f"0-{len(data) - 1}/{len(data)}"})
        if r.status_code >= 300:
            raise ProvisioningError(f"upload of {name} failed ({r.status_code})")
        return f"/var/config/rest/downloads/{name}"

    def install(self, params: dict, bundle: InstallBundle) -> None:
        if bundle.key_pem is None:
            raise ProvisioningError("F5 targets need a centrally generated key")
        part = self.config.get("partition", "Common")
        obj = f"{params['object_prefix']}_{bundle.serial_hex[:12]}"
        with self._client() as c:
            self._login(c)
            key_file = self._upload(c, f"{obj}.key", bundle.key_pem)
            crt_file = self._upload(c, f"{obj}.crt", bundle.cert_pem.encode())
            chain_file = self._upload(c, f"{obj}-chain.crt", bundle.chain_pem.encode())
            for kind, name, src in (("key", f"{obj}.key", key_file), ("cert", f"{obj}.crt", crt_file),
                                    ("cert", f"{obj}-chain.crt", chain_file)):
                r = c.post(f"/mgmt/tm/sys/crypto/{kind}", json={"command": "install", "name": name,
                                                                  "partition": part, "from-local-file": src})
                if r.status_code >= 300:
                    raise ProvisioningError(f"installing {name} failed ({r.status_code}): {r.text[:200]}")
            bundle.steps.append(f"installed {obj}.key/.crt/-chain.crt in /{part}")
            r = c.patch(f"/mgmt/tm/ltm/profile/client-ssl/~{part}~{params['profile']}",
                        json={"certKeyChain": [{"name": "default", "cert": f"/{part}/{obj}.crt",
                                                "key": f"/{part}/{obj}.key", "chain": f"/{part}/{obj}-chain.crt"}]})
            if r.status_code >= 300:
                raise ProvisioningError(f"updating profile {params['profile']} failed ({r.status_code})")
            bundle.steps.append(f"switched client-ssl profile {params['profile']} to {obj}")
