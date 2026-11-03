"""Kubernetes TLS secrets, for ingress controllers and anything that mounts a
kubernetes.io/tls secret. The API server certificate is verified against the
target's ca_cert, namespaces are limited to the target's list, and a secret
Certadillo did not create is not overwritten unless the installation says
adopt: true."""
from __future__ import annotations

import base64
import ssl

import httpx

from certadillo.provisioning.drivers import register
from certadillo.provisioning.drivers.base import Driver, InstallBundle, ProvisioningError, safe_name

LABEL = "app.kubernetes.io/managed-by"


@register
class KubernetesDriver(Driver):
    kind = "kubernetes"

    @classmethod
    def check_config(cls, config: dict) -> dict:
        cls.require(config, "api_server", "namespaces")
        if not str(config["api_server"]).startswith("https://"):
            raise ValueError("api_server must be https://")
        if not isinstance(config["namespaces"], list) or not config["namespaces"]:
            raise ValueError("namespaces must list the namespaces Certadillo may write to")
        return config

    def check_params(self, params: dict) -> dict:
        ns = safe_name(params.get("namespace", ""), "namespace")
        if ns not in self.config["namespaces"]:
            raise ValueError(f"namespace {ns} is not allowed on this target")
        return {"namespace": ns, "secret_name": safe_name(params.get("secret_name", ""), "secret_name"),
                "adopt": bool(params.get("adopt", False))}

    def _client(self) -> httpx.Client:
        verify: bool | ssl.SSLContext = True
        if self.config.get("ca_cert"):
            verify = ssl.create_default_context(cadata=self.config["ca_cert"])
        headers = {"Authorization": f"Bearer {self.secret}"} if self.secret else {}
        return httpx.Client(base_url=self.config["api_server"], headers=headers, verify=verify, timeout=20,
                            transport=self.transport)

    def install(self, params: dict, bundle: InstallBundle) -> None:
        if bundle.key_pem is None:
            raise ProvisioningError("kubernetes targets need a centrally generated key")
        ns, name = params["namespace"], params["secret_name"]
        path = f"/api/v1/namespaces/{ns}/secrets"
        b64 = lambda b: base64.b64encode(b if isinstance(b, bytes) else b.encode()).decode()  # noqa: E731
        body = {
            "apiVersion": "v1", "kind": "Secret", "type": "kubernetes.io/tls",
            "metadata": {"name": name, "namespace": ns,
                         "labels": {LABEL: "certadillo"},
                         "annotations": {"certadillo.io/serial": bundle.serial_hex}},
            "data": {"tls.crt": b64(bundle.cert_pem + bundle.chain_pem), "tls.key": b64(bundle.key_pem)},
        }
        with self._client() as c:
            r = c.get(f"{path}/{name}")
            if r.status_code == 404:
                r = c.post(path, json=body)
                bundle.steps.append(f"created secret {ns}/{name}")
            elif r.status_code == 200:
                existing = r.json()
                if (existing.get("metadata", {}).get("labels") or {}).get(LABEL) != "certadillo" and not params["adopt"]:
                    raise ProvisioningError(f"secret {ns}/{name} exists and was not created by Certadillo; "
                                            "set adopt: true on the installation to take it over")
                body["metadata"]["resourceVersion"] = existing["metadata"].get("resourceVersion")
                r = c.put(f"{path}/{name}", json=body)
                bundle.steps.append(f"updated secret {ns}/{name}")
            if r.status_code >= 300:
                raise ProvisioningError(f"Kubernetes API returned {r.status_code}: {r.text[:200]}")
