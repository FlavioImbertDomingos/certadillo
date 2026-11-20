# Certadillo Helm chart

```bash
kubectl create namespace pki
kubectl -n pki create secret generic certadillo \
  --from-literal=db-url='postgresql+psycopg://certadillo_app:...@db.pki:5432/certadillo' \
  --from-literal=key-passphrase="$(openssl rand -hex 32)" \
  --from-literal=bootstrap-admin-key="cdl_$(openssl rand -hex 24)"
helm install certadillo deploy/helm/certadillo -n pki \
  --set baseUrl=https://pki.bank.example --set image.digest=sha256:...
```

| Feature | How |
| --- | --- |
| Schema upgrades | a pre-install/pre-upgrade Job runs `certadillo db migrate` (with `database.migrationJob.ownerSecretKey` if DDL needs a separate owner credential); pods run with `CERTADILLO_DB_AUTO_MIGRATE=false` |
| Replicas | `replicaCount > 1` needs `persistence.accessMode: ReadWriteMany` (the chart refuses otherwise): replicas share the data directory. Background work runs on one replica at a time through leases |
| Hardening | non-root uid 10001, read-only root filesystem, no capabilities, RuntimeDefault seccomp, no service account token |
| Network | optional NetworkPolicy (DNS plus the peers you list), on top of `CERTADILLO_EGRESS_ALLOW` |
| Monitoring | optional ServiceMonitor for the Prometheus Operator; rules and dashboards are in `deploy/prometheus` and `deploy/grafana` |
| Settings | the common ones in `values.yaml`; anything else in `env` |

The data volume is kept when the release is deleted (`helm.sh/resource-policy:
keep`): it holds OCSP keys and, with software signing, CA keys. Use an HSM
(`signer: pkcs11`) or Vault Transit (`signer: vault-transit`) in production;
see [docs/HSM.md](../../../docs/HSM.md).

CI renders the chart with several value sets and validates the output with
kubeconform against the Kubernetes 1.31 schemas.
