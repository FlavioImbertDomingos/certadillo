# Getting started

## Option 1: local, in two minutes

Needs Python 3.11 or newer.

```bash
git clone https://github.com/FlavioImbertDomingos/certadillo.git
cd certadillo
pip install -e ".[dev,hsm]"

export CERTADILLO_BOOTSTRAP_ADMIN_KEY=admin-key
export CERTADILLO_BOOTSTRAP_APPROVER_KEY=approver-key
certadillo serve --port 8080
```

On first start Certadillo creates a SQLite database and a root and issuing CA under `./.certadillo`. Open `http://localhost:8080`, paste `admin-key` into the key field and press Connect.

Fill it with example data (teams, apps, certificates, a few bad legacy certificates so the alerts have something to show):

```bash
python scripts/demo_seed.py --server http://localhost:8080 --admin-key admin-key --approver-key approver-key
```

## Option 2: the full stack with Docker

PostgreSQL, Prometheus, Alertmanager and Grafana, with rules and a dashboard already wired.

```bash
cp deploy/.env.example deploy/.env      # replace every value
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
```

| Service | URL |
| --- | --- |
| Certadillo console and API | http://localhost:8080 (interactive API docs at `/docs`) |
| Knowledge base | http://localhost:8080/kb |
| Grafana | http://localhost:3000, dashboard "Certadillo: certificate estate" in the PKI folder |
| Prometheus | http://localhost:9090 |
| Alertmanager | http://localhost:9093 |

## Your first certificate

```bash
S=http://localhost:8080
A=(-H "X-API-Key: admin-key" -H "Content-Type: application/json")

# a team and an app that may use names under *.cards.bank.internal
curl -s "${A[@]}" -X POST $S/api/v1/teams -d '{"name":"cards","contact_email":"cards-sre@bank.example"}'
curl -s "${A[@]}" -X POST $S/api/v1/apps -d '{"team_id":1,"name":"card-auth","environment":"dev",
  "profile":"tls-server","allowed_domains":["*.cards.bank.internal"]}'

# a credential for the app (shown once)
KEY=$(curl -s "${A[@]}" -X POST $S/api/v1/apps/1/credentials | python3 -c 'import json,sys;print(json.load(sys.stdin)["api_key"])')

# the app generates its own key and gets a certificate
export CERTADILLO_SERVER=$S CERTADILLO_API_KEY=$KEY
certadillo cert request --cn auth.cards.bank.internal --san auth.cards.bank.internal --out ./tls
openssl x509 -in tls/tls.crt -noout -subject -enddate
```

`./tls` now holds `tls.key` (mode 0600), `tls.crt` (leaf plus issuing CA) and `meta.json`. The key never left your machine.

Next: [Onboarding](03-onboarding.md) explains the choices you just skipped.

## Trusting the CA

Clients that verify your certificates need the root:

```bash
curl -s $S/pki/ca/root-ca.pem -o bank-root.pem
# Debian/Ubuntu
sudo cp bank-root.pem /usr/local/share/ca-certificates/bank-root.crt && sudo update-ca-certificates
```

Check the fingerprint against the one printed by `certadillo init` (or `GET /api/v1/cas`) before you trust it.
