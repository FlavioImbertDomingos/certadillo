# Deploying to your own server

`deploy.sh` ships the committed tree to a Docker host over SSH and runs Certadillo with PostgreSQL. Only port 8080 is published; the database stays on the private Docker network.

## First deploy

Needs Docker with the compose plugin on the server and SSH access from your machine.

```bash
deploy/server/deploy.sh root@154.53.47.199
```

The first run:

1. uploads the current commit to `/opt/certadillo/releases/<commit>` and points `/opt/certadillo/app` at it;
2. generates secrets into `/opt/certadillo/.env` (mode 600): database password, key passphrase, admin and approver keys;
3. builds the image and starts `certadillo` and `postgres` with `restart: unless-stopped`;
4. loads the demo estate and creates a read-only `recruiter-viewer` key (auditor role);
5. prints the keys once.

Then open `http://154.53.47.199:8080`, paste a key and press Connect. The knowledge base is at `/kb/`.

## Updates

Commit, then run the same command. Data, CA keys and secrets are kept; the five newest releases stay on disk for rollback.

## Useful commands on the server

```bash
cd /opt/certadillo
C="docker compose -f app/deploy/server/docker-compose.yml --env-file .env -p certadillo"
$C ps
$C logs -f certadillo
$C exec certadillo certadillo audit verify
$C exec certadillo certadillo principal alice --role operator      # new key, printed once
$C down                                                              # stop (data stays in volumes)
```

Back up the `certadillo_pgdata` and `certadillo_cadata` volumes; `cadata` holds the CA keys (encrypted with the passphrase in `.env`).

## Moving to a domain

When certadillo.com points at the server, follow the steps at the top of `nginx-certadillo.com.conf`. The last step redeploys with `BASE_URL=https://certadillo.com BIND=127.0.0.1`, which puts the domain into new certificates' OCSP and CRL URLs and closes 8080 to the internet.

## Before you share it

This is a public demo of an MVP, not a production PKI. Over plain HTTP, keys typed into the console cross the network unencrypted, so share only the viewer key until the domain and TLS are in place, and keep the admin and approver keys private. See `docs/SECURITY.md` for the known gaps.
