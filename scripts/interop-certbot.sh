#!/usr/bin/env bash
# End-to-end ACME interop: certbot (standalone http-01) -> Certadillo -> openssl
# verify + OCSP -> certbot revoke -> OCSP shows revoked.
# Needs: certbot, openssl, root (certbot binds :80), and the two names below
# resolving to 127.0.0.1 (the script adds them to /etc/hosts when it can).
set -euo pipefail
PORT=${PORT:-8080}
S=http://127.0.0.1:$PORT
WORK=$(mktemp -d)
NAMES=(www.portal.bank.internal api.portal.bank.internal)
export NO_PROXY=127.0.0.1,localhost,.bank.internal no_proxy=127.0.0.1,localhost,.bank.internal

grep -q "${NAMES[0]}" /etc/hosts || echo "127.0.0.1 ${NAMES[*]}" >> /etc/hosts

CERTADILLO_DATA_DIR=$WORK/data CERTADILLO_BOOTSTRAP_ADMIN_KEY=admin-key CERTADILLO_BASE_URL=$S \
  certadillo serve --port "$PORT" > "$WORK/server.log" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
for _ in $(seq 30); do curl -sf "$S/healthz" >/dev/null && break; sleep 0.5; done

A=(-H "X-API-Key: admin-key" -H "Content-Type: application/json")
curl -sf -X POST "${A[@]}" "$S/api/v1/teams" -d '{"name":"web","contact_email":"web@bank.example"}' >/dev/null
curl -sf -X POST "${A[@]}" "$S/api/v1/apps" -d '{"team_id":1,"name":"web-portal","environment":"dev","profile":"tls-server","allowed_domains":["*.portal.bank.internal"]}' >/dev/null
read -r KID HMAC < <(curl -sf -X POST "${A[@]}" "$S/api/v1/apps/1/acme-eab" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["kid"],d["hmac_key"])')

CB=(--config-dir "$WORK/cb" --work-dir "$WORK/cb" --logs-dir "$WORK/cb" --server "$S/acme/directory" --non-interactive)
certbot certonly --standalone --agree-tos -m pki@bank.example --key-type ecdsa \
  --eab-kid "$KID" --eab-hmac-key "$HMAC" -d "${NAMES[0]}" -d "${NAMES[1]}" "${CB[@]}"

LIVE=$WORK/cb/live/${NAMES[0]}
curl -sf "$S/pki/ca/root-ca.pem" > "$WORK/root.pem"
openssl verify -CAfile "$WORK/root.pem" -untrusted "$LIVE/chain.pem" "$LIVE/cert.pem"
openssl ocsp -issuer "$LIVE/chain.pem" -cert "$LIVE/cert.pem" -url "$S/pki/ocsp" -CAfile "$WORK/root.pem" | grep -q ": good"
echo "OCSP: good"
certbot revoke --cert-name "${NAMES[0]}" --reason keycompromise --no-delete-after-revoke "${CB[@]}"
openssl ocsp -issuer "$LIVE/chain.pem" -cert "$LIVE/cert.pem" -url "$S/pki/ocsp" -CAfile "$WORK/root.pem" | grep -q ": revoked"
echo "OCSP: revoked"
curl -sf "$S/pki/crl/issuing-ca-1.crl" | openssl crl -inform DER -noout -text | grep -q "$(openssl x509 -in "$LIVE/cert.pem" -noout -serial | cut -d= -f2)"
echo "CRL: contains revoked serial"
echo "interop OK"
