#!/usr/bin/env bash
# End-to-end SCEP interop with micromdm scepclient (Go, RFC 8894):
# one-time challenge -> GetCACaps/GetCACert -> PKIOperation -> issued cert
# verified with openssl; then challenge reuse and an out-of-scope name must fail.
# scepclient 2.3 encrypts requests with single DES, so this run enables
# CERTADILLO_SCEP_ALLOW_DES. Leave it off in production unless such clients exist.
set -euo pipefail
PORT=${PORT:-8080}
S=http://127.0.0.1:$PORT
WORK=$(mktemp -d)
VER=v2.3.0
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost

CLIENT=${SCEPCLIENT:-$(command -v scepclient || true)}
if [ -z "$CLIENT" ]; then
  curl -sSL -o "$WORK/scep.zip" "https://github.com/micromdm/scep/releases/download/$VER/scepclient-linux-amd64-$VER.zip"
  unzip -q "$WORK/scep.zip" -d "$WORK" && CLIENT=$WORK/scepclient-linux-amd64 && chmod +x "$CLIENT"
fi

CERTADILLO_DATA_DIR=$WORK/data CERTADILLO_BOOTSTRAP_ADMIN_KEY=admin-key CERTADILLO_BASE_URL=$S \
CERTADILLO_SCEP_ALLOW_DES=true certadillo serve --port "$PORT" > "$WORK/server.log" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
for _ in $(seq 30); do curl -sf "$S/healthz" >/dev/null && break; sleep 0.5; done

A=(-H "X-API-Key: admin-key" -H "Content-Type: application/json")
curl -sf -X POST "${A[@]}" "$S/api/v1/teams" -d '{"name":"network","contact_email":"net@bank.example"}' >/dev/null
curl -sf -X POST "${A[@]}" "$S/api/v1/apps" -d '{"team_id":1,"name":"branch-routers","environment":"dev","profile":"tls-client","allowed_domains":["*.routers.bank.internal"]}' >/dev/null
challenge() { curl -sf -X POST "${A[@]}" "$S/api/v1/apps/1/scep-challenge" | python3 -c 'import json,sys;print(json.load(sys.stdin)["challenge"])'; }

enroll() { # cn challenge
  rm -f "$WORK"/key.pem "$WORK"/cert.pem "$WORK"/csr.pem "$WORK"/self.pem
  (cd "$WORK" && "$CLIENT" -server-url "$S/scep" -challenge "$2" -cn "$1" -dnsname "$1" \
      -private-key key.pem -certificate cert.pem -key-encipherment-selector >/dev/null 2>&1) || true
  [ -f "$WORK/cert.pem" ]
}

CH=$(challenge)
enroll rtr-0042.routers.bank.internal "$CH"
curl -sf "$S/pki/ca/root-ca.pem" > "$WORK/root.pem"
curl -sf "$S/pki/ca/issuing-ca-1.pem" > "$WORK/issuing.pem"
openssl verify -CAfile "$WORK/root.pem" -untrusted "$WORK/issuing.pem" "$WORK/cert.pem"
echo "SCEP: issued and verified"
if enroll rtr-0043.routers.bank.internal "$CH"; then echo "FAIL: challenge was reusable"; exit 1; fi
echo "SCEP: reused challenge refused"
if enroll evil.other.example "$(challenge)"; then echo "FAIL: out-of-scope name issued"; exit 1; fi
echo "SCEP: out-of-scope name refused"
echo "interop OK"
