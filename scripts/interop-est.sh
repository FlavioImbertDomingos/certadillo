#!/usr/bin/env bash
# EST interop with the GlobalSign estclient (Go, RFC 7030) through nginx, the
# way it runs in production: nginx terminates TLS, asks for a client
# certificate and forwards it to Certadillo in X-SSL-Client-Cert together with
# a shared secret. Covers cacerts, csrattrs, enroll with HTTP Basic, re-enroll
# with a new key authenticated only by the current certificate, serverkeygen,
# and a device bootstrapping with a manufacturer (IDevID) certificate.
# Needs: nginx, openssl, go (for estclient), root (edits /etc/hosts).
set -euo pipefail
PORT=${PORT:-8080}
TLSPORT=${TLSPORT:-8443}
S=http://127.0.0.1:$PORT
EST=est.bank.internal:$TLSPORT
WORK=$(mktemp -d)
SECRET=$(openssl rand -hex 16)
export NO_PROXY=127.0.0.1,localhost,.bank.internal no_proxy=127.0.0.1,localhost,.bank.internal
grep -q "est.bank.internal" /etc/hosts || echo "127.0.0.1 est.bank.internal" >> /etc/hosts

EC=${ESTCLIENT:-$(command -v estclient || echo "$(go env GOPATH)/bin/estclient")}
[ -x "$EC" ] || go install github.com/globalsign/est/cmd/estclient@latest

CERTADILLO_DATA_DIR=$WORK/data CERTADILLO_BOOTSTRAP_ADMIN_KEY=admin-key CERTADILLO_BASE_URL=$S \
CERTADILLO_EST_CLIENT_CERT_HEADER=X-SSL-Client-Cert CERTADILLO_EST_PROXY_SECRET=$SECRET \
  certadillo serve --port "$PORT" > "$WORK/server.log" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true; [ -f "$WORK/nginx.pid" ] && kill "$(cat "$WORK/nginx.pid")" 2>/dev/null || true' EXIT
for _ in $(seq 30); do curl -sf "$S/healthz" >/dev/null && break; sleep 0.5; done

A=(-H "X-API-Key: admin-key" -H "Content-Type: application/json")
j() { python3 -c "import json,sys;print(json.load(sys.stdin)$1)"; }
curl -sf -X POST "${A[@]}" "$S/api/v1/teams" -d '{"name":"devices","contact_email":"iot@bank.example"}' >/dev/null
# the EST endpoint's own TLS certificate comes from Certadillo too
curl -sf -X POST "${A[@]}" "$S/api/v1/apps" -d '{"team_id":1,"name":"est-gateway","environment":"dev","profile":"tls-server","allowed_domains":["est.bank.internal"]}' >/dev/null
GW=$(curl -sf -X POST "${A[@]}" "$S/api/v1/apps/1/credentials" | j '["api_key"]')
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$WORK/tls.key" -subj /CN=est.bank.internal \
  -addext subjectAltName=DNS:est.bank.internal -out "$WORK/tls.csr" 2>/dev/null
python3 - "$WORK" "$S" "$GW" <<'PY'
import json, sys, urllib.request
work, s, key = sys.argv[1:]
req = urllib.request.Request(s + "/api/v1/certificates", method="POST",
      data=json.dumps({"csr_pem": open(work + "/tls.csr").read()}).encode(),
      headers={"X-API-Key": key, "Content-Type": "application/json"})
d = json.load(urllib.request.urlopen(req))
open(work + "/tls.crt", "w").write(d["pem"] + d["chain_pem"])
PY
curl -sf "$S/pki/ca/root-ca.pem" > "$WORK/root.pem"

cat > "$WORK/nginx.conf" <<EOF
pid $WORK/nginx.pid;
error_log $WORK/nginx-error.log;
events {}
http {
  access_log $WORK/nginx-access.log;
  server {
    listen 127.0.0.1:$TLSPORT ssl;
    server_name est.bank.internal;
    ssl_certificate $WORK/tls.crt;
    ssl_certificate_key $WORK/tls.key;
    # ask for a client certificate; TLS proves the client holds its key,
    # Certadillo decides whether the issuer is one it trusts
    ssl_verify_client optional_no_ca;
    location /.well-known/est/ {
      proxy_pass http://127.0.0.1:$PORT;
      proxy_set_header Host \$host;
      proxy_set_header X-SSL-Client-Cert \$ssl_client_escaped_cert;
      proxy_set_header X-Certadillo-Proxy-Auth $SECRET;
    }
  }
}
EOF
nginx -c "$WORK/nginx.conf"
sleep 0.5
E=(-server "$EST" -explicit "$WORK/root.pem")

"$EC" cacerts "${E[@]}" -out "$WORK/cacerts.pem"
grep -c "BEGIN CERTIFICATE" "$WORK/cacerts.pem" | grep -q 2
echo "EST: cacerts over TLS"

curl -sf -X POST "${A[@]}" "$S/api/v1/apps" -d '{"team_id":1,"name":"atm-fleet","environment":"dev","profile":"tls-client","allowed_domains":["*.atm.bank.internal"]}' >/dev/null
APPKEY=$(curl -sf -X POST "${A[@]}" "$S/api/v1/apps/2/credentials" | j '["api_key"]')
"$EC" csrattrs "${E[@]}" -user atm -pass "$APPKEY" > "$WORK/csrattrs.txt"
grep -q "1.2.840.10045.2.1" "$WORK/csrattrs.txt" && echo "EST: csrattrs asks for an EC key"

openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/k1.pem"
"$EC" enroll "${E[@]}" -user atm -pass "$APPKEY" -key "$WORK/k1.pem" -cn atm-7.atm.bank.internal -out "$WORK/c1.pem"
openssl verify -CAfile "$WORK/root.pem" -untrusted "$WORK/cacerts.pem" "$WORK/c1.pem" >/dev/null
echo "EST: enrolled with HTTP Basic"

openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/k2.pem"
"$EC" csr -key "$WORK/k2.pem" -cn atm-7.atm.bank.internal -out "$WORK/c2.csr"
"$EC" reenroll "${E[@]}" -certs "$WORK/c1.pem" -key "$WORK/k1.pem" -csr "$WORK/c2.csr" -out "$WORK/c2.pem"
[ "$(openssl x509 -in "$WORK/c1.pem" -noout -serial)" != "$(openssl x509 -in "$WORK/c2.pem" -noout -serial)" ]
curl -sf "${A[@]}" "$S/api/v1/audit?limit=20" | grep -q '"auth":"certificate","reenroll":true'
echo "EST: re-enrolled with a new key, authenticated by the TLS client certificate alone"
if "$EC" reenroll "${E[@]}" -certs "$WORK/c1.pem" -key "$WORK/k1.pem" -csr "$WORK/c2.csr" -out "$WORK/x.pem" 2>/dev/null; then
  echo "FAIL: the superseded certificate still authenticates"; exit 1
fi
echo "EST: the replaced certificate no longer authenticates"

"$EC" serverkeygen "${E[@]}" -user atm -pass "$APPKEY" -cn sensor-3.atm.bank.internal \
  -key "$WORK/k2.pem" -out "$WORK/skg.pem" -keyout "$WORK/skg.key"
[ "$(openssl x509 -in "$WORK/skg.pem" -noout -pubkey)" = "$(openssl pkey -in "$WORK/skg.key" -pubout)" ]
echo "EST: serverkeygen returned a key and its certificate"

# a device with only a manufacturer certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$WORK/mfr.key" -out "$WORK/mfr.pem" \
  -subj "/O=Acme Devices/CN=Acme Devices IDevID CA" -days 3650 -addext basicConstraints=critical,CA:true 2>/dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$WORK/idev.key" -subj /serialNumber=SN-451 \
  -out "$WORK/idev.csr" 2>/dev/null
openssl x509 -req -in "$WORK/idev.csr" -CA "$WORK/mfr.pem" -CAkey "$WORK/mfr.key" -CAcreateserial -days 3650 \
  -out "$WORK/idev.pem" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/k3.pem"
"$EC" csr -key "$WORK/k3.pem" -cn atm-451.atm.bank.internal -out "$WORK/c3.csr"
if "$EC" enroll "${E[@]}" -certs "$WORK/idev.pem" -key "$WORK/idev.key" -csr "$WORK/c3.csr" -out "$WORK/c3.pem" 2>/dev/null; then
  echo "FAIL: an unknown manufacturer certificate was accepted"; exit 1
fi
python3 -c "import json;print(json.dumps({'name':'acme-devices','cert_pem':open('$WORK/mfr.pem').read()}))" \
  | curl -sf -X POST "${A[@]}" "$S/api/v1/apps/2/est-trust-anchors" -d @- >/dev/null
"$EC" enroll "${E[@]}" -certs "$WORK/idev.pem" -key "$WORK/idev.key" -csr "$WORK/c3.csr" -out "$WORK/c3.pem"
openssl verify -CAfile "$WORK/root.pem" -untrusted "$WORK/cacerts.pem" "$WORK/c3.pem" >/dev/null
echo "EST: device bootstrapped with its manufacturer certificate"
echo "interop OK"
