#!/usr/bin/env bash
# ACME interop with certbot for the Phase 2 features:
#   dns-01 through a split-horizon view (a local DNS server stands in for the
#   internal resolvers), a wildcard certificate, ARI: `certbot renew` leaves a
#   certificate alone until a renewal campaign pulls its window forward, then
#   renews it, and the campaign sees the replacement; finally the replaced
#   certificate is revoked and `certbot unregister` deactivates the account.
# Needs: certbot >= 4 (ARI), openssl, python3 with dnspython.
set -euo pipefail
# Fresh random API keys for this throwaway server; nothing reusable ends up in the repo or the logs.
ADMIN_KEY=$(openssl rand -hex 24)
PORT=${PORT:-8080}
DNSPORT=${DNSPORT:-5353}
S=http://127.0.0.1:$PORT
WORK=$(mktemp -d)
HERE=$(cd "$(dirname "$0")" && pwd)
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
echo '{}' > "$WORK/zone.json"

python3 "$HERE/tinydns.py" "$WORK/zone.json" "$DNSPORT" > "$WORK/dns.log" 2>&1 &
DNSPID=$!
CERTADILLO_DATA_DIR=$WORK/data CERTADILLO_BOOTSTRAP_ADMIN_KEY=$ADMIN_KEY CERTADILLO_BASE_URL=$S \
CERTADILLO_ACME_DNS_VIEWS="portal.bank.internal=127.0.0.1:$DNSPORT" \
  certadillo serve --port "$PORT" > "$WORK/server.log" 2>&1 &
SERVER=$!
trap 'kill $SERVER $DNSPID 2>/dev/null || true' EXIT
for _ in $(seq 30); do curl -sf "$S/healthz" >/dev/null && break; sleep 0.5; done

# certbot manual hooks: write and remove the TXT record in the zone file
cat > "$WORK/auth.sh" <<EOF
#!/usr/bin/env bash
python3 - "\$CERTBOT_DOMAIN" "\$CERTBOT_VALIDATION" <<'PY'
import json, sys
p = "$WORK/zone.json"; d = json.load(open(p))
d.setdefault("_acme-challenge." + sys.argv[1], {"TXT": []})["TXT"].append(sys.argv[2])
json.dump(d, open(p, "w"))
PY
EOF
cat > "$WORK/cleanup.sh" <<EOF
#!/usr/bin/env bash
python3 - "\$CERTBOT_DOMAIN" <<'PY'
import json, sys
p = "$WORK/zone.json"; d = json.load(open(p)); d.pop("_acme-challenge." + sys.argv[1], None)
json.dump(d, open(p, "w"))
PY
EOF
chmod +x "$WORK/auth.sh" "$WORK/cleanup.sh"

A=(-H "X-API-Key: $ADMIN_KEY" -H "Content-Type: application/json")
curl -sf -X POST "${A[@]}" "$S/api/v1/teams" -d '{"name":"web","contact_email":"web@bank.example"}' >/dev/null
curl -sf -X POST "${A[@]}" "$S/api/v1/apps" -d '{"team_id":1,"name":"portal-edge","environment":"dev","profile":"tls-wildcard","allowed_domains":["*.portal.bank.internal"]}' >/dev/null
read -r KID HMAC < <(curl -sf -X POST "${A[@]}" "$S/api/v1/apps/1/acme-eab" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["kid"],d["hmac_key"])')

CB=(--config-dir "$WORK/cb" --work-dir "$WORK/cb" --logs-dir "$WORK/cb" --server "$S/acme/directory" --non-interactive)
DNS01=(--manual --preferred-challenges dns --manual-auth-hook "$WORK/auth.sh" --manual-cleanup-hook "$WORK/cleanup.sh")
certbot certonly "${DNS01[@]}" --agree-tos -m pki@bank.example --key-type ecdsa \
  --eab-kid "$KID" --eab-hmac-key "$HMAC" -d '*.edge.portal.bank.internal' -d edge.portal.bank.internal \
  --cert-name edge "${CB[@]}"
grep -q "_acme-challenge.edge.portal.bank.internal -> NOERROR" "$WORK/dns.log"
LIVE=$WORK/cb/live/edge
curl -sf "$S/pki/ca/root-ca.pem" > "$WORK/root.pem"
openssl verify -CAfile "$WORK/root.pem" -untrusted "$LIVE/chain.pem" "$LIVE/cert.pem"
openssl x509 -in "$LIVE/cert.pem" -noout -ext subjectAltName | grep -q '\*.edge.portal.bank.internal'
echo "dns-01: wildcard issued through the internal view and verified"

OLD_SERIAL=$(openssl x509 -in "$LIVE/cert.pem" -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f' | sed 's/^0*//')
certbot renew --no-random-sleep-on-renew "${CB[@]}" > "$WORK/renew1.log" 2>&1
grep -qi "not yet due" "$WORK/renew1.log"
echo "ARI: not due yet, certbot left it alone"

CAMP=$(curl -sf -X POST "${A[@]}" "$S/api/v1/renewal-campaigns" -d "{\"name\":\"interop\",\"reason\":\"rotate before revoking\",\"criteria\":{\"serials\":[\"$OLD_SERIAL\"]},\"renew_within_hours\":24,\"immediate\":true}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
# certbot honours ARI's Retry-After (6 hours by default) and would not ask again
# yet; drop the remembered time to stand in for those hours passing
grep -q '^ari_retry_after' "$WORK/cb/renewal/edge.conf"
sed -i '/^ari_retry_after/d' "$WORK/cb/renewal/edge.conf"
certbot renew --no-random-sleep-on-renew "${CB[@]}" > "$WORK/renew2.log" 2>&1
NEW_SERIAL=$(openssl x509 -in "$LIVE/cert.pem" -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f' | sed 's/^0*//')
[ "$NEW_SERIAL" != "$OLD_SERIAL" ] || { echo "FAIL: certbot did not renew inside the ARI window"; cat "$WORK/renew2.log"; exit 1; }
STATE=$(curl -sf "${A[@]}" "$S/api/v1/renewal-campaigns/$CAMP" | python3 -c 'import json,sys;print(json.load(sys.stdin)["counts"])')
echo "$STATE" | grep -q "'replaced': 1" || { echo "FAIL: campaign did not see the replacement: $STATE"; exit 1; }
echo "ARI: campaign window made certbot renew; campaign counts $STATE"
if curl -sf "${A[@]}" "$S/api/v1/audit?limit=50" | grep -q '"action":"certificate.renew"'; then
  echo "ARI: certbot sent replaces; the order was linked to the old certificate"
fi

OUT=$(curl -sf -X POST "${A[@]}" "$S/api/v1/renewal-campaigns/$CAMP/revoke-replaced" -d '{}')
[ "$OUT" = '{"revoked":1}' ] || { echo "FAIL: revoke-replaced returned $OUT"; exit 1; }
openssl ocsp -issuer "$LIVE/chain.pem" -cert "$LIVE/cert.pem" -url "$S/pki/ocsp" -CAfile "$WORK/root.pem" | grep -q ": good"
echo "ARI: replaced certificate revoked; the new one is still good"

certbot unregister "${CB[@]}" >/dev/null
curl -sf "${A[@]}" "$S/api/v1/audit?limit=5" | grep -q acme.account.deactivate
echo "account deactivated"
echo "interop OK"
