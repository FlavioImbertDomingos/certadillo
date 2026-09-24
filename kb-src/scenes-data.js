/* Scene definitions: actors on the platform, then steps made of moves.
 * move: {from, to, label, sub, kind: request|response|secret|reject|local, effect, dilly, local}
 * effect: check | sign | hsm | store | reject | burn | unlock */
(function () {
  "use strict";
  var S = window.CertadilloScenes;

  // ------------------------------------------------------------------ ACME
  S.register({
    id: "acme",
    title: "ACME with certbot (http-01)",
    dilly: "ra",
    chainAt: "db",
    chainOffset: [1.2, 0.2],
    camera: { theta: 0.35, phi: 1.1, radius: 20.5 },
    actors: [
      { id: "operator", kind: "person", label: "PKI operator", sub: "onboarding", x: -2.2, z: 6.8 },
      { id: "certbot", kind: "laptop", label: "certbot", sub: "on www.portal", x: -6.8, z: 2.4, anchorY: 0.8 },
      { id: "web", kind: "server", label: "Web server :80", sub: "serves the token", x: -5.6, z: -3.8, anchorY: 1.1 },
      { id: "acme", kind: "gateway", label: "Certadillo ACME", sub: "/acme/*", x: -0.6, z: 0.4, anchorY: 1.5 },
      { id: "ra", kind: "shield", label: "RA + policy", sub: "scope · keys · validity", x: 3.4, z: -4.2, anchorY: 1.2 },
      { id: "ca", kind: "ca", label: "Issuing CA", sub: "issuing-ca-1 · P-384", x: 6.9, z: -0.8, anchorY: 1.6, labelY: 3.0 },
      { id: "hsm", kind: "hsm", label: "HSM", sub: "PKCS#11 · non-extractable", x: 6.4, z: 3.4, anchorY: 0.6, labelY: 1.5 },
      { id: "db", kind: "db", label: "Inventory + audit", sub: "hash-chained events", x: 2.2, z: 5.6, anchorY: 1.1 }
    ],
    steps: [
      {
        phase: "Onboarding", title: "Mint an EAB credential for the app",
        body: "Before any ACME traffic, an operator mints a single-use External Account Binding credential for the onboarded app web-portal. It ties the future ACME account to the app, so every order inherits the app's approved names and profile.",
        payload: "POST /api/v1/apps/3/acme-eab\nX-API-Key: <operator key>\n\n201 Created\n{\n  \"kid\": \"eab_ea1ae05c6517f939\",\n  \"hmac_key\": \"oh7sIaV_ZUzExOL24qDutXJfRwAHF4OL1X-ZjiXUWO8\"\n}",
        moves: [
          { from: "operator", to: "acme", label: "POST /apps/3/acme-eab" },
          { from: "acme", to: "db", label: "audit: acme.eab.create", kind: "response", effect: "store" },
          { from: "acme", to: "operator", label: "kid + hmac_key", kind: "secret" }
        ]
      },
      {
        phase: "Discovery", title: "Read the directory",
        body: "certbot starts from one URL. The directory lists every endpoint and says an external account is required.",
        payload: "GET /acme/directory\n\n{\n  \"newNonce\":   \"https://pki.bank.internal/acme/new-nonce\",\n  \"newAccount\": \"https://pki.bank.internal/acme/new-account\",\n  \"newOrder\":   \"https://pki.bank.internal/acme/new-order\",\n  \"revokeCert\": \"https://pki.bank.internal/acme/revoke-cert\",\n  \"meta\": { \"externalAccountRequired\": true }\n}",
        moves: [
          { from: "certbot", to: "acme", label: "GET /acme/directory" },
          { from: "acme", to: "certbot", label: "endpoints", kind: "response" }
        ]
      },
      {
        phase: "Discovery", title: "Get a replay nonce",
        body: "Every signed ACME request carries a fresh nonce. Certadillo marks a nonce spent before it processes the request, so a captured request cannot be replayed.",
        payload: "HEAD /acme/new-nonce\n\n200 OK\nReplay-Nonce: oQ3xK1vX2d6Hq9tYb0mR3w\nCache-Control: no-store",
        moves: [
          { from: "certbot", to: "acme", label: "HEAD /new-nonce" },
          { from: "acme", to: "certbot", label: "Replay-Nonce", kind: "response" }
        ]
      },
      {
        phase: "Account", title: "Register the account with EAB",
        body: "certbot generates an account key, signs the request with it (JWS, ES256), and embeds the EAB: its JWK signed with the HMAC key. Certadillo checks the HMAC, burns the EAB credential and binds the account to the app.",
        payload: "POST /acme/new-account\nContent-Type: application/jose+json\n\nprotected: {\"alg\":\"ES256\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",...},\n            \"nonce\":\"oQ3x...\",\"url\":\".../acme/new-account\"}\npayload:   {\"termsOfServiceAgreed\":true,\n            \"externalAccountBinding\":{\n              \"protected\":{\"alg\":\"HS256\",\"kid\":\"eab_ea1a...\",\"url\":\"...\"},\n              \"payload\": <account JWK>, \"signature\": <HMAC-SHA256>}}\n\n201 Created   Location: .../acme/acct/1",
        moves: [
          { from: "certbot", to: "acme", label: "POST /new-account", sub: "JWS + EAB" },
          { from: "acme", to: "ra", label: "verify EAB HMAC", effect: "check" },
          { from: "ra", to: "db", label: "account 1 -> app web-portal", kind: "response", effect: "store" },
          { from: "acme", to: "certbot", label: "201 acct/1", kind: "response" }
        ]
      },
      {
        phase: "Order", title: "Order two names",
        body: "The order lists the DNS names. Certadillo checks them against the app's scope (*.portal.bank.internal) before creating any challenge, then returns one authorization per name.",
        payload: "POST /acme/new-order   (JWS, kid = .../acme/acct/1)\npayload: {\"identifiers\":[\n  {\"type\":\"dns\",\"value\":\"www.portal.bank.internal\"},\n  {\"type\":\"dns\",\"value\":\"api.portal.bank.internal\"}]}\n\n201 Created   Location: .../acme/order/7\n{\"status\":\"pending\",\n \"authorizations\":[\".../authz/11\",\".../authz/12\"],\n \"finalize\":\".../acme/order/7/finalize\"}",
        moves: [
          { from: "certbot", to: "acme", label: "POST /new-order" },
          { from: "acme", to: "ra", label: "scope check", sub: "*.portal.bank.internal", effect: "check", dilly: "happy" },
          { from: "acme", to: "certbot", label: "order 7: pending", kind: "response" }
        ]
      },
      {
        phase: "Order", title: "What an out-of-scope order looks like",
        body: "If the account asks for a name the app never had, the order is refused at once with rejectedIdentifier and the attempt goes into the audit trail. No challenge is ever created for it.",
        payload: "POST /acme/new-order\npayload: {\"identifiers\":[{\"type\":\"dns\",\"value\":\"www.google.com\"}]}\n\n403\n{\"type\":\"urn:ietf:params:acme:error:rejectedIdentifier\",\n \"detail\":\"outside app scope: www.google.com\"}",
        moves: [
          { from: "certbot", to: "acme", label: "new-order www.google.com" },
          { from: "acme", to: "ra", label: "scope check", effect: "reject", dilly: "worried" },
          { from: "ra", to: "db", label: "audit: certificate.rejected", kind: "reject", effect: "store" },
          { from: "acme", to: "certbot", label: "403 rejectedIdentifier", kind: "reject" }
        ]
      },
      {
        phase: "Challenge", title: "Fetch the http-01 challenge",
        body: "For each authorization certbot receives a random token. The key authorization is the token joined to the thumbprint of the account key.",
        payload: "POST /acme/authz/11   (POST-as-GET)\n\n{\"status\":\"pending\",\n \"identifier\":{\"type\":\"dns\",\"value\":\"www.portal.bank.internal\"},\n \"challenges\":[{\"type\":\"http-01\",\n   \"url\":\".../acme/chall/11\",\n   \"token\":\"LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0\"}]}",
        moves: [
          { from: "certbot", to: "acme", label: "POST /authz/11", dilly: "happy" },
          { from: "acme", to: "certbot", label: "token", kind: "response" }
        ]
      },
      {
        phase: "Challenge", title: "Serve the key authorization",
        body: "certbot (standalone or webroot) publishes the key authorization on port 80 at a well-known path.",
        payload: "/.well-known/acme-challenge/LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0\n\nLoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0.9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI",
        moves: [
          { from: "certbot", to: "web", label: "token.thumbprint", kind: "local" }
        ]
      },
      {
        phase: "Challenge", title: "Validate http-01",
        body: "certbot tells Certadillo it is ready. Certadillo fetches the path over HTTP from where it runs (off the event loop, so a slow host only delays its own order), compares in constant time, and marks the authorization valid. With CERTADILLO_ACME_CHALLENGE=ra-scope this network check is skipped for names already in scope.",
        payload: "POST /acme/chall/11   payload: {}\n\nCertadillo -> GET http://www.portal.bank.internal/.well-known/acme-challenge/LoqX...\n          <- LoqX....9jg46WB3...\n\n{\"type\":\"http-01\",\"status\":\"valid\",\"validated\":\"2026-09-23T22:31:39Z\"}",
        moves: [
          { from: "certbot", to: "acme", label: "POST /chall/11" },
          { from: "acme", to: "web", label: "GET /.well-known/acme-challenge/..." },
          { from: "web", to: "acme", label: "key authorization", kind: "response", effect: "check" }
        ]
      },
      {
        phase: "Issue", title: "Finalize with a CSR",
        body: "certbot generates the certificate key locally and sends a CSR. The RA runs the same policy as every other protocol: proof of possession, P-256 allowed, both SANs in scope, 30-day default validity. The issuing CA builds the certificate and the HSM signs its to-be-signed bytes; the CA key never leaves the HSM.",
        payload: "POST /acme/order/7/finalize\npayload: {\"csr\": \"MIIBJjCBzQIBADAjMSEwHwYDVQQDDBh3d3cucG9ydGFsLmJhbmsu...\"}\n\nPolicy: csr_signature ok · key ec-256 ok · SAN www/api.portal.bank.internal in scope\n        validity 30d <= 90d · profile tls-server\nHSM:    C_Sign(CKM_ECDSA, SHA-384(tbsCertificate)) -> (r, s)",
        moves: [
          { from: "certbot", to: "acme", label: "POST /finalize", sub: "CSR" },
          { from: "acme", to: "ra", label: "policy engine", effect: "check" },
          { from: "ra", to: "ca", label: "build certificate" },
          { from: "ca", to: "hsm", label: "sign TBS digest", kind: "secret", effect: "hsm" },
          { from: "hsm", to: "ca", label: "ECDSA signature", kind: "response", effect: "sign" }
        ]
      },
      {
        phase: "Issue", title: "Record it",
        body: "The certificate row and its audit event commit in one transaction. The audit event extends the SHA-256 hash chain (the stack of blocks). Prometheus sees the new expiry gauge on its next scrape, labelled with app, team and environment.",
        payload: "audit_event {\n  actor: \"acme:1:web-portal\", action: \"certificate.issue\",\n  target: \"7b4c294dac830d452407acffe8492c99a84d2bd6\",\n  details: {protocol: \"acme\", profile: \"tls-server\", not_after: \"2026-10-23\"},\n  prev_hash: \"5f1c...\", hash: \"a93e...\"\n}\ncertadillo_issuance_total{profile=\"tls-server\",protocol=\"acme\",result=\"issued\"} += 1",
        moves: [
          { from: "ca", to: "db", label: "certificate + audit event", kind: "response", effect: "store" }
        ]
      },
      {
        phase: "Issue", title: "Download the chain",
        body: "certbot downloads the leaf plus the issuing CA and installs it. The root is distributed out of band to relying parties.",
        payload: "POST /acme/cert/42   (POST-as-GET)\nContent-Type: application/pem-certificate-chain\n\n-----BEGIN CERTIFICATE-----   (www.portal.bank.internal, 30 days)\n-----BEGIN CERTIFICATE-----   (Example Bank Issuing CA issuing-ca-1)",
        moves: [
          { from: "certbot", to: "acme", label: "POST /cert/42" },
          { from: "acme", to: "certbot", label: "PEM chain", kind: "response" }
        ]
      },
      {
        phase: "Renew", title: "Renew at two-thirds of the lifetime",
        body: "certbot's timer renews with a new key around day 20 of 30, reusing the account, so no new EAB is needed. If that timer ever stops, the lifetime-aware alert fires at 10 days left (warning) and 3 days left (critical), routed to the web team.",
        payload: "systemd: certbot.timer -> certbot renew\nnew order -> new CSR (new key) -> new certificate\nold certificate: status superseded, replaced_by = 43",
        moves: [
          { from: "certbot", to: "acme", label: "certbot renew" },
          { from: "acme", to: "db", label: "old -> superseded", kind: "response", effect: "store" },
          { from: "acme", to: "certbot", label: "new chain", kind: "response" }
        ]
      }
    ]
  });

  // ------------------------------------------------------------------ EST + SCEP
  S.register({
    id: "devices",
    title: "EST and SCEP for devices",
    dilly: "ra",
    chainAt: "db",
    chainOffset: [1.2, 0.2],
    camera: { theta: 0.2, phi: 1.1, radius: 21.0 },
    actors: [
      { id: "atm", kind: "atm", label: "ATM fleet", sub: "EST client", x: -7.0, z: 2.6, anchorY: 1.3 },
      { id: "router", kind: "router", label: "Branch router", sub: "SCEP client", x: -6.2, z: -3.6, anchorY: 0.5, labelY: 1.7 },
      { id: "mdm", kind: "cloud", label: "MDM / operator", sub: "mints challenges", x: -1.6, z: -7.0, anchorY: 0.9, labelY: 1.9 },
      { id: "est", kind: "gateway", label: "EST endpoint", sub: "/.well-known/est", x: -1.6, z: 3.2, anchorY: 1.5 },
      { id: "scep", kind: "gateway", label: "SCEP endpoint", sub: "/scep · RSA RA cert", x: -0.4, z: -2.4, anchorY: 1.5 },
      { id: "ra", kind: "shield", label: "RA + policy", sub: "same rules as ACME", x: 3.6, z: 0.2, anchorY: 1.2 },
      { id: "ca", kind: "ca", label: "Issuing CA", sub: "issuing-ca-1", x: 7.0, z: -2.6, anchorY: 1.6, labelY: 3.0 },
      { id: "hsm", kind: "hsm", label: "HSM", sub: "CA key", x: 7.1, z: 1.4, anchorY: 0.6, labelY: 1.5 },
      { id: "db", kind: "db", label: "Inventory + audit", x: 3.4, z: 5.4, anchorY: 1.1 }
    ],
    steps: [
      {
        phase: "EST", title: "Get the CA certificates",
        body: "An ATM starts by fetching the trust anchors. EST answers with a base64 PKCS#7 certs-only bundle: the root and the issuing CA.",
        payload: "GET /.well-known/est/cacerts\n\n200 application/pkcs7-mime; smime-type=certs-only\nContent-Transfer-Encoding: base64\n\nMIIF6QYJKoZIhvcNAQcCoIIF2jCCBdYCAQExADALBgkqhkiG9w0BBwGgggW+...",
        moves: [
          { from: "atm", to: "est", label: "GET /cacerts" },
          { from: "est", to: "atm", label: "PKCS#7: root + issuing", kind: "response" }
        ]
      },
      {
        phase: "EST", title: "Enroll with the app credential",
        body: "The ATM generates its key, sends a base64 PKCS#10 CSR, and authenticates with HTTP Basic where the password is the app's API key. The RA checks the CN against *.atm.bank.internal and the tls-client profile, the HSM signs, and the certificate comes back as PKCS#7.",
        payload: "POST /.well-known/est/simpleenroll\nAuthorization: Basic YXRtLTAwNDI6Y2RsXy4uLg==      (atm-0042:<app key>)\nContent-Type: application/pkcs10\n\nMIIBBDCBqwIBADAlMSMwIQYDVQQDDBphdG0tMDA0Mi5hdG0uYmFuay5pbnRlcm5h...\n\n200 application/pkcs7-mime   (CN=atm-0042.atm.bank.internal, 30 days)",
        moves: [
          { from: "atm", to: "est", label: "POST /simpleenroll", sub: "Basic + PKCS#10" },
          { from: "est", to: "ra", label: "policy: tls-client", effect: "check", dilly: "happy" },
          { from: "ra", to: "ca", label: "build certificate" },
          { from: "ca", to: "hsm", label: "sign", kind: "secret", effect: "hsm" },
          { from: "ca", to: "db", label: "store + audit", kind: "response", effect: "store" },
          { from: "est", to: "atm", label: "PKCS#7 certificate", kind: "response" }
        ]
      },
      {
        phase: "EST", title: "Re-enroll with a new key",
        body: "Before expiry the ATM sends a CSR with the same subject and a new key to simplereenroll. Certadillo finds its current certificate by app and CN, issues the new one and marks the old one superseded. Reusing the old key is refused (key_reuse).",
        payload: "POST /.well-known/est/simplereenroll\nAuthorization: Basic ...\n\n200   new certificate\ncertificate 18: status superseded, replaced_by 21",
        moves: [
          { from: "atm", to: "est", label: "POST /simplereenroll" },
          { from: "est", to: "ra", label: "new key? same subject?", effect: "check" },
          { from: "ra", to: "db", label: "old -> superseded", kind: "response", effect: "store" },
          { from: "est", to: "atm", label: "new certificate", kind: "response" }
        ]
      },
      {
        phase: "SCEP", title: "Mint a one-time challenge",
        body: "For SCEP, the MDM (or an operator) asks Certadillo for a challenge password for this one device, exactly as the Intune connector asks NDES. Only a hash is stored; the challenge works once and expires after 60 minutes.",
        payload: "POST /api/v1/apps/7/scep-challenge?ttl_minutes=60\n\n201\n{\"challenge\": \"90b0eb873c1e68e462ea7aeca645b992\",\n \"expires\": \"2026-09-24T00:19:27Z\",\n \"server_url\": \"https://pki.bank.internal/scep\"}",
        moves: [
          { from: "mdm", to: "scep", label: "POST /scep-challenge" },
          { from: "scep", to: "db", label: "store sha256(challenge)", kind: "response", effect: "store" },
          { from: "scep", to: "mdm", label: "challenge", kind: "secret" },
          { from: "mdm", to: "router", label: "profile with challenge", kind: "secret" }
        ]
      },
      {
        phase: "SCEP", title: "GetCACaps and GetCACert",
        body: "The router asks what the server supports, then fetches the certificates. GetCACert returns the SCEP RA certificate (RSA-3072, because SCEP encrypts with RSA key transport) and the issuing CA.",
        payload: "GET /scep?operation=GetCACaps\n  POSTPKIOperation  SHA-256  SHA-512  AES  SCEPStandard\n\nGET /scep?operation=GetCACert\n  application/x-x509-ca-ra-cert\n  [SCEP RA issuing-ca-1 (RSA-3072, keyEncipherment), Issuing CA (P-384)]",
        moves: [
          { from: "router", to: "scep", label: "GetCACaps / GetCACert" },
          { from: "scep", to: "router", label: "RA cert + CA", kind: "response" }
        ]
      },
      {
        phase: "SCEP", title: "Build the pkiMessage",
        body: "The router creates a key and a CSR containing the challenge password, encrypts the CSR to the RA certificate (EnvelopedData), and signs the whole message with a throwaway self-signed certificate (SignedData) carrying the transaction ID and a nonce.",
        payload: "ContentInfo SignedData {\n  signerInfo: self-signed CN=rtr-0042, sha256WithRSA\n  signedAttrs: messageType=19 (PKCSReq), transactionID, senderNonce\n  content: EnvelopedData {\n    recipient: SCEP RA cert (RSA key transport)\n    encryptedContent: CSR {CN=rtr-0042.routers.bank.internal,\n                           challengePassword=90b0eb87...}\n  }\n}",
        moves: [
          { from: "router", to: "router", local: true, label: "encrypt + sign", effect: "sign" }
        ]
      },
      {
        phase: "SCEP", title: "PKIOperation: decrypt, redeem, issue",
        body: "Certadillo verifies the message signature and messageDigest, decrypts the envelope with the RA key, and redeems the challenge (it is burned even if policy later fails, which stops guessing). Then the usual RA checks run and the HSM signs.",
        payload: "POST /scep?operation=PKIOperation   (application/x-pki-message)\n\nverify signature over signedAttrs ....... ok\nmessageDigest == sha256(content) ........ ok\ndecrypt EnvelopedData with RA key ....... AES-128-CBC ok\nredeem challenge 90b0eb87... ............ used = true\npolicy tls-client, CN in *.routers ...... ok",
        moves: [
          { from: "router", to: "scep", label: "PKIOperation (PKCSReq)", kind: "secret" },
          { from: "scep", to: "scep", local: true, label: "decrypt", effect: "unlock" },
          { from: "scep", to: "db", label: "burn challenge", kind: "reject", effect: "burn" },
          { from: "scep", to: "ra", label: "policy", effect: "check" },
          { from: "ra", to: "ca", label: "build certificate" },
          { from: "ca", to: "hsm", label: "sign", kind: "secret", effect: "hsm" },
          { from: "ca", to: "db", label: "store + audit", kind: "response", effect: "store" }
        ]
      },
      {
        phase: "SCEP", title: "CertRep back to the device",
        body: "The reply is SignedData from the RA with pkiStatus SUCCESS and the device's nonce echoed back. Inside, the new certificate is encrypted to the router's own key, so only that router can open it.",
        payload: "CertRep SignedData (signed by SCEP RA) {\n  messageType=3, pkiStatus=0 (SUCCESS),\n  transactionID=<same>, recipientNonce=<router's senderNonce>\n  content: EnvelopedData -> router key {\n    certs-only PKCS#7: CN=rtr-0042.routers.bank.internal (tls-client, 30d)\n  }\n}",
        moves: [
          { from: "scep", to: "router", label: "CertRep SUCCESS", kind: "secret" },
          { from: "router", to: "router", local: true, label: "decrypt + install", effect: "check" }
        ]
      },
      {
        phase: "SCEP", title: "A replayed challenge is refused",
        body: "If the same challenge is used again (a cloned config, an attacker), Certadillo answers with a signed FAILURE (badRequest) and writes the reason to the audit trail.",
        payload: "CertRep {messageType=3, pkiStatus=2 (FAILURE), failInfo=2 (badRequest)}\naudit: certificate.rejected {protocol: scep,\n  reason: \"SCEP challenge password is unknown, used or expired\"}",
        moves: [
          { from: "router", to: "scep", label: "PKIOperation (same challenge)", kind: "secret" },
          { from: "scep", to: "db", label: "challenge already used", kind: "reject", effect: "reject", dilly: "worried" },
          { from: "scep", to: "db", label: "audit: rejected", kind: "reject", effect: "store" },
          { from: "scep", to: "router", label: "FAILURE badRequest", kind: "reject" }
        ]
      },
      {
        phase: "SCEP", title: "Renewal signed by the current certificate",
        body: "Before expiry the router sends RenewalReq (messageType 17), signed with its current certificate instead of a throwaway one. No challenge is needed: the signature is the authentication. The name must stay the same, the key must be new, and the old certificate is superseded.",
        payload: "GetCACaps: POSTPKIOperation Renewal SHA-256 SHA-512 AES SCEPStandard\n\nPKIOperation SignedData (signed by CN=rtr-0042, issued by issuing-ca-1) {\n  messageType=17 (RenewalReq), content: EnvelopedData(CSR, new key) -> RA }\n-> CertRep SUCCESS   old serial: superseded",
        moves: [
          { from: "router", to: "scep", label: "RenewalReq", sub: "signed by current cert", kind: "secret" },
          { from: "scep", to: "ra", label: "current cert + same name", effect: "check", dilly: "happy" },
          { from: "ra", to: "ca", label: "sign", effect: "sign" },
          { from: "scep", to: "router", label: "CertRep SUCCESS", kind: "secret" }
        ]
      },
      {
        phase: "SCEP", title: "PENDING until a second person approves",
        body: "For a profile under dual control the first answer is PENDING. The device polls with CertPoll (or, like micromdm scepclient, by sending the same request again). Only the key that made the request gets the answer, once an approver has decided.",
        payload: "CertRep {pkiStatus=3 (PENDING)}          approval #58 created\n... 30 s ...\nCertPoll {messageType=20, transactionID=<same>}   -> PENDING\nPOST /api/v1/approvals/58/approve   (approver)\nCertPoll -> CertRep {pkiStatus=0 (SUCCESS)} + certificate",
        moves: [
          { from: "router", to: "scep", label: "PKCSReq (dual control)", kind: "secret" },
          { from: "scep", to: "db", label: "approval #58", kind: "response", effect: "store", dilly: "worried" },
          { from: "scep", to: "router", label: "PENDING", kind: "response" },
          { from: "mdm", to: "ra", label: "approver: approve", effect: "check" },
          { from: "router", to: "scep", label: "CertPoll" },
          { from: "scep", to: "router", label: "SUCCESS + certificate", kind: "secret", dilly: "happy" }
        ]
      }
    ]
  });

  // ------------------------------------------------------------------ Revocation
  S.register({
    id: "revocation",
    title: "Revocation: OCSP and CRL",
    dilly: "api",
    chainAt: "db",
    chainOffset: [1.2, 0.3],
    camera: { theta: -0.2, phi: 1.1, radius: 21.0 },
    actors: [
      { id: "rp", kind: "globe", label: "Relying party", sub: "browser or service", x: -7.0, z: 1.4, anchorY: 0.9 },
      { id: "server", kind: "server", label: "api.cards", sub: "presents its certificate", x: -5.0, z: -4.4, anchorY: 1.1 },
      { id: "cdn", kind: "cloud", label: "CRL distribution", sub: "/pki/crl/issuing-ca-1.crl", x: -0.8, z: -7.0, anchorY: 0.9, labelY: 1.9 },
      { id: "ocsp", kind: "terminal", label: "OCSP responder", sub: "delegated cert, 30 days", x: 2.6, z: -5.2, anchorY: 0.9, labelY: 1.9 },
      { id: "operator", kind: "person", label: "Operator", sub: "revokes", x: -2.0, z: 6.6 },
      { id: "api", kind: "gateway", label: "Certadillo API", x: -0.6, z: 1.2, anchorY: 1.5 },
      { id: "ca", kind: "ca", label: "Issuing CA", x: 6.6, z: -2.0, anchorY: 1.6, labelY: 3.0 },
      { id: "hsm", kind: "hsm", label: "HSM", x: 7.2, z: 1.6, anchorY: 0.6, labelY: 1.5 },
      { id: "db", kind: "db", label: "Certificate status", sub: "active · revoked", x: 3.4, z: 5.2, anchorY: 1.1 },
      { id: "prom", kind: "chart", label: "Prometheus", sub: "CRLStale", x: 6.6, z: 5.0, anchorY: 0.8, labelY: 1.9 }
    ],
    steps: [
      {
        phase: "Normal", title: "The certificate says where to check",
        body: "During the TLS handshake the server presents its certificate. Two extensions tell the relying party where revocation lives: AIA points at the OCSP responder, CDP at the CRL.",
        payload: "Authority Information Access:\n    OCSP - URI:https://pki.bank.internal/pki/ocsp\n    CA Issuers - URI:https://pki.bank.internal/pki/ca/issuing-ca-1.crt\nX509v3 CRL Distribution Points:\n    URI:https://pki.bank.internal/pki/crl/issuing-ca-1.crl",
        moves: [
          { from: "server", to: "rp", label: "certificate (AIA, CDP)", kind: "response" }
        ]
      },
      {
        phase: "Normal", title: "OCSP says good",
        body: "The relying party asks about one serial. The responder looks up live status and signs a short answer (valid 4 hours) with its delegated responder key, so the CA key is not used for every query.",
        payload: "$ openssl ocsp -issuer issuing.pem -cert server.crt -url https://pki.bank.internal/pki/ocsp -CAfile root.pem\nResponse verify OK\nserver.crt: good\n\tThis Update: Sep 23 22:31:39 2026 GMT\n\tNext Update: Sep 24 02:31:39 2026 GMT",
        moves: [
          { from: "rp", to: "ocsp", label: "OCSPRequest(serial 7B4C...)" },
          { from: "ocsp", to: "db", label: "status?" },
          { from: "db", to: "ocsp", label: "active", kind: "response" },
          { from: "ocsp", to: "rp", label: "good (signed)", kind: "response", effect: "check" }
        ]
      },
      {
        phase: "Incident", title: "Key compromise: revoke",
        body: "The server's key leaked. The operator revokes with reason key_compromise, which needs no change ticket even in production. The status changes in the same transaction as the audit event.",
        payload: "POST /api/v1/certificates/7/revoke\n{\"reason\": \"key_compromise\"}\n\n200 {\"status\": \"revoked\", \"revocation_reason\": \"key_compromise\"}",
        moves: [
          { from: "operator", to: "api", label: "POST /certificates/7/revoke", kind: "reject", dilly: "worried" },
          { from: "api", to: "db", label: "status = revoked + audit", kind: "reject", effect: "store" }
        ]
      },
      {
        phase: "Incident", title: "Publish a new CRL right away",
        body: "In the same request the issuing CA signs a new CRL with the next CRL number. The HSM signs it, and the CRL is published for download. Anonymous downloads serve this stored copy; they never trigger signing.",
        payload: "Certificate Revocation List (CRL):\n    Issuer: CN=Example Bank Issuing CA issuing-ca-1\n    Last Update: Sep 23 22:40:02 2026 GMT\n    Next Update: Sep 24 22:40:02 2026 GMT\n    X509v3 CRL Number: 5\nRevoked Certificates:\n    Serial Number: 7B4C294DAC830D452407ACFFE8492C99A84D2BD6\n        X509v3 CRL Reason Code: Key Compromise",
        moves: [
          { from: "api", to: "ca", label: "sign CRL #5" },
          { from: "ca", to: "hsm", label: "sign", kind: "secret", effect: "hsm" },
          { from: "ca", to: "cdn", label: "CRL #5", kind: "response" }
        ]
      },
      {
        phase: "Incident", title: "OCSP now says revoked",
        body: "OCSP answers from live state, so the very next query returns revoked with the reason and time. Clients that hard-fail on revoked certificates stop trusting the server immediately.",
        payload: "server.crt: revoked\n\tThis Update: Sep 23 22:40:05 2026 GMT\n\tReason: keyCompromise\n\tRevocation Time: Sep 23 22:40:02 2026 GMT",
        moves: [
          { from: "rp", to: "ocsp", label: "OCSPRequest" },
          { from: "ocsp", to: "db", label: "status?" },
          { from: "db", to: "ocsp", label: "revoked", kind: "reject" },
          { from: "ocsp", to: "rp", label: "revoked (keyCompromise)", kind: "reject", effect: "reject" }
        ]
      },
      {
        phase: "Incident", title: "CRL clients see it too",
        body: "Clients that use CRLs (many appliances, Windows chains) download the list and find the serial.",
        payload: "GET /pki/crl/issuing-ca-1.crl   (Cache-Control: max-age=300)\n-> serial 7B4C... present, reason keyCompromise",
        moves: [
          { from: "rp", to: "cdn", label: "GET issuing-ca-1.crl" },
          { from: "cdn", to: "rp", label: "serial listed", kind: "reject", effect: "reject" }
        ]
      },
      {
        phase: "Housekeeping", title: "Responder certificate rotation",
        body: "The OCSP responder certificate lives 30 days. Housekeeping has the CA sign a new one a week before expiry, so the responder never answers with an expired signer.",
        payload: "OCSP Responder issuing-ca-1\n  Extended Key Usage: OCSP Signing\n  OCSP No Check\n  Validity: 30 days, rotated at 7 days left",
        moves: [
          { from: "ca", to: "hsm", label: "sign responder cert", kind: "secret", effect: "hsm", dilly: "happy" },
          { from: "ca", to: "ocsp", label: "new responder cert", kind: "response", effect: "sign" }
        ]
      },
      {
        phase: "Housekeeping", title: "Freshness is watched",
        body: "CRLs are re-signed every 12 hours even without revocations. Prometheus scrapes certadillo_crl_last_generated_timestamp_seconds; if a CRL goes 24 hours without re-signing, CRLStale pages the PKI on-call before relying parties start failing.",
        payload: "alert: CRLStale\nexpr: time() - certadillo_crl_last_generated_timestamp_seconds{ca!=\"root-ca\"} > 24 * 3600\nlabels: {severity: critical}",
        moves: [
          { from: "prom", to: "api", label: "scrape /metrics" },
          { from: "api", to: "prom", label: "crl_last_generated", kind: "response", effect: "check" }
        ]
      }
    ]
  });

  // ------------------------------------------------------------------ Platform tour
  S.register({
    id: "platform",
    title: "Platform tour",
    dilly: "ra",
    chainAt: "db",
    chainOffset: [1.3, -0.2],
    platformRadius: 9.4,
    camera: { theta: 0.15, phi: 1.1, radius: 22.0 },
    actors: [
      { id: "team", kind: "person", label: "App team", sub: "cards", x: -7.4, z: 1.2, color: 0x3f6f9f },
      { id: "approver", kind: "person", label: "Approver", sub: "second person", x: -5.0, z: -5.2, color: 0xb7791f },
      { id: "console", kind: "laptop", label: "Console / API", sub: "onboarding", x: -4.2, z: 5.2, anchorY: 0.8 },
      { id: "protocols", kind: "gateway", label: "Enrollment", sub: "REST ACME EST SCEP SSH SPIFFE", x: -1.4, z: 0.2, anchorY: 1.5 },
      { id: "ra", kind: "shield", label: "RA + policy", x: 2.4, z: -2.0, anchorY: 1.2 },
      { id: "ca", kind: "ca", label: "CA hierarchy", sub: "root offline · issuing online", x: 5.6, z: -5.0, anchorY: 1.6, labelY: 3.0 },
      { id: "hsm", kind: "hsm", label: "HSM", x: 7.8, z: -1.6, anchorY: 0.6, labelY: 1.5 },
      { id: "db", kind: "db", label: "Inventory + audit", x: 4.6, z: 2.8, anchorY: 1.1 },
      { id: "scanner", kind: "radar", label: "Discovery", sub: "TLS scans · connectors", x: 1.2, z: 6.8, anchorY: 1.1, labelY: 2.0 },
      { id: "alerts", kind: "bell", label: "Alerting", sub: "Slack · Jira · ServiceNow", x: 0.6, z: -7.2, anchorY: 1.0, labelY: 2.0 },
      { id: "prom", kind: "chart", label: "Prometheus + Grafana", x: 7.8, z: 3.6, anchorY: 0.8, labelY: 1.9 }
    ],
    steps: [
      {
        phase: "Onboard", title: "Onboard a team and an app",
        body: "The cards team registers card-auth-api: environment prod, profile mtls-service, scope *.cards.bank.internal, classification pci. Nothing can be issued outside that scope later.",
        payload: "POST /api/v1/apps\n{\"team_id\": 1, \"name\": \"card-auth-api\", \"environment\": \"prod\",\n \"profile\": \"mtls-service\", \"allowed_domains\": [\"*.cards.bank.internal\"],\n \"data_classification\": \"pci\"}\n-> 201 {\"status\": \"pending_approval\", \"approval_id\": 12}",
        moves: [
          { from: "team", to: "console", label: "team + app + scope" },
          { from: "console", to: "db", label: "app pending + audit", kind: "response", effect: "store" }
        ]
      },
      {
        phase: "Onboard", title: "A second person approves production",
        body: "Maker-checker: only the approver role decides, never the requester, and never with a key the requester minted.",
        payload: "POST /api/v1/approvals/12/approve   (approver key)\n{\"comment\": \"CHG0012345 approved at CAB\"}\n-> app card-auth-api: active",
        moves: [
          { from: "console", to: "approver", label: "approval #12" },
          { from: "approver", to: "console", label: "approved", kind: "response", effect: "check" },
          { from: "console", to: "db", label: "audit: approval.approved", kind: "response", effect: "store" }
        ]
      },
      {
        phase: "Onboard", title: "Credentials for the way it enrolls",
        body: "The team gets exactly one credential type per client: an API key for REST, EST and SSH, a single-use EAB for ACME, or one-time challenges for SCEP devices. Each is shown once.",
        payload: "POST /api/v1/apps/3/credentials   -> {\"api_key\": \"cdl_...\"}\nPOST /api/v1/apps/3/acme-eab      -> {\"kid\": \"eab_...\", \"hmac_key\": \"...\"}\nPOST /api/v1/apps/7/scep-challenge -> {\"challenge\": \"90b0...\"}",
        moves: [
          { from: "console", to: "team", label: "API key · EAB · challenge", kind: "secret" }
        ]
      },
      {
        phase: "Issue", title: "Every protocol meets one RA",
        body: "Whichever protocol the client speaks, the request lands in the same registration authority. The same policy, the same dual control, the same audit.",
        payload: "REST   POST /api/v1/certificates\nACME   POST /acme/order/{id}/finalize\nEST    POST /.well-known/est/simpleenroll\nSCEP   POST /scep?operation=PKIOperation\nSSH    POST /api/v1/ssh/certificates\n  -> Platform.request_certificate()",
        moves: [
          { from: "team", to: "protocols", label: "CSR", sub: "any protocol" },
          { from: "protocols", to: "ra", label: "request_certificate()", effect: "check", dilly: "happy" }
        ]
      },
      {
        phase: "Issue", title: "Sign in the HSM, record everything",
        body: "The issuing CA key sits in the HSM as sensitive and non-extractable. The certificate, the audit event and the metrics update together.",
        payload: "C_Sign(CKM_ECDSA, SHA-384(tbsCertificate))\ncertificates: + auth.cards.bank.internal (mtls-service, 30d, app card-auth-api)\naudit_events: + certificate.issue (hash chained)",
        moves: [
          { from: "ra", to: "ca", label: "build certificate" },
          { from: "ca", to: "hsm", label: "sign", kind: "secret", effect: "hsm" },
          { from: "ca", to: "db", label: "store + audit", kind: "response", effect: "store" },
          { from: "protocols", to: "team", label: "certificate", kind: "response" }
        ]
      },
      {
        phase: "Operate", title: "Discovery finds a stranger",
        body: "A scan of the payments subnet finds a certificate nobody onboarded, five days from expiry, on a load balancer. It enters the inventory as discovered and unowned.",
        payload: "POST /api/v1/discovery/scan {\"targets\": [\"10.20.0.0/28:443\"]}\n-> 10.20.0.14:443  legacy-gw.cards.bank.internal  expires in 5 days\n   findings: quantum_vulnerable",
        moves: [
          { from: "scanner", to: "db", label: "10.20.0.14:443: unknown cert", kind: "reject", effect: "store", dilly: "worried" }
        ]
      },
      {
        phase: "Operate", title: "The alert reaches the owner",
        body: "Once the certificate is assigned to card-auth-api, CertificateExpiringSoon goes to the cards team webhook, opens a ServiceNow incident and a Jira issue, and Dilly rolls into a ball.",
        payload: "alert CertificateExpiringSoon  severity=critical\n  legacy-gw.cards.bank.internal at 10.20.0.14:443 expires in 4d 23h\n  team=cards  app=card-auth-api  environment=prod\n  runbook: docs/RUNBOOK.md#certificateexpiringsoon",
        moves: [
          { from: "db", to: "alerts", label: "CertificateExpiringSoon", kind: "reject", dilly: "rolled" },
          { from: "alerts", to: "team", label: "Slack + ServiceNow + Jira", kind: "reject", effect: "reject" }
        ]
      },
      {
        phase: "Operate", title: "Automation replaces it",
        body: "The team moves the load balancer to ACME. The next scan sees the new certificate at the same endpoint, retires the old one, and the alert sends its resolved notice.",
        payload: "certbot certonly --server https://pki.bank.internal/acme/directory ... -d legacy-gw.cards.bank.internal\nrescan 10.20.0.14:443 -> new certificate; old one superseded\nalert CertificateExpiringSoon: resolved",
        moves: [
          { from: "team", to: "protocols", label: "ACME order" },
          { from: "protocols", to: "ra", label: "policy", effect: "check" },
          { from: "ra", to: "ca", label: "sign" },
          { from: "ca", to: "db", label: "store; old superseded", kind: "response", effect: "store", dilly: "happy" },
          { from: "db", to: "alerts", label: "resolved", kind: "response", effect: "check" }
        ]
      },
      {
        phase: "Prove", title: "Metrics, dashboards and reports",
        body: "Prometheus scrapes expiry and lifetime gauges per certificate, labelled by team. Grafana shows the estate; auditors pull the PCI DSS 4.2.1.1 inventory and the CycloneDX CBOM, and the audit chain verifies end to end.",
        payload: "GET /metrics                     certadillo_certificate_expiry_timestamp_seconds{team=\"cards\",...}\nGET /api/v1/reports/pci-inventory?format=csv\nGET /api/v1/reports/cbom          CycloneDX 1.6\nGET /api/v1/audit/verify          {\"valid\": true, \"events\": 51}",
        moves: [
          { from: "prom", to: "db", label: "scrape /metrics" },
          { from: "db", to: "prom", label: "gauges by team", kind: "response", effect: "check" }
        ]
      }
    ]
  });

  // ------------------------------------------------------------------ dns-01 + ARI
  S.register({
    id: "ari",
    title: "dns-01, wildcards and a renewal campaign (ARI)",
    dilly: "ra",
    chainAt: "db",
    chainOffset: [1.2, 0.2],
    camera: { theta: 0.3, phi: 1.1, radius: 21.0 },
    actors: [
      { id: "operator", kind: "person", label: "PKI operator", sub: "runs the campaign", x: -1.6, z: 7.0 },
      { id: "client", kind: "laptop", label: "ACME client", sub: "cert-manager, lego, certbot", x: -7.0, z: 2.2, anchorY: 0.8 },
      { id: "dnsint", kind: "globe", label: "Internal DNS", sub: "bank.internal view", x: -6.2, z: -3.8, anchorY: 0.9 },
      { id: "dnspub", kind: "cloud", label: "Public DNS", sub: "never asked for .internal", x: -2.2, z: -7.0, anchorY: 0.9, labelY: 1.9 },
      { id: "acme", kind: "gateway", label: "Certadillo ACME", sub: "/acme/*", x: -0.8, z: 0.4, anchorY: 1.5 },
      { id: "ra", kind: "shield", label: "RA + policy", sub: "tls-wildcard profile", x: 3.4, z: -4.0, anchorY: 1.2 },
      { id: "ca", kind: "ca", label: "Issuing CA", sub: "issuing-ca-1", x: 7.0, z: -0.8, anchorY: 1.6, labelY: 3.0 },
      { id: "db", kind: "db", label: "Inventory + audit", sub: "campaign state", x: 2.4, z: 5.6, anchorY: 1.1 },
      { id: "alerts", kind: "bell", label: "Alerting", sub: "routed to the owning team", x: 6.8, z: 4.2, anchorY: 1.0, labelY: 2.0 }
    ],
    steps: [
      {
        phase: "Order", title: "Order a wildcard",
        body: "The app portal-edge is onboarded with the tls-wildcard profile and the scope *.portal.bank.internal. Its ACME client orders *.edge.portal.bank.internal. Any other profile would refuse the wildcard at newOrder, before a challenge exists.",
        payload: "POST /acme/new-order\npayload: {\"identifiers\":[\n  {\"type\":\"dns\",\"value\":\"*.edge.portal.bank.internal\"},\n  {\"type\":\"dns\",\"value\":\"edge.portal.bank.internal\"}]}\n\n201 Created\n{\"status\":\"pending\",\"authorizations\":[\".../authz/21\",\".../authz/22\"], ...}",
        moves: [
          { from: "client", to: "acme", label: "POST /new-order", sub: "*.edge.portal" },
          { from: "acme", to: "ra", label: "scope + allow_wildcard", effect: "check", dilly: "happy" },
          { from: "acme", to: "client", label: "order: pending", kind: "response" }
        ]
      },
      {
        phase: "Challenge", title: "A wildcard gets dns-01 only",
        body: "RFC 8555 lets a wildcard be proven only through DNS, so its authorization offers dns-01 alone. The authorization names the base domain and carries wildcard: true. The plain name gets both http-01 and dns-01.",
        payload: "POST /acme/authz/21   (POST-as-GET)\n\n{\"status\":\"pending\",\n \"identifier\":{\"type\":\"dns\",\"value\":\"edge.portal.bank.internal\"},\n \"wildcard\":true,\n \"challenges\":[{\"type\":\"dns-01\",\n   \"url\":\".../acme/chall/21/dns-01\",\n   \"token\":\"Xk8tZq3R0vE2aHn7YcLw5pUdGf4sJm1bQy9oTi6rVxE\"}]}",
        moves: [
          { from: "client", to: "acme", label: "POST /authz/21" },
          { from: "acme", to: "client", label: "dns-01 token", kind: "response" }
        ]
      },
      {
        phase: "Challenge", title: "Publish the TXT record",
        body: "The client writes base64url(SHA-256(token.thumbprint)) at _acme-challenge. Many teams CNAME that name into a small zone their automation may write; Certadillo follows the CNAME.",
        payload: "_acme-challenge.edge.portal.bank.internal. 60 IN TXT \"qZ0m4Wv1cN8yR2kP6tB3xH9sJ7eL5aD0fU2gQ8iO4rE\"\n\n; or delegated:\n_acme-challenge.edge.portal.bank.internal. CNAME edge.acme-delegate.portal.bank.internal.",
        moves: [
          { from: "client", to: "dnsint", label: "TXT via DNS API", kind: "secret" }
        ]
      },
      {
        phase: "Challenge", title: "Validate through the internal view",
        body: "CERTADILLO_ACME_DNS_VIEWS maps zones to resolvers. portal.bank.internal is answered by the internal resolvers; the public resolvers are never asked about it, and would not know the zone anyway. The longest matching zone wins, and the answer names the view that answered.",
        payload: "CERTADILLO_ACME_DNS_VIEWS=\"bank.internal=10.1.0.53,10.2.0.53;portal.bank.internal=10.9.0.53\"\n\ndig @10.9.0.53 TXT _acme-challenge.edge.portal.bank.internal\n-> \"qZ0m4Wv1cN8yR2kP6tB3xH9sJ7eL5aD0fU2gQ8iO4rE\"   (matches)\n\n{\"type\":\"dns-01\",\"status\":\"valid\",\"validated\":\"2026-09-24T04:10:13Z\"}",
        moves: [
          { from: "client", to: "acme", label: "POST /chall/21/dns-01" },
          { from: "acme", to: "dnsint", label: "TXT _acme-challenge.edge..." },
          { from: "dnsint", to: "acme", label: "digest matches", kind: "response", effect: "check" }
        ]
      },
      {
        phase: "Issue", title: "Finalize and issue",
        body: "The CSR carries both names. Policy checks the key, the scope and the profile, and the CA signs. The client now holds a 30-day wildcard.",
        payload: "POST /acme/order/9/finalize   {\"csr\": \"MIIBTzCB9wIBADAmMSQwIgYDVQQDDBsqLmVkZ2UucG9y...\"}\n\nSAN: *.edge.portal.bank.internal, edge.portal.bank.internal\nprofile tls-wildcard · 30 days · P-256",
        moves: [
          { from: "client", to: "acme", label: "POST /finalize" },
          { from: "acme", to: "ra", label: "policy", effect: "check" },
          { from: "ra", to: "ca", label: "sign", effect: "sign" },
          { from: "ca", to: "db", label: "store + audit", kind: "response", effect: "store" }
        ]
      },
      {
        phase: "ARI", title: "The client asks when to renew",
        body: "The directory advertises renewalInfo (RFC 9773). The client asks with the certificate's CertID, built from the issuer's key identifier and the serial. Normally the window sits at 50 to 60 percent of the lifetime, before the platform's own expiry warning, and the client picks a random moment inside it.",
        payload: "GET /acme/renewal-info/kBXWiC6ES11xBWj1ZleSver1klM.WhBfketKLIVSfmI5ps5e1Ht5sE4\n\n200 OK\nRetry-After: 21600\n{\"suggestedWindow\":{\"start\":\"2026-10-09T04:10:13Z\",\n                    \"end\":  \"2026-10-12T04:10:13Z\"}}",
        moves: [
          { from: "client", to: "acme", label: "GET /renewal-info/<CertID>" },
          { from: "acme", to: "client", label: "window: day 15 to 18", kind: "response" }
        ]
      },
      {
        phase: "Campaign", title: "Something is wrong with a batch",
        body: "A build host that held keys for these certificates is suspected of compromise. The operator starts a renewal campaign for the affected serials instead of revoking straight away: revoking first would take the services down.",
        payload: "POST /api/v1/renewal-campaigns\n{\"name\": \"rotate portal-edge\",\n \"reason\": \"suspected key exposure on build host bh-12\",\n \"criteria\": {\"app_ids\": [4]},\n \"renew_within_hours\": 24,\n \"explanation_url\": \"https://status.bank.example/pki/2026-09\"}\n\n201 {\"id\": 3, \"counts\": {\"total\": 14, \"replaced\": 0, \"remaining\": 14}}",
        moves: [
          { from: "operator", to: "acme", label: "POST /renewal-campaigns" },
          { from: "acme", to: "db", label: "advice for 14 certificates", kind: "response", effect: "store", dilly: "worried" }
        ]
      },
      {
        phase: "Campaign", title: "The window moves forward",
        body: "The next time each client checks, the window is now: within 24 hours, with a link explaining why, and a one-hour Retry-After. Clients spread their renewals across the window, so the CA is not hit by all of them at once. For a true emergency, immediate: true puts the window in the past and every client renews on its next check.",
        payload: "GET /acme/renewal-info/kBXWiC6ES11xBWj1ZleSver1klM.WhBf...\n\n200 OK\nRetry-After: 3600\n{\"suggestedWindow\":{\"start\":\"2026-09-24T04:15:00Z\",\n                    \"end\":  \"2026-09-25T04:15:00Z\"},\n \"explanationURL\":\"https://status.bank.example/pki/2026-09\"}",
        moves: [
          { from: "client", to: "acme", label: "GET /renewal-info" },
          { from: "acme", to: "client", label: "renew within 24h", kind: "response" }
        ]
      },
      {
        phase: "Campaign", title: "Renew with a new key",
        body: "The client orders again with replaces set to the old CertID, proves the names again and sends a CSR with a new key; reusing the old key is refused. The old certificate is marked superseded. Clients that do not send replaces (certbot 5.8 checks ARI but does not) are matched by app and names instead.",
        payload: "POST /acme/new-order\npayload: {\"identifiers\":[...],\n          \"replaces\":\"kBXWiC6ES11xBWj1ZleSver1klM.WhBfketKLIVSfmI5ps5e1Ht5sE4\"}\n\naudit: certificate.renew {serial: 5a1f..., new_serial: 7c02...}",
        moves: [
          { from: "client", to: "acme", label: "new-order + replaces" },
          { from: "acme", to: "ra", label: "new key required", effect: "check" },
          { from: "ra", to: "ca", label: "sign", effect: "sign" },
          { from: "ca", to: "db", label: "old: superseded", kind: "response", effect: "store", dilly: "happy" }
        ]
      },
      {
        phase: "Campaign", title: "Revoke what has been replaced",
        body: "Revoking a certificate that has a successor breaks nothing, so this needs no second person. The CRL is re-signed at once and OCSP answers revoked for the old serials.",
        payload: "POST /api/v1/renewal-campaigns/3/revoke-replaced\n{\"change_ref\": \"CHG0042117\"}\n\n200 {\"revoked\": 13}",
        moves: [
          { from: "operator", to: "acme", label: "revoke-replaced" },
          { from: "acme", to: "ca", label: "revoke 13 + new CRL", kind: "secret", effect: "sign" },
          { from: "ca", to: "db", label: "audit", kind: "response", effect: "store" }
        ]
      },
      {
        phase: "Campaign", title: "The deadline passes with one left",
        body: "One client never renewed. RenewalCampaignOverdue fires as critical and goes to the team that owns the app, with the certificate named. Revoking the rest is the hard cutoff that can cause an outage, so it goes to an approver.",
        payload: "alert RenewalCampaignOverdue (critical)\n  renewal campaign 'rotate portal-edge' passed its deadline with 1 certificate(s)\n  not replaced (teams: web)\n\nPOST /api/v1/renewal-campaigns/3/revoke-remaining  {\"change_ref\":\"CHG0042117\"}\n202 {\"status\":\"pending_approval\",\"approval_id\":61}",
        moves: [
          { from: "db", to: "alerts", label: "RenewalCampaignOverdue", kind: "reject", dilly: "rolled" },
          { from: "operator", to: "acme", label: "revoke-remaining" },
          { from: "acme", to: "db", label: "approval #61: second person", kind: "response", effect: "store" }
        ]
      }
    ]
  });

  // ------------------------------------------------------------------ EST behind a load balancer
  S.register({
    id: "estlb",
    title: "EST behind a load balancer",
    dilly: "ra",
    chainAt: "db",
    chainOffset: [1.2, 0.2],
    camera: { theta: 0.25, phi: 1.1, radius: 21.0 },
    actors: [
      { id: "device", kind: "router", label: "Branch router", sub: "IDevID from the factory", x: -7.0, z: 2.0, anchorY: 0.5, labelY: 1.7 },
      { id: "mfr", kind: "ca", label: "Manufacturer CA", sub: "Acme Devices IDevID", x: -6.0, z: -4.6, anchorY: 1.6, labelY: 3.0 },
      { id: "lb", kind: "gateway", label: "nginx / load balancer", sub: "TLS + client cert", x: -2.4, z: 0.2, anchorY: 1.5 },
      { id: "attacker", kind: "laptop", label: "Direct caller", sub: "bypasses the LB", x: -2.4, z: 6.4, anchorY: 0.8 },
      { id: "est", kind: "terminal", label: "Certadillo EST", sub: "/.well-known/est", x: 1.6, z: 2.4, anchorY: 0.9, labelY: 1.9 },
      { id: "ra", kind: "shield", label: "RA + policy", sub: "tls-client", x: 3.2, z: -3.8, anchorY: 1.2 },
      { id: "ca", kind: "ca", label: "Issuing CA", sub: "issuing-ca-1", x: 7.0, z: -0.6, anchorY: 1.6, labelY: 3.0 },
      { id: "db", kind: "db", label: "Inventory + audit", x: 4.6, z: 5.2, anchorY: 1.1 }
    ],
    steps: [
      {
        phase: "Setup", title: "Trust the manufacturer's CA for one app",
        body: "The router shipped with a manufacturer certificate (IDevID) and no shared secret. An operator registers the manufacturer's CA for the app branch-routers. For a production app this is an approval, since it lets every device from that factory enroll.",
        payload: "POST /api/v1/apps/7/est-trust-anchors\n{\"name\": \"acme-devices\", \"cert_pem\": \"-----BEGIN CERTIFICATE-----\\nMIIB...\"}\n\n202 {\"status\":\"pending_approval\",\"approval_id\":52}   (prod app)\n-> approved by a second person\naudit: est.trust_anchor.add {subject: \"CN=Acme Devices IDevID CA,O=Acme Devices\"}",
        moves: [
          { from: "mfr", to: "ra", label: "CA certificate, via operator", kind: "secret" },
          { from: "ra", to: "db", label: "anchor for branch-routers", kind: "response", effect: "store" }
        ]
      },
      {
        phase: "Bootstrap", title: "TLS with the factory certificate",
        body: "The router connects to the load balancer and offers its IDevID during the TLS handshake. The handshake itself proves the router holds the IDevID key. nginx does not need to know the manufacturer; Certadillo decides whom to trust.",
        payload: "server {\n  listen 443 ssl;\n  ssl_verify_client optional_no_ca;\n  location /.well-known/est/ {\n    proxy_pass http://certadillo:8080;\n    proxy_set_header X-SSL-Client-Cert        $ssl_client_escaped_cert;\n    proxy_set_header X-Certadillo-Proxy-Auth  <shared secret>;\n  }\n}",
        moves: [
          { from: "device", to: "lb", label: "TLS ClientHello + IDevID", kind: "secret" },
          { from: "lb", to: "device", label: "handshake OK", kind: "response", effect: "check" }
        ]
      },
      {
        phase: "Bootstrap", title: "Ask what to put in the CSR",
        body: "csrattrs answers from the app's profile: an EC P-256 key and ECDSA with SHA-256. The router generates its operational key accordingly.",
        payload: "GET /.well-known/est/csrattrs\n\n200 application/csrattrs\nSEQUENCE {\n  attribute id-ecPublicKey { secp256r1 }\n  oid ecdsa-with-SHA256\n}",
        moves: [
          { from: "device", to: "lb", label: "GET /csrattrs" },
          { from: "lb", to: "est", label: "forward + cert header" },
          { from: "est", to: "device", label: "P-256, ECDSA-SHA256", kind: "response" }
        ]
      },
      {
        phase: "Bootstrap", title: "Enroll with the IDevID",
        body: "nginx forwards the client certificate URL-encoded in a header, plus the shared secret. Certadillo believes the header only with that secret, finds that the IDevID chains to the registered manufacturer CA, and enrolls the CSR into branch-routers under the normal scope and policy.",
        payload: "POST /.well-known/est/simpleenroll\nX-SSL-Client-Cert: -----BEGIN%20CERTIFICATE-----%0AMIIB...\nX-Certadillo-Proxy-Auth: <secret>\n\nidentify: IDevID serialNumber=SN-451 -> anchor acme-devices -> app branch-routers\npolicy:   CN rtr-451.routers.bank.internal in *.routers.bank.internal, P-256\n200 application/pkcs7-mime",
        moves: [
          { from: "device", to: "lb", label: "POST /simpleenroll", sub: "CSR" },
          { from: "lb", to: "est", label: "CSR + IDevID header" },
          { from: "est", to: "ra", label: "anchor + scope", effect: "check", dilly: "happy" },
          { from: "ra", to: "ca", label: "sign", effect: "sign" },
          { from: "ca", to: "db", label: "audit: est.enroll auth=idevid", kind: "response", effect: "store" },
          { from: "est", to: "device", label: "operational certificate", kind: "response" }
        ]
      },
      {
        phase: "Renew", title: "Re-enroll with the certificate alone",
        body: "Later the router re-enrolls using its operational certificate for TLS and a CSR with a new key. No password is involved. RFC 7030 requires the same subject and names; the old certificate is superseded and stops authenticating.",
        payload: "POST /.well-known/est/simplereenroll\nX-SSL-Client-Cert: <rtr-451 certificate>\n\naudit: est.enroll {\"auth\":\"certificate\",\"reenroll\":true}\nold serial 3f9a...: superseded",
        moves: [
          { from: "device", to: "lb", label: "TLS with current cert" },
          { from: "lb", to: "est", label: "POST /simplereenroll" },
          { from: "est", to: "ra", label: "same subject, new key", effect: "check" },
          { from: "ra", to: "ca", label: "sign", effect: "sign" },
          { from: "est", to: "device", label: "new certificate", kind: "response" }
        ]
      },
      {
        phase: "Guard", title: "A forged header is ignored",
        body: "Someone who reaches Certadillo without going through the load balancer can type any header. Without the shared secret (or a trusted source address) the header is ignored and the request falls back to HTTP Basic, which it does not have.",
        payload: "POST /.well-known/est/simplereenroll\nX-SSL-Client-Cert: <someone else's certificate>\n\nlog: client certificate header ignored: request did not come through the trusted load balancer\n401 Unauthorized",
        moves: [
          { from: "attacker", to: "est", label: "forged X-SSL-Client-Cert", kind: "reject" },
          { from: "est", to: "attacker", label: "401", kind: "reject", effect: "reject", dilly: "worried" }
        ]
      },
      {
        phase: "Keygen", title: "A sensor that cannot make a key",
        body: "For profiles with allow_server_keygen, serverkeygen creates the key on the server and returns it with the certificate as multipart/mixed over TLS. The key is not stored; the audit event says so. Anything that can generate its own key should.",
        payload: "POST /.well-known/est/serverkeygen\n\n200 multipart/mixed; boundary=est-4f1c...\n--est-4f1c...\nContent-Type: application/pkcs8\n\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...\n--est-4f1c...\nContent-Type: application/pkcs7-mime; smime-type=certs-only\n\nMIIC...\n--est-4f1c...--\n\naudit: est.serverkeygen {\"key\":\"ec-256\",\"stored\":false}",
        moves: [
          { from: "device", to: "lb", label: "POST /serverkeygen" },
          { from: "lb", to: "est", label: "forward" },
          { from: "est", to: "ca", label: "new key + certificate", effect: "sign" },
          { from: "est", to: "device", label: "PKCS#8 + certificate", kind: "secret" }
        ]
      }
    ]
  });

  // ------------------------------------------------------------------ CMP
  S.register({
    id: "cmp",
    title: "CMP for industrial devices (RFC 9483)",
    dilly: "ra",
    chainAt: "db",
    chainOffset: [1.2, 0.2],
    camera: { theta: 0.3, phi: 1.1, radius: 21.0 },
    actors: [
      { id: "operator", kind: "person", label: "OT engineer", sub: "commissions devices", x: -2.0, z: 7.0 },
      { id: "plc", kind: "terminal", label: "PLC / base station", sub: "openssl cmp", x: -7.0, z: 1.6, anchorY: 0.9, labelY: 1.9 },
      { id: "cmp", kind: "gateway", label: "Certadillo CMP", sub: "/.well-known/cmp", x: -1.4, z: -0.6, anchorY: 1.5 },
      { id: "ra", kind: "shield", label: "RA + policy", sub: "CMP RA cert · cmcRA", x: 3.2, z: -4.4, anchorY: 1.2 },
      { id: "approver", kind: "person", label: "Approver", sub: "second person", x: -4.6, z: -6.0 },
      { id: "ca", kind: "ca", label: "Issuing CA", sub: "issuing-ca-1", x: 7.0, z: 0.0, anchorY: 1.6, labelY: 3.0 },
      { id: "hsm", kind: "hsm", label: "HSM", x: 6.6, z: 4.0, anchorY: 0.6, labelY: 1.5 },
      { id: "db", kind: "db", label: "Inventory + audit", x: 2.2, z: 5.6, anchorY: 1.1 }
    ],
    steps: [
      {
        phase: "Setup", title: "A one-time reference and secret",
        body: "A device without any certificate proves itself with a shared secret (RFC 9483 4.1.1). The operator mints a one-time reference and secret for the app plant-sensors and loads them into the device at commissioning.",
        payload: "POST /api/v1/apps/5/cmp-secret\n\n201 {\"reference\": \"cmp-37614dc792fc\",\n     \"secret\": \"q7Cq3oT0y1F2l8i9WmXbRk2v\",\n     \"expires\": \"2026-09-24T05:27:21Z\"}",
        moves: [
          { from: "operator", to: "cmp", label: "POST /apps/5/cmp-secret" },
          { from: "cmp", to: "db", label: "secret, encrypted at rest", kind: "response", effect: "store" },
          { from: "cmp", to: "operator", label: "reference + secret", kind: "secret" },
          { from: "operator", to: "plc", label: "load into device", kind: "secret" }
        ]
      },
      {
        phase: "Enroll", title: "ir, protected with a MAC",
        body: "The device makes a key, puts the public key and its names in a CRMF template, signs the request with the new key (proof of possession) and protects the whole message with PasswordBasedMac keyed from the secret. senderKID is the reference.",
        payload: "openssl cmp -cmd ir -server pki.bank.internal -path .well-known/cmp \\\n  -ref cmp-37614dc792fc -secret pass:... -newkey dev.key \\\n  -subject /CN=s1.plant.bank.internal -sans s1.plant.bank.internal\n\nPKIHeader { pvno 2, senderKID \"cmp-37614dc792fc\",\n  protectionAlg PasswordBasedMac { salt, owf sha256, iterations 500, mac hmac-sha1 },\n  transactionID 039d45ec..., senderNonce 6f5101ad... }\nPKIBody ir { certReqId 0, template { subject, publicKey ec P-256, SAN }, popo signature }",
        moves: [
          { from: "plc", to: "cmp", label: "ir (MAC)", sub: "CRMF + PoP", kind: "secret" },
          { from: "cmp", to: "ra", label: "MAC + PoP + scope", effect: "check", dilly: "happy" },
          { from: "ra", to: "ca", label: "build certificate" },
          { from: "ca", to: "hsm", label: "sign", kind: "secret", effect: "hsm" },
          { from: "hsm", to: "ca", label: "signature", kind: "response", effect: "sign" }
        ]
      },
      {
        phase: "Enroll", title: "ip with the certificate and a trust anchor",
        body: "The reply is protected with the same secret. It carries the certificate, the issuing CA in extraCerts and the root in caPubs, because a device that enrolled with a password has no trust anchor yet. The secret is now spent.",
        payload: "PKIBody ip {\n  caPubs [ Example Bank Root CA ]\n  response { certReqId 0, status accepted,\n    certificate CN=s1.plant.bank.internal (tls-client, 30 days) } }\nextraCerts [ Issuing CA issuing-ca-1 ]\nrecipNonce = 6f5101ad...   (the device's senderNonce)",
        moves: [
          { from: "cmp", to: "db", label: "audit: cmp.issue", kind: "response", effect: "store" },
          { from: "cmp", to: "plc", label: "ip (MAC)", kind: "response" }
        ]
      },
      {
        phase: "Enroll", title: "certConf, then pkiConf",
        body: "The device confirms it received the right certificate by sending its hash. Only then is the transaction closed. A device that asks for implicitConfirm skips this round trip; one that never confirms is flagged after 15 minutes.",
        payload: "PKIBody certConf { certHash SHA-384(certificate), certReqId 0 }\n-> PKIBody pkiconf NULL\naudit: cmp.confirmed",
        moves: [
          { from: "plc", to: "cmp", label: "certConf", sub: "certHash" },
          { from: "cmp", to: "plc", label: "pkiConf", kind: "response", effect: "check" }
        ]
      },
      {
        phase: "Update", title: "kur, signed with the current certificate",
        body: "Before expiry the device asks for a key update, signing with its current certificate. The template may leave the subject out; it is copied from the old certificate. The old one is superseded, but still accepted for the certConf of this same transaction.",
        payload: "openssl cmp -cmd kur -cert dev.crt -key dev.key -newkey dev2.key -trusted root.pem\n\nPKIHeader { protectionAlg ecdsa-with-SHA256, extraCerts [ dev.crt, issuing CA ] }\nPKIBody kur -> kup (signed by CMP RA issuing-ca-1, EKU id-kp-cmcRA)",
        moves: [
          { from: "plc", to: "cmp", label: "kur (signature)" },
          { from: "cmp", to: "ra", label: "same subject, new key", effect: "check" },
          { from: "ra", to: "ca", label: "sign", effect: "sign" },
          { from: "cmp", to: "plc", label: "kup (RA signature)", kind: "response" }
        ]
      },
      {
        phase: "Approval", title: "Firmware signing waits for a second person",
        body: "A code-signing certificate needs dual control. The ip says waiting, and the device polls with pollReq; each pollRep tells it when to ask again.",
        payload: "ip { response { certReqId 0, status waiting, \"waiting for a second approver\" } }\npollReq { certReqId 0 }\npollRep { certReqId 0, checkAfter 30 }",
        moves: [
          { from: "plc", to: "cmp", label: "ir (code-signing)" },
          { from: "cmp", to: "db", label: "approval #63", kind: "response", effect: "store", dilly: "worried" },
          { from: "cmp", to: "plc", label: "status: waiting", kind: "response" },
          { from: "plc", to: "cmp", label: "pollReq" },
          { from: "cmp", to: "plc", label: "pollRep checkAfter 30", kind: "response" }
        ]
      },
      {
        phase: "Approval", title: "Approved; the next poll gets the certificate",
        body: "The approver is not the person who asked. Once they approve, the next pollReq is answered with the ip carrying the certificate, and the device confirms it as usual.",
        payload: "POST /api/v1/approvals/63/approve   (approver key)\n\npollReq -> ip { status accepted, certificate CN=fw.plant.bank.internal, EKU codeSigning }\ncertConf -> pkiConf",
        moves: [
          { from: "approver", to: "cmp", label: "approve #63" },
          { from: "cmp", to: "ca", label: "issue", effect: "sign", dilly: "happy" },
          { from: "plc", to: "cmp", label: "pollReq" },
          { from: "cmp", to: "plc", label: "ip + certificate", kind: "response" }
        ]
      },
      {
        phase: "Revoke", title: "The device revokes a certificate it holds",
        body: "rr names the certificate by issuer and serial and gives a reason. It must be signed with a certificate of the same app. The CRL is re-signed right away.",
        payload: "openssl cmp -cmd rr -cert dev2.crt -key dev2.key -oldcert s3.crt -revreason 4\n\nPKIBody rr { certDetails { issuer, serialNumber }, crlEntryDetails { CRLReason superseded } }\n-> rp { status accepted }",
        moves: [
          { from: "plc", to: "cmp", label: "rr (signature)" },
          { from: "cmp", to: "ca", label: "revoke + CRL", kind: "secret", effect: "sign" },
          { from: "cmp", to: "plc", label: "rp accepted", kind: "response" }
        ]
      }
    ]
  });
})();
