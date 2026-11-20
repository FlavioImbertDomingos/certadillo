# ServiceNow catalog item: request a Certadillo application

Teams ask for a new application in the ServiceNow service catalog. ServiceNow
runs its usual approval; once the requested item (RITM) is approved, a flow
sends it to Certadillo, which onboards the app through its normal path and
writes every decision back to the RITM as a work note. The approval is
recorded in both systems:

| Step | ServiceNow | Certadillo |
| --- | --- | --- |
| Request | RITM created from the catalog item | |
| ServiceNow approval | manager or PKI group approves | stored on the request and in the audit trail (`servicenow.onboarding`); required before anything happens |
| Onboarding | work note: received | app created; a production scope waits for a Certadillo approver |
| Certadillo approval | work note: approved or rejected, by whom, approval number | `approval.approved` / `approval.rejected`; the person the item was requested for cannot approve it |
| Credentials | never written to the ticket | the team gets them from Certadillo (console, an operator, or ACME EAB) |

## Catalog item variables

| Variable | Type | Notes |
| --- | --- | --- |
| `certadillo_team` | Reference or select box | must match a Certadillo team name |
| `certadillo_app_name` | Single line text | lowercase letters, digits and dashes |
| `certadillo_environment` | Select box | dev, test, uat, prod |
| `certadillo_profile` | Select box | `tls-server`, `tls-client`, `mtls-service`, `spiffe-svid`, `tls-server-pq`, ... (`GET /api/v1/profiles`) |
| `certadillo_domains` | Multi line text | one scope entry per line: `api.pay.bank.example`, `*.pay.bank.example` |
| `certadillo_classification` | Select box | internal, confidential, restricted |

## Wiring it up

1. In Certadillo, create the integration principal and keep its key for step 3:
   `POST /api/v1/principals {"name": "servicenow", "role": "operator"}`.
2. Set `CERTADILLO_SNOW_URL`, `_SNOW_USER` and `_SNOW_PASSWORD` (a ServiceNow
   user that may write work notes on `sc_req_item`) so Certadillo can write
   back, and add the instance to `CERTADILLO_EGRESS_ALLOW` if you use it.
3. In ServiceNow, create a Connection & Credential alias `x_certadillo.api`
   with the Certadillo base URL and an API key credential (header
   `X-API-Key`), and allow the Certadillo host in your outbound firewall.
4. Create the catalog item with the variables above and an approval in its
   flow, then add an action after the approval that runs
   [`certadillo_onboarding.js`](certadillo_onboarding.js).

Certadillo refuses a request whose ServiceNow approval is missing or was given
by the person the item is for, and repeating a RITM returns the app it already
created. Work notes that cannot be delivered are retried on every housekeeping
cycle; `GET /api/v1/integrations/servicenow/requests` shows any that are still
waiting.

The Certadillo side is covered by `tests/test_servicenow_catalog.py` against a
fake ServiceNow Table API. The ServiceNow script is an example to adapt to
your instance; it has not been run against a live instance.
