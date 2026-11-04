"""Importing a keycensus inventory.json. The fixture was produced by keycensus
itself (`keycensus scan -f json` over a PEM source with one application
linked), so this is an interop test against the real export format."""
from __future__ import annotations

import copy
import json
from pathlib import Path

from fastapi.testclient import TestClient

from certadillo.api.app import create_app
from conftest import ADMIN, make_settings

FIX = Path(__file__).parent / "fixtures" / "keycensus"


def test_import_links_applications_and_flags_untracked_certificates(tmp_path):
    doc = json.loads((FIX / "inventory.json").read_text())
    with TestClient(create_app(make_settings(tmp_path), background=False)) as c:
        # Certadillo already knows one of the two certificates keycensus saw
        r = c.post("/api/v1/inventory/import", json={"pem": (FIX / "known.pem").read_text(), "location": "web1"},
                   headers=ADMIN)
        assert r.status_code == 200, r.text
        known_id = c.get("/api/v1/certificates?source=imported", headers=ADMIN).json()[0]["id"]

        r = c.post("/api/v1/inventory/keycensus", content=json.dumps(doc), headers=ADMIN)
        assert r.status_code == 200, r.text
        res = r.json()
        assert res["assets"] == 3 and res["new"] == 3
        assert res["certificates_matched"] == 1 and res["certificates_untracked"] == 1

        # the application keycensus linked shows up on Certadillo's certificate
        linked = c.get(f"/api/v1/inventory/external?certificate_id={known_id}", headers=ADMIN).json()
        assert linked[0]["applications"] == ["card-api"] and linked[0]["name"] == "known.pay.bank.internal"
        assert {a["name"] for a in c.get("/api/v1/inventory/external?application=card-api",
                                         headers=ADMIN).json()} == {
            "known.pay.bank.internal", "shadow.pay.bank.internal", "payments-signing.key"}

        # the certificate only keycensus knows about is a finding
        f = c.get("/api/v1/discovery/findings?kind=untracked_certificate", headers=ADMIN).json()
        assert [x["detail"]["name"] for x in f] == ["shadow.pay.bank.internal"]
        assert f[0]["detail"]["applications"] == ["card-api"]

        # keys go into the CBOM next to the certificates
        bom = c.get("/api/v1/reports/cbom", headers=ADMIN).json()
        kc = [x for x in bom["components"] if x["bom-ref"].startswith("keycensus:")]
        assert len(kc) == 1 and {"name": "keycensus:application", "value": "card-api"} in kc[0]["properties"]

        # re-importing is idempotent; an asset missing from a later export is marked removed,
        # and a certificate that is no longer seen closes its finding
        assert c.post("/api/v1/inventory/keycensus", content=json.dumps(doc), headers=ADMIN).json()["new"] == 0
        later = copy.deepcopy(doc)
        later["assets"] = [a for a in later["assets"] if a["name"] != "shadow.pay.bank.internal"]
        assert c.post("/api/v1/inventory/keycensus", content=json.dumps(later), headers=ADMIN).json()["removed"] == 1
        assert c.get("/api/v1/discovery/findings?kind=untracked_certificate", headers=ADMIN).json() == []
        assert [a["name"] for a in c.get("/api/v1/inventory/external?status=removed", headers=ADMIN).json()] == [
            "shadow.pay.bank.internal"]

        # not a keycensus file, and roles
        assert c.post("/api/v1/inventory/keycensus", content=json.dumps({"assets": []}),
                      headers=ADMIN).status_code == 400
        assert c.post("/api/v1/inventory/keycensus", content="not json", headers=ADMIN).status_code == 400
        assert c.post("/api/v1/inventory/keycensus", content=json.dumps(doc),
                      headers={"X-API-Key": "approver-key"}).status_code == 403

        audit = [e["action"] for e in c.get("/api/v1/audit?limit=100", headers=ADMIN).json()]
        assert "inventory.keycensus.import" in audit
