"""Findings from the AI code review: an app's scope, the environment label, and
approvals decided after the world changed."""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from certadillo.api.app import create_app
from conftest import ADMIN, APPROVER, make_csr, make_settings, onboard


def _team(client, name="team-scope"):
    r = client.post("/api/v1/teams", json={"name": name, "contact_email": "t@example.com"}, headers=ADMIN)
    return r.json()["id"] if r.status_code == 201 else client.get("/api/v1/teams", headers=ADMIN).json()[0]["id"]


@pytest.mark.parametrize("scope", [["*"], ["*.com"], ["*.internal"], ["a*b.bank.internal"], ["[ab].bank.internal"],
                                   ["spiffe://bank.internal/../core/*"], ["bad name.bank.internal"]])
def test_broad_or_malformed_scopes_are_refused(client, scope):
    r = client.post("/api/v1/apps", json={"team_id": _team(client), "name": "xapp", "environment": "dev",
                                          "profile": "tls-server", "allowed_domains": scope}, headers=ADMIN)
    assert r.status_code in (400, 422), (scope, r.status_code, r.text)


def test_dev_label_does_not_skip_approval_for_names_outside_dev_zones(client):
    # dev_domains in the test settings is bank.internal and bank.example
    r = client.post("/api/v1/apps", json={"team_id": _team(client), "name": "sneaky", "environment": "dev",
                                          "profile": "tls-server", "allowed_domains": ["*.payments.bank.com"]},
                    headers=ADMIN)
    assert r.status_code == 201 and r.json()["status"] == "pending_approval"
    inside = client.post("/api/v1/apps", json={"team_id": _team(client), "name": "fine", "environment": "dev",
                                               "profile": "tls-server", "allowed_domains": ["*.pay.bank.internal"]},
                         headers=ADMIN)
    assert inside.json()["status"] == "active"


def test_without_dev_zones_every_onboarding_needs_a_second_person(tmp_path):
    with TestClient(create_app(make_settings(tmp_path, dev_domains=[]), background=False)) as c:
        r = c.post("/api/v1/apps", json={"team_id": _team(c), "name": "aapp", "environment": "dev",
                                         "profile": "tls-server", "allowed_domains": ["*.pay.bank.internal"]},
                   headers=ADMIN)
        assert r.json()["status"] == "pending_approval"


def test_spiffe_id_with_dot_segments_is_refused(client):
    _, h = onboard(client, "mesh", profile="spiffe-svid", domains=["spiffe://bank.internal/payments/*"])
    _, csr = make_csr(uris=["spiffe://bank.internal/payments/../core/admin"])
    r = client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=h)
    assert r.status_code == 422 and "spiffe_id" in [v["rule"] for v in r.json()["violations"]]


def test_approval_refused_once_the_requester_is_deactivated(client):
    _, h = onboard(client, "signer", profile="code-signing", domains=["release.bank.internal"])
    _, csr = make_csr("Release Signing", key=ec.generate_private_key(ec.SECP384R1()))
    approval = client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=h).json()["approval_id"]
    requester = client.get("/api/v1/approvals", headers=APPROVER).json()[0]["requested_by"]
    assert client.post(f"/api/v1/principals/{requester}/deactivate", headers=ADMIN).status_code == 200
    r = client.post(f"/api/v1/approvals/{approval}/approve", headers=APPROVER)
    assert r.status_code == 403 and "deactivated" in r.text
