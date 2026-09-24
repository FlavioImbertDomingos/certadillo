#!/usr/bin/env python3
"""A throwaway authoritative DNS server for dns-01 interop tests.

Answers TXT and CNAME queries from a JSON file that is re-read on every
query, so ACME client hooks can add and remove records by editing it:

    {"_acme-challenge.www.portal.bank.internal": {"TXT": ["..."]},
     "_acme-challenge.api.portal.bank.internal": {"CNAME": "api.delegate.portal.bank.internal"}}

Usage: tinydns.py records.json [port]      (default port 5353, 127.0.0.1)
Not for production use.
"""
from __future__ import annotations

import json
import socket
import sys

import dns.message
import dns.rcode
import dns.rrset


def answer(resp, records: dict, name: str, depth: int = 0) -> bool:
    rec = records.get(name)
    if rec is None:
        return False
    if "CNAME" in rec and depth < 5:
        resp.answer.append(dns.rrset.from_text(name + ".", 30, "IN", "CNAME", rec["CNAME"].rstrip(".") + "."))
        answer(resp, records, rec["CNAME"].rstrip("."), depth + 1)
        return True
    if rec.get("TXT"):
        resp.answer.append(dns.rrset.from_text_list(name + ".", 30, "IN", "TXT", [f'"{v}"' for v in rec["TXT"]]))
    return True


def main() -> None:
    path = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5353
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    print(f"tinydns on 127.0.0.1:{port} serving {path}", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        try:
            q = dns.message.from_wire(data)
        except Exception:  # noqa: BLE001
            continue
        resp = dns.message.make_response(q)
        name = q.question[0].name.to_text().rstrip(".").lower()
        try:
            with open(path) as f:
                records = {k.lower().rstrip("."): v for k, v in json.load(f).items()}
        except (OSError, ValueError):
            records = {}
        if not answer(resp, records, name):
            resp.set_rcode(dns.rcode.NXDOMAIN)
        print(f"query {name} -> {dns.rcode.to_text(resp.rcode())}", flush=True)
        sock.sendto(resp.to_wire(), addr)


if __name__ == "__main__":
    main()
