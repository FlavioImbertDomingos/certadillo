"""Build synthetic Windows security descriptors for the AD CS audit tests.

Produces the same self-relative SECURITY_DESCRIPTOR bytes that AD returns in
nTSecurityDescriptor, so the parser and analyzer are exercised on real
wire-format input rather than mocks.
"""
from __future__ import annotations

import struct
import uuid

ACCESS_ALLOWED_ACE_TYPE = 0x00
ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
ACE_OBJECT_TYPE_PRESENT = 0x01


def sid_to_bytes(sid: str) -> bytes:
    parts = sid.split("-")
    assert parts[0] == "S"
    revision = int(parts[1])
    authority = int(parts[2])
    subs = [int(x) for x in parts[3:]]
    out = struct.pack("<BB", revision, len(subs)) + authority.to_bytes(6, "big")
    for s in subs:
        out += struct.pack("<I", s)
    return out


def allowed_ace(sid: str, mask: int) -> bytes:
    sid_b = sid_to_bytes(sid)
    body = struct.pack("<I", mask) + sid_b
    size = 4 + len(body)
    return struct.pack("<BBH", ACCESS_ALLOWED_ACE_TYPE, 0, size) + body


def allowed_object_ace(sid: str, mask: int, object_type: str | None) -> bytes:
    sid_b = sid_to_bytes(sid)
    if object_type:
        flags = ACE_OBJECT_TYPE_PRESENT
        guid = uuid.UUID(object_type).bytes_le
        body = struct.pack("<II", mask, flags) + guid + sid_b
    else:
        body = struct.pack("<II", mask, 0) + sid_b
    size = 4 + len(body)
    return struct.pack("<BBH", ACCESS_ALLOWED_OBJECT_ACE_TYPE, 0, size) + body


def build_acl(aces: list[bytes]) -> bytes:
    data = b"".join(aces)
    size = 8 + len(data)
    return struct.pack("<BBHHH", 2, 0, size, len(aces), 0) + data


def build_sd(owner: str, aces: list[bytes]) -> bytes:
    """Self-relative SD with owner and a DACL. No group/SACL."""
    owner_b = sid_to_bytes(owner)
    dacl = build_acl(aces)
    header_size = 20
    off_owner = header_size
    off_dacl = header_size + len(owner_b)
    control = 0x8004  # SE_SELF_RELATIVE | SE_DACL_PRESENT
    header = struct.pack("<BBHIIII", 1, 0, control, off_owner, 0, 0, off_dacl)
    return header + owner_b + dacl
