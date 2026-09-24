"""Parse a Windows self-relative SECURITY_DESCRIPTOR (nTSecurityDescriptor).

Just enough to read the owner and the DACL: the access mask, the SID it
applies to, and the ObjectType GUID of object ACEs (which is how AD encodes
the "Enroll" extended right and per-property write rights). No external
dependency; the layout is MS-DTYP 2.4.6 for the descriptor, 2.4.4 for the
ACEs and 2.4.2 for the SID.
"""
from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field

# ACE types we care about (MS-DTYP 2.4.4.1)
ACCESS_ALLOWED_ACE_TYPE = 0x00
ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05

# Object ACE flags (MS-DTYP 2.4.4.3)
ACE_OBJECT_TYPE_PRESENT = 0x01
ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x02

# Access mask bits relevant to AD objects (MS-ADTS 5.1.3.2)
RIGHT_DS_CONTROL_ACCESS = 0x00000100  # "extended right" / control access
RIGHT_DS_WRITE_PROP = 0x00000020
RIGHT_WRITE_DACL = 0x00040000
RIGHT_WRITE_OWNER = 0x00080000
RIGHT_GENERIC_ALL = 0x10000000
RIGHT_GENERIC_WRITE = 0x40000000


def _sid_to_string(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a SID starting at offset; return (string, bytes_consumed)."""
    revision = data[offset]
    sub_count = data[offset + 1]
    authority = int.from_bytes(data[offset + 2 : offset + 8], "big")
    parts = [f"S-{revision}-{authority}"]
    pos = offset + 8
    for _ in range(sub_count):
        parts.append(str(struct.unpack_from("<I", data, pos)[0]))
        pos += 4
    return "-".join(parts), pos - offset


@dataclass
class Ace:
    sid: str
    mask: int
    object_type: str | None = None  # GUID string, lowercased, or None
    ace_type: int = ACCESS_ALLOWED_ACE_TYPE

    def has(self, bit: int) -> bool:
        return bool(self.mask & bit)


@dataclass
class SecurityDescriptor:
    owner: str | None = None
    group: str | None = None
    aces: list[Ace] = field(default_factory=list)

    @classmethod
    def parse(cls, data: bytes) -> "SecurityDescriptor":
        if len(data) < 20:
            raise ValueError("security descriptor too short")
        (revision, _sbz1, _control, off_owner, off_group, _off_sacl, off_dacl) = struct.unpack_from(
            "<BBHIIII", data, 0
        )
        sd = cls()
        if off_owner:
            sd.owner = _sid_to_string(data, off_owner)[0]
        if off_group:
            sd.group = _sid_to_string(data, off_group)[0]
        if off_dacl:
            sd.aces = cls._parse_acl(data, off_dacl)
        return sd

    @staticmethod
    def _parse_acl(data: bytes, offset: int) -> list[Ace]:
        (_rev, _sbz1, _size, count, _sbz2) = struct.unpack_from("<BBHHH", data, offset)
        pos = offset + 8
        aces: list[Ace] = []
        for _ in range(count):
            ace_type, _flags, ace_size = struct.unpack_from("<BBH", data, pos)
            body = pos + 4
            if ace_type == ACCESS_ALLOWED_ACE_TYPE:
                mask = struct.unpack_from("<I", data, body)[0]
                sid, _ = _sid_to_string(data, body + 4)
                aces.append(Ace(sid=sid, mask=mask, ace_type=ace_type))
            elif ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                mask, obj_flags = struct.unpack_from("<II", data, body)
                p = body + 8
                object_type = None
                if obj_flags & ACE_OBJECT_TYPE_PRESENT:
                    object_type = str(uuid.UUID(bytes_le=data[p : p + 16]))
                    p += 16
                if obj_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT:
                    p += 16
                sid, _ = _sid_to_string(data, p)
                aces.append(Ace(sid=sid, mask=mask, object_type=object_type, ace_type=ace_type))
            # other ACE types (deny, audit) are ignored: they do not grant enrollment
            pos += ace_size
        return aces
