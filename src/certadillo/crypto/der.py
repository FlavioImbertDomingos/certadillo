"""Just enough DER to swap the signature on an X.509 structure.

cryptography's builders only sign with in-process private keys. To sign with
an HSM we let the builder sign with a throwaway key of the same algorithm,
keep its to-be-signed bytes (which already carry the right AlgorithmIdentifier),
sign those bytes on the HSM, and rebuild the outer SEQUENCE.
"""
from __future__ import annotations


def _read_len(data: bytes, pos: int) -> tuple[int, int]:
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    n = first & 0x7F
    if n == 0 or n > 4:
        raise ValueError("unsupported DER length")
    return int.from_bytes(data[pos : pos + n], "big"), pos + n


def encode_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + encode_len(len(value)) + value


def split_sequence(data: bytes) -> list[bytes]:
    """Return the raw TLV encodings of each child of the outer SEQUENCE."""
    if data[0] != 0x30:
        raise ValueError("not a SEQUENCE")
    length, pos = _read_len(data, 1)
    end = pos + length
    children = []
    while pos < end:
        start = pos
        pos += 1  # tag (all X.509 top-level tags are single byte)
        clen, pos = _read_len(data, pos)
        pos += clen
        children.append(data[start:pos])
    return children


def replace_signature(signed_der: bytes, tbs_der: bytes, signature: bytes) -> bytes:
    """Rebuild Certificate / CertificateList with a new signature value."""
    children = split_sequence(signed_der)
    if len(children) != 3 or children[0] != tbs_der:
        raise ValueError("unexpected structure")
    sig_bits = tlv(0x03, b"\x00" + signature)
    return tlv(0x30, children[0] + children[1] + sig_bits)
