from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from pwn import log

if TYPE_CHECKING:
    pass

# Common bad-byte sets for various input functions
_FUNC_BAD_BYTES: dict[str, bytes] = {
    "gets": b"\x00\n",          # null + newline
    "scanf": b"\x00\t\n\x0b\x0c\r ",  # null + whitespace
    "fgets": b"\x00\n",
    "strcpy": b"\x00",
    "strcat": b"\x00",
    "strncpy": b"\x00",
    "read": b"",                # read() accepts everything
    "fread": b"",
    "recv": b"",
    "recvfrom": b"",
    "__isoc99_scanf": b"\x00\t\n\x0b\x0c\r ",
}


def detect_bad_bytes(binary_path: str, input_func: str = "read") -> bytes:
    """Return the known bad bytes for *input_func*.

    For ``read()`` / ``recv()`` there are no inherent bad bytes (the kernel
    delivers everything).  For ``gets()`` / ``scanf()`` we know the
    problematic characters statically.

    A more precise dynamic probe could be added later.
    """
    func_lower = input_func.lower().strip()

    # direct lookup
    if func_lower in _FUNC_BAD_BYTES:
        bad = _FUNC_BAD_BYTES[func_lower]
        if bad:
            log.info(f"Bad bytes for {input_func}: {bad.hex()}")
        return bad

    # conservative default: at least null byte is dangerous
    log.info(f"Unknown input func '{input_func}', assuming \\x00 is bad")
    return b"\x00"


def filter_payload(payload: bytes, bad_bytes: bytes) -> bytes | None:
    """Return *payload* if it contains no bad bytes, else ``None``."""
    if not bad_bytes:
        return payload
    for b in bad_bytes:
        if b in payload:
            log.debug(f"Payload contains bad byte 0x{b:02x}")
            return None
    return payload


def has_bad_bytes(payload: bytes, bad_bytes: bytes) -> bool:
    """Check whether *payload* contains any of *bad_bytes*."""
    if not bad_bytes:
        return False
    return any(b in payload for b in bad_bytes)


def encode_payload(payload: bytes, bad_bytes: bytes, arch: str = "amd64") -> bytes:
    """Try to encode *payload* to avoid *bad_bytes*.

    Currently a best-effort approach: if the payload already passes, return
    it as-is.  Otherwise, for ROP-style payloads (sequences of addresses),
    there is no generic encoding -- we just return the original and let the
    caller decide.

    For shellcode payloads, we delegate to ``pwnlib.encoders`` when
    available.
    """
    if not bad_bytes or not has_bad_bytes(payload, bad_bytes):
        return payload

    # try pwntools encoder (works for shellcode, not for ROP chains)
    try:
        from pwnlib.encoders import encode as pwn_encode
        encoded = pwn_encode(payload, avoid=bad_bytes)
        if encoded and not has_bad_bytes(encoded, bad_bytes):
            log.success("Payload encoded to avoid bad bytes")
            return encoded
    except Exception:
        pass

    log.warning("Could not encode payload to avoid bad bytes")
    return payload
