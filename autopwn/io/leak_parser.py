from __future__ import annotations

import re
import struct
from typing import TYPE_CHECKING

from pwn import log

if TYPE_CHECKING:
    pass


def parse_leak(data: bytes, bits: int = 64) -> int:
    """Parse a leaked address from raw bytes, hex string, or puts output.

    Tries several heuristics in order:
    1. Hex string like ``0x7f1234567890``
    2. Raw bytes (puts-style, possibly null-truncated)
    """
    if not data:
        return 0

    # strip trailing whitespace / newlines
    stripped = data.strip()

    # try hex string first (e.g. from printf %p)
    addr = _try_hex(stripped)
    if addr:
        return addr

    # fall back to raw bytes
    return parse_puts_leak(data, bits)


def parse_puts_leak(data: bytes, bits: int = 64) -> int:
    """Parse puts-style leak (raw bytes, possibly null-truncated by puts).

    ``puts()`` stops at the first null byte but appends a newline, so a
    leaked address like ``\\x90\\x56\\x34\\x12\\x7f`` (5 bytes) means the
    6th byte was ``\\x00``.  We strip the trailing newline, take up to
    ``bits // 8`` bytes, and right-pad with ``\\x00``.
    """
    addr_len = bits // 8

    # strip trailing newline(s) that puts adds
    raw = data
    while raw.endswith(b"\n"):
        raw = raw[:-1]

    if not raw:
        # all-null address (puts outputs just a newline for \\x00...)
        return 0

    raw = raw[:addr_len]
    raw = raw.ljust(addr_len, b"\x00")

    return int.from_bytes(raw, "little")


def parse_printf_leak(data: bytes) -> int:
    """Parse ``printf("%p", addr)`` or ``printf("0x%lx", addr)`` output."""
    stripped = data.strip()
    addr = _try_hex(stripped)
    if addr:
        return addr

    # sometimes surrounded by other text; extract first hex-looking thing
    addrs = extract_address_from_output(data)
    if addrs:
        return addrs[0]
    return 0


def extract_address_from_output(data: bytes, bits: int = 64) -> list[int]:
    """Extract all plausible addresses from binary output.

    Looks for hex patterns like ``0x7f...`` or ``0x56...`` in the text.
    """
    results: list[int] = []
    try:
        text = data.decode("latin-1")
    except Exception:
        text = data.decode("utf-8", errors="replace")

    if bits == 64:
        # 64-bit: 10-14 hex digits (user-space addresses)
        pattern = r"0x([0-9a-fA-F]{8,14})"
    else:
        # 32-bit: 7-8 hex digits
        pattern = r"0x([0-9a-fA-F]{6,8})"

    for m in re.finditer(pattern, text):
        try:
            val = int(m.group(1), 16)
            if _plausible_address(val, bits):
                results.append(val)
        except ValueError:
            continue
    return results


# ------------------------------------------------------------------
# internal helpers
# ------------------------------------------------------------------

_HEX_RE = re.compile(rb"^(?:0x)?([0-9a-fA-F]+)$")


def _try_hex(data: bytes) -> int:
    """Try to parse *data* as a hex string, return 0 on failure."""
    m = _HEX_RE.match(data.strip())
    if m:
        try:
            return int(m.group(1), 16)
        except ValueError:
            pass
    return 0


def _plausible_address(val: int, bits: int = 64) -> bool:
    """Check if *val* looks like a plausible user-space address."""
    if val == 0:
        return False
    if bits == 64:
        # typical user-space ranges
        return (0x400000 <= val <= 0x7fffffffffff) or (0x55_0000000000 <= val <= 0x7f_ffffffffffff)
    else:
        return 0x08000000 <= val <= 0xffffffff
