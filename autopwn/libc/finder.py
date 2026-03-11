from __future__ import annotations

import json
from typing import TYPE_CHECKING

from pwn import log

from autopwn.config import LIBC_RIP_URL

if TYPE_CHECKING:
    pass


def find_libc_online(known_symbols: dict[str, int]) -> list[dict]:
    """Query libc.rip API with leaked symbol addresses.

    Parameters
    ----------
    known_symbols:
        Mapping of symbol name to its **runtime** address, e.g.
        ``{"puts": 0x7f1234567890}``.
        The low 12 bits (page offset) are extracted automatically.

    Returns
    -------
    list[dict]
        Each entry: ``{"id": "libc6_...", "download_url": "...",
        "symbols": {"puts": ..., "system": ..., ...}}``.
        Empty list on failure.
    """
    if not known_symbols:
        log.warning("find_libc_online: no symbols provided")
        return []

    # build query: libc.rip wants {"symbols": {"puts": "0x690"}}
    symbols_query: dict[str, str] = {}
    for name, addr in known_symbols.items():
        offset = addr & 0xFFF  # low 12 bits
        symbols_query[name] = hex(offset)

    payload = json.dumps({"symbols": symbols_query}).encode()
    log.info(f"Querying libc.rip with: {symbols_query}")

    try:
        import urllib.request

        req = urllib.request.Request(
            LIBC_RIP_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        log.warning(f"libc.rip query failed: {e}")
        return []

    if not isinstance(data, list):
        log.warning(f"libc.rip unexpected response: {type(data)}")
        return []

    log.info(f"libc.rip returned {len(data)} candidate(s)")
    for entry in data[:5]:
        log.info(f"  {entry.get('id', '?')}")

    return data


def download_libc(url: str, dest: str) -> bool:
    """Download a libc from *url* to *dest*.

    Returns True on success.
    """
    try:
        import urllib.request

        log.info(f"Downloading libc from {url}")
        urllib.request.urlretrieve(url, dest)
        log.success(f"Saved to {dest}")
        return True
    except Exception as e:
        log.warning(f"Download failed: {e}")
        return False
