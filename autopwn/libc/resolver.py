from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from pwn import ELF, log

if TYPE_CHECKING:
    pass


def resolve_symbols(libc_path: str, symbols: list[str]) -> dict[str, int]:
    """Resolve symbol offsets within a libc binary.

    Parameters
    ----------
    libc_path:
        Path to libc.so.
    symbols:
        List of symbol names to resolve (e.g. ``["system", "execve", "puts"]``).

    Returns
    -------
    dict[str, int]
        Symbol name to offset within libc.  Missing symbols are omitted.
    """
    try:
        elf = ELF(libc_path, checksec=False)
    except Exception as e:
        log.warning(f"Failed to load libc {libc_path}: {e}")
        return {}

    result: dict[str, int] = {}
    for sym in symbols:
        addr = elf.symbols.get(sym)
        if addr is not None:
            result[sym] = addr
        else:
            log.debug(f"Symbol '{sym}' not found in {libc_path}")
    return result


def find_bin_sh(libc_path: str) -> int:
    """Find the offset of ``/bin/sh`` string in libc.

    Returns 0 if not found.
    """
    try:
        elf = ELF(libc_path, checksec=False)
    except Exception as e:
        log.warning(f"Failed to load libc: {e}")
        return 0

    try:
        addr = next(elf.search(b"/bin/sh\x00"))
        log.info(f"/bin/sh found at offset {addr:#x}")
        return addr
    except StopIteration:
        pass

    # fallback: strings + grep
    try:
        result = subprocess.run(
            ["strings", "-t", "x", libc_path],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if "/bin/sh" in line:
                parts = line.split(None, 1)
                if len(parts) == 2 and parts[1].strip() == "/bin/sh":
                    addr = int(parts[0], 16)
                    log.info(f"/bin/sh found via strings at offset {addr:#x}")
                    return addr
    except Exception:
        pass

    log.warning("/bin/sh not found in libc")
    return 0


def resolve_with_base(
    libc_path: str,
    base: int,
    symbols: list[str],
) -> dict[str, int]:
    """Resolve runtime addresses given a known libc base.

    Parameters
    ----------
    libc_path:
        Path to libc.so.
    base:
        Runtime base address of libc.
    symbols:
        Symbols to resolve.

    Returns
    -------
    dict[str, int]
        Symbol name to runtime (absolute) address.
    """
    offsets = resolve_symbols(libc_path, symbols)
    result: dict[str, int] = {}
    for sym, off in offsets.items():
        result[sym] = base + off
        log.info(f"  {sym} = {result[sym]:#x} (base + {off:#x})")
    return result
