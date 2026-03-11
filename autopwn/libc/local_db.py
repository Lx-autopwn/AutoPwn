from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from pwn import ELF, log

if TYPE_CHECKING:
    pass

# Directories to search for libc on the local system
_SEARCH_DIRS: list[str] = [
    "/lib/x86_64-linux-gnu",
    "/lib/i386-linux-gnu",
    "/lib/aarch64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/i386-linux-gnu",
    "/usr/lib",
    "/lib",
    "/lib32",
    "/lib64",
    "/usr/lib32",
    "/usr/lib64",
]


def find_local_libc(known_offsets: dict[str, int]) -> str | None:
    """Search local system for a libc matching *known_offsets*.

    Parameters
    ----------
    known_offsets:
        Symbol name to **offset within libc**, e.g.
        ``{"puts": 0x80970, "printf": 0x60e10}``.

    Returns
    -------
    str | None
        Path to matching libc, or ``None``.
    """
    if not known_offsets:
        return None

    candidates = _find_libc_files()
    if not candidates:
        log.info("No libc candidates found on local system")
        return None

    log.info(f"Checking {len(candidates)} local libc candidate(s)")

    for path in candidates:
        try:
            elf = ELF(path, checksec=False)
        except Exception:
            continue

        match = True
        for sym, expected_off in known_offsets.items():
            actual = elf.symbols.get(sym, None)
            if actual is None:
                match = False
                break
            if actual != expected_off:
                match = False
                break

        if match:
            log.success(f"Local libc match: {path}")
            return path

    log.info("No local libc matched the given offsets")
    return None


def get_libc_version(libc_path: str) -> str:
    """Extract the glibc version string (e.g. ``'2.31'``) from a libc.

    Tries multiple methods: strings output, ELF .rodata, ldd.
    """
    # method 1: strings | grep "GNU C Library"
    try:
        result = subprocess.run(
            ["strings", libc_path],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            m = re.search(r"GNU C Library.*?(\d+\.\d+)", line)
            if m:
                return m.group(1)
            m = re.search(r"GLIBC[_ ](\d+\.\d+)", line)
            if m:
                return m.group(1)
    except Exception:
        pass

    # method 2: run the libc itself (glibc prints version info when executed)
    try:
        result = subprocess.run(
            [libc_path],
            capture_output=True, text=True, timeout=5,
        )
        out = result.stdout + result.stderr
        m = re.search(r"release version (\d+\.\d+)", out)
        if m:
            return m.group(1)
        m = re.search(r"GLIBC (\d+\.\d+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass

    # method 3: filename heuristic (libc-2.31.so)
    base = os.path.basename(libc_path)
    m = re.search(r"(\d+\.\d+)", base)
    if m:
        return m.group(1)

    return ""


# ------------------------------------------------------------------
# internals
# ------------------------------------------------------------------

def _find_libc_files() -> list[str]:
    """Collect all libc.so* files from known system directories."""
    results: list[str] = []
    seen: set[str] = set()

    for d in _SEARCH_DIRS:
        p = Path(d)
        if not p.is_dir():
            continue
        for f in p.iterdir():
            if not f.is_file():
                continue
            name = f.name
            if name.startswith("libc.so") or name.startswith("libc-"):
                real = str(f.resolve())
                if real not in seen:
                    seen.add(real)
                    results.append(real)

    return results
