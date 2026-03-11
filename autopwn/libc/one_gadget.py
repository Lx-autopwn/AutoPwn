from __future__ import annotations

import re
import subprocess
from typing import TYPE_CHECKING

from pwn import log

if TYPE_CHECKING:
    pass


def find_one_gadgets(libc_path: str) -> list[dict]:
    """Run ``one_gadget`` on *libc_path* and parse the results.

    Returns
    -------
    list[dict]
        Each entry::

            {
                "offset": 0x4f3d5,
                "constraints": ["rax == NULL", "[rsp+0x70] == NULL"],
            }

        Empty list if ``one_gadget`` is not installed or finds nothing.
    """
    try:
        result = subprocess.run(
            ["one_gadget", libc_path],
            capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        log.warning("one_gadget not installed")
        return []
    except subprocess.TimeoutExpired:
        log.warning("one_gadget timed out")
        return []

    if result.returncode != 0 and not result.stdout.strip():
        log.warning(f"one_gadget failed: {result.stderr.strip()}")
        return []

    gadgets = _parse_output(result.stdout)

    if gadgets:
        log.info(f"Found {len(gadgets)} one_gadget(s) in {libc_path}")
        for g in gadgets:
            constraints = ", ".join(g["constraints"]) if g["constraints"] else "none"
            log.info(f"  {g['offset']:#x}  constraints: {constraints}")
    else:
        log.info("No one_gadgets found")

    return gadgets


def find_one_gadgets_with_base(libc_path: str, base: int) -> list[dict]:
    """Like :func:`find_one_gadgets` but adds ``"address"`` (base + offset)."""
    gadgets = find_one_gadgets(libc_path)
    for g in gadgets:
        g["address"] = base + g["offset"]
    return gadgets


# ------------------------------------------------------------------
# parser
# ------------------------------------------------------------------

_OFFSET_RE = re.compile(r"^(0x[0-9a-fA-F]+)\s")
_CONSTRAINT_RE = re.compile(r"^\s*(.+)$")


def _parse_output(output: str) -> list[dict]:
    """Parse one_gadget's stdout.

    Typical output::

        0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
        constraints:
          rax == NULL

        0x4f432 execve("/bin/sh", rsp+0x40, environ)
        constraints:
          rsp & 0xf == 0
          rcx == NULL
    """
    gadgets: list[dict] = []
    lines = output.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i].strip()
        m = _OFFSET_RE.match(line)
        if m:
            offset = int(m.group(1), 16)
            constraints: list[str] = []

            # look for "constraints:" line
            i += 1
            if i < len(lines) and "constraints:" in lines[i].lower():
                i += 1
                while i < len(lines):
                    cline = lines[i].strip()
                    if not cline or _OFFSET_RE.match(cline):
                        break
                    constraints.append(cline)
                    i += 1
            gadgets.append({
                "offset": offset,
                "constraints": constraints,
            })
        else:
            i += 1

    return gadgets
