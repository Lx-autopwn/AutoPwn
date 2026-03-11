from __future__ import annotations

import re
from typing import TYPE_CHECKING

from pwn import log

if TYPE_CHECKING:
    from autopwn.context import PwnContext

INTERESTING_PATTERNS: list[str] = [
    "/bin/sh",
    "/bin/bash",
    "/bin/cat",
    "sh",
    "flag",
    "cat flag",
    "/flag",
    "flag.txt",
    "/home/",
    "system",
    "execve",
    "%s",
    "%n",
    "%x",
]


def extract_strings(ctx: PwnContext) -> None:
    """Extract useful strings from ELF, write to ctx.useful_strings."""
    elf = ctx.elf
    if elf is None:
        log.warn("strings: no ELF loaded")
        return

    found: dict[str, int] = {}

    try:
        # search for each interesting pattern in ELF data
        for pattern in INTERESTING_PATTERNS:
            try:
                results = elf.search(pattern.encode())
                for addr in results:
                    found[pattern] = addr
                    break  # keep first occurrence
            except (StopIteration, ValueError):
                continue

        # also search for /bin/sh as null-terminated
        try:
            for addr in elf.search(b"/bin/sh\x00"):
                found["/bin/sh"] = addr
                break
        except (StopIteration, ValueError):
            pass

        # search readable sections for interesting strings via regex
        _search_sections(elf, found)

    except Exception as e:
        log.warn(f"strings extraction error: {e}")

    ctx.useful_strings = found
    if found:
        log.info(f"strings: found {len(found)} useful strings")
        for s, addr in found.items():
            log.debug(f"  {addr:#x}: {s!r}")
    else:
        log.info("strings: no useful strings found")


def _search_sections(elf, found: dict[str, int]) -> None:
    """Search readable sections for flag-related paths."""
    flag_re = re.compile(rb"(flag[\w./]*\.txt|/home/\w+/flag)", re.IGNORECASE)
    for section_name in (".rodata", ".data"):
        try:
            section = elf.get_section_by_name(section_name)
            if section is None:
                continue
            data = section.data()
            base = section.header.sh_addr
            for m in flag_re.finditer(data):
                s = m.group(0).decode("ascii", errors="ignore")
                if s not in found:
                    found[s] = base + m.start()
        except Exception:
            continue
