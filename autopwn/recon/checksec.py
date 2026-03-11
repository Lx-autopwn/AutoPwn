from __future__ import annotations

from typing import TYPE_CHECKING

from pwn import log

if TYPE_CHECKING:
    from autopwn.context import PwnContext


def run_checksec(ctx: PwnContext) -> None:
    """Extract security mitigations from the ELF."""
    elf = ctx.elf
    if elf is None:
        log.warn("checksec: no ELF loaded")
        return

    try:
        ctx.nx = bool(elf.execstack) is False  # execstack=False means NX on
        ctx.pie = bool(elf.pie)
        ctx.canary = bool(elf.canary)

        relro = elf.relro
        if relro is None:
            ctx.relro = "no"
        elif relro == "Full":
            ctx.relro = "full"
        elif relro == "Partial":
            ctx.relro = "partial"
        else:
            ctx.relro = str(relro).lower()

        ctx.fortify = bool(getattr(elf, "fortify", False))

        log.info(
            f"checksec: NX={ctx.nx} PIE={ctx.pie} Canary={ctx.canary} "
            f"RELRO={ctx.relro} Fortify={ctx.fortify}"
        )
    except Exception as e:
        log.warn(f"checksec failed: {e}")
