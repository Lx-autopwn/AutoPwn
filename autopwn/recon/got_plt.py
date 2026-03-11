from __future__ import annotations

from typing import TYPE_CHECKING

from pwn import log

if TYPE_CHECKING:
    from autopwn.context import PwnContext


def analyze_got_plt(ctx: PwnContext) -> None:
    """Extract GOT and PLT tables, write to ctx.got_table, ctx.plt_table."""
    elf = ctx.elf
    if elf is None:
        log.warn("got_plt: no ELF loaded")
        return

    got: dict[str, int] = {}
    plt: dict[str, int] = {}

    try:
        for name, addr in elf.got.items():
            if name and addr:
                got[name] = addr
    except Exception as e:
        log.warn(f"got_plt: GOT extraction failed: {e}")

    try:
        for name, addr in elf.plt.items():
            if name and addr:
                plt[name] = addr
    except Exception as e:
        log.warn(f"got_plt: PLT extraction failed: {e}")

    ctx.got_table = got
    ctx.plt_table = plt
    log.info(f"got_plt: GOT={len(got)} entries, PLT={len(plt)} entries")
