from __future__ import annotations

from typing import TYPE_CHECKING

from pwn import log

if TYPE_CHECKING:
    from autopwn.context import PwnContext


def analyze_binary(ctx: PwnContext) -> None:
    """Analyze ELF basic info: arch, bits, endian, static/stripped."""
    elf = ctx.elf
    if elf is None:
        log.warn("binary: no ELF loaded")
        return

    try:
        ctx.arch = elf.arch
        ctx.bits = elf.bits
        ctx.endian = elf.endian

        # static linked: no INTERP segment and no dynamic section
        ctx.is_static = not bool(getattr(elf, "libs", None))
        if hasattr(elf, "elftype"):
            # double check via segments
            try:
                interp = elf.get_section_by_name(".interp")
                ctx.is_static = interp is None
            except Exception:
                pass

        # stripped: no .symtab section
        try:
            symtab = elf.get_section_by_name(".symtab")
            ctx.is_stripped = symtab is None
        except Exception:
            ctx.is_stripped = len(elf.sym) < 5

        static_str = "static" if getattr(ctx, "is_static", False) else "dynamic"
        stripped_str = "stripped" if getattr(ctx, "is_stripped", False) else "not stripped"
        log.info(
            f"binary: {ctx.arch} {ctx.bits}-bit {ctx.endian} "
            f"({static_str}, {stripped_str})"
        )
    except Exception as e:
        log.warn(f"binary analysis failed: {e}")
