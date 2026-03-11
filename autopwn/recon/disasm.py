from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from pwn import log

if TYPE_CHECKING:
    from autopwn.context import PwnContext


def disassemble_function(ctx: PwnContext, func_name: str) -> str:
    """Disassemble a function by name. Returns readable disassembly string."""
    elf = ctx.elf
    if elf is None:
        return ""

    # resolve function address and size
    addr = elf.sym.get(func_name, 0)
    if not addr:
        log.warn(f"disasm: function {func_name!r} not found")
        return ""

    # try objdump for best output
    result = _disasm_objdump(ctx.binary_path, func_name)
    if result:
        return result

    # fallback: pwntools disasm
    return _disasm_pwntools(elf, addr)


def disassemble_address(ctx: PwnContext, addr: int, count: int = 20) -> str:
    """Disassemble `count` instructions starting at `addr`."""
    elf = ctx.elf
    if elf is None:
        return ""

    # try objdump
    result = _disasm_objdump_addr(ctx.binary_path, addr, count)
    if result:
        return result

    # fallback: pwntools
    return _disasm_pwntools(elf, addr, count * 8)


def _disasm_objdump(binary_path: str, func_name: str) -> str:
    """Disassemble a function using objdump."""
    try:
        proc = subprocess.run(
            ["objdump", "-d", binary_path],
            capture_output=True, text=True, timeout=15,
        )
        lines = proc.stdout.splitlines()
        capture = False
        result = []
        for line in lines:
            if f"<{func_name}>:" in line:
                capture = True
                result.append(line)
                continue
            if capture:
                if line and not line.startswith(" ") and ":" in line and "<" in line:
                    break  # next function
                if not line.strip():
                    if result:
                        break
                    continue
                result.append(line)
        return "\n".join(result)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def _disasm_objdump_addr(binary_path: str, addr: int, count: int) -> str:
    """Disassemble starting from address using objdump."""
    try:
        start = f"{addr:#x}"
        stop = f"{addr + count * 15:#x}"  # upper bound
        proc = subprocess.run(
            [
                "objdump", "-d", binary_path,
                f"--start-address={start}",
                f"--stop-address={stop}",
            ],
            capture_output=True, text=True, timeout=15,
        )
        lines = []
        collecting = False
        for line in proc.stdout.splitlines():
            stripped = line.strip()
            if stripped and stripped[0].isalnum() and ":" in stripped:
                collecting = True
            if collecting:
                if not stripped:
                    break
                lines.append(line)
                if len(lines) >= count:
                    break
        return "\n".join(lines)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def _disasm_pwntools(elf, addr: int, size: int = 256) -> str:
    """Fallback disassembly using pwntools."""
    try:
        data = elf.read(addr, size)
        from pwn import context as pwn_context, disasm

        old_arch = pwn_context.arch
        old_bits = pwn_context.bits
        try:
            pwn_context.arch = elf.arch
            pwn_context.bits = elf.bits
            return disasm(data, vma=addr)
        finally:
            pwn_context.arch = old_arch
            pwn_context.bits = old_bits
    except Exception as e:
        log.debug(f"disasm pwntools fallback failed: {e}")
        return ""
