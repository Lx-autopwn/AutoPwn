from __future__ import annotations

import re
import subprocess
from typing import TYPE_CHECKING, Any

from pwn import log

from autopwn.config import (
    DANGEROUS_FUNCS,
    FORMAT_FUNCS,
    HEAP_ALLOC_FUNCS,
    HEAP_FREE_FUNCS,
    INPUT_FUNC_NAMES,
    OUTPUT_FUNC_NAMES,
    SKIP_FUNCS,
    SYSTEM_CALLS,
    WIN_FUNC_NAMES,
)

if TYPE_CHECKING:
    from autopwn.context import PwnContext


def _strip_plt(name: str) -> str:
    """Remove @plt suffix, leading underscores, and common prefixes for matching."""
    name = name.split("@")[0]
    name = name.lstrip("_")
    # Remove glibc internal prefixes like "isoc99_" or "GI_"
    for prefix in ("isoc99_", "GI_", "libc_"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return name


def _match(name: str, patterns: list[str]) -> bool:
    clean = _strip_plt(name).lower()
    return any(p.lower() == clean for p in patterns)


def _make_entry(name: str, addr: int, source: str = "sym") -> dict[str, Any]:
    return {"name": name, "addr": addr, "source": source}


def _detect_win_by_disasm(ctx: PwnContext) -> list[dict[str, Any]]:
    """Find functions that call system/execve via objdump.

    For stripped binaries (where only section labels like ``.text`` exist),
    track ``push %rbp`` / ``endbr64`` prologues to identify real function
    boundaries and report the correct address.
    """
    results = []
    if ctx.elf is None:
        return results
    try:
        proc = subprocess.run(
            ["objdump", "-d", ctx.binary_path],
            capture_output=True, text=True, timeout=15,
        )
        current_func = None
        current_addr = 0
        is_section_label = False
        # For stripped binaries: track the most recent function prologue
        last_prologue_addr = 0

        for line in proc.stdout.splitlines():
            # function header: 0000000000401196 <vuln>:
            if line and not line.startswith(" ") and "<" in line and ">:" in line:
                name = line.split("<")[1].split(">")[0]
                addr_str = line.split()[0]
                try:
                    current_addr = int(addr_str, 16)
                except ValueError:
                    current_addr = 0
                current_func = name
                is_section_label = name.startswith(".")
                if not is_section_label:
                    last_prologue_addr = current_addr
            elif current_func:
                # Track function prologues in stripped binaries
                if is_section_label:
                    m = re.match(r"\s*([0-9a-f]+):", line)
                    if m and ("push" in line and "%rbp" in line
                              or "push" in line and "%ebp" in line
                              or "endbr64" in line or "endbr32" in line):
                        last_prologue_addr = int(m.group(1), 16)

                # call to system/execve
                if "call" in line.lower():
                    for sc in SYSTEM_CALLS:
                        if f"<{sc}" in line or f"<{sc}@plt>" in line:
                            if is_section_label and last_prologue_addr:
                                func_name = f"sub_{last_prologue_addr:x}"
                                func_addr = last_prologue_addr
                            else:
                                func_name = current_func
                                func_addr = current_addr

                            if not _match(func_name, SKIP_FUNCS + SYSTEM_CALLS):
                                results.append(
                                    _make_entry(func_name, func_addr, "disasm")
                                )
                            break
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return results


def identify_functions(ctx: PwnContext) -> None:
    """Identify and classify all functions, writing results to ctx."""
    elf = ctx.elf
    if elf is None:
        log.warn("functions: no ELF loaded")
        return

    all_syms: dict[str, int] = {}
    # collect from .sym (includes PLT entries)
    for name, addr in elf.sym.items():
        if name and addr and not _match(name, SKIP_FUNCS):
            all_syms[name] = addr
    # collect from PLT specifically
    for name, addr in elf.plt.items():
        if name and addr:
            all_syms[name] = addr

    dangerous = []
    win = []
    inputs = []
    outputs = []
    heap_alloc = []
    heap_free = []
    fmt_funcs = []

    for name, addr in all_syms.items():
        entry = _make_entry(name, addr)
        if _match(name, WIN_FUNC_NAMES):
            win.append(entry)
        if _match(name, DANGEROUS_FUNCS):
            dangerous.append(entry)
        if _match(name, INPUT_FUNC_NAMES):
            inputs.append(entry)
        if _match(name, OUTPUT_FUNC_NAMES):
            outputs.append(entry)
        if _match(name, HEAP_ALLOC_FUNCS):
            heap_alloc.append(entry)
        if _match(name, HEAP_FREE_FUNCS):
            heap_free.append(entry)
        if _match(name, FORMAT_FUNCS):
            fmt_funcs.append(entry)

    # detect win functions by disassembly (system() callers)
    disasm_wins = _detect_win_by_disasm(ctx)
    seen = {f["name"] for f in win}
    for w in disasm_wins:
        if w["name"] not in seen:
            win.append(w)
            seen.add(w["name"])

    # Detect required arguments for win functions
    if win:
        _detect_win_args(ctx, win)

    ctx.dangerous_funcs = dangerous
    ctx.win_funcs = win
    ctx.input_funcs = inputs
    ctx.output_funcs = outputs

    # store extra categories as attributes for downstream use
    ctx.heap_alloc_funcs = heap_alloc  # type: ignore[attr-defined]
    ctx.heap_free_funcs = heap_free  # type: ignore[attr-defined]
    ctx.format_funcs = fmt_funcs  # type: ignore[attr-defined]

    log.info(
        f"functions: {len(dangerous)} dangerous, {len(win)} win, "
        f"{len(inputs)} input, {len(outputs)} output, "
        f"{len(heap_alloc)} heap_alloc, {len(heap_free)} heap_free, "
        f"{len(fmt_funcs)} format"
    )


def _detect_win_args(ctx: PwnContext, win_funcs: list[dict[str, Any]]) -> None:
    """Detect required arguments for win functions by analyzing disassembly.

    Looks for patterns like:
      cmp  $0xdeadbeef,%rdi / %edi   → arg1 must be 0xdeadbeef
      cmp  $0xcafebabe,%rsi / %esi   → arg2 must be 0xcafebabe
      cmp  $0x1234,%edx / %rdx       → arg3 must be 0x1234

    Also detects 64-bit: movabs + cmp reg,reg patterns.
    """
    try:
        proc = subprocess.run(
            ["objdump", "-d", ctx.binary_path],
            capture_output=True, text=True, timeout=15,
        )
        disasm = proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return

    for wf in win_funcs:
        fname = wf.get("name", "")
        faddr = wf.get("addr", 0)
        if not fname or not faddr:
            continue

        func_lines = _extract_func_lines(disasm, fname, faddr)
        if not func_lines:
            continue

        args = _parse_cmp_args(func_lines, ctx.bits)
        if args:
            wf["args"] = args
            arg_str = ", ".join(f"arg{i+1}={v:#x}" for i, v in enumerate(args))
            log.info(f"functions: win {fname} requires: {arg_str}")


def _extract_func_lines(disasm: str, func_name: str, func_addr: int) -> list[str]:
    """Extract disassembly lines for a specific function."""
    lines = []
    in_func = False
    for line in disasm.splitlines():
        if f"<{func_name}>:" in line:
            in_func = True
            continue
        if in_func:
            if line and not line.startswith(" ") and ">:" in line:
                break
            lines.append(line)
    return lines


def _parse_cmp_args(func_lines: list[str], bits: int) -> list[int]:
    """Parse cmp instructions to detect required argument values.

    Handles multiple GCC patterns:
    1. cmp $0xNNNN,%rdi           (direct immediate comparison)
    2. mov $0xNNNN,%eax; cmp %rax,-0x8(%rbp)  (store-to-stack then compare)
    3. cmp %regA,%regB            (register-register with prior mov imm)

    For pattern 2, we track which stack slots hold function arguments:
      mov %rdi,-0x8(%rbp)  → slot rbp-8 = arg0
      mov %rsi,-0x10(%rbp) → slot rbp-16 = arg1

    Returns a list of argument values indexed by position.
    """
    if bits == 64:
        reg_to_pos = {
            "rdi": 0, "edi": 0,
            "rsi": 1, "esi": 1,
            "rdx": 2, "edx": 2,
            "rcx": 3, "ecx": 3,
        }
    else:
        reg_to_pos = {"eax": 0, "ecx": 1, "edx": 2}

    found: dict[int, int] = {}

    # Track mov $imm,%reg
    last_mov_imm: dict[str, int] = {}
    # Track which stack slots store which argument:
    # mov %rdi,-0x8(%rbp) → slot_to_arg["-0x8"] = 0
    slot_to_arg: dict[str, int] = {}

    for line in func_lines:
        stripped = line.strip()

        # Pattern: mov %rdi,-0xN(%rbp) — argument saved to stack
        m = re.search(
            r"mov\s+%(\w+),\s*(-0x[0-9a-fA-F]+)\(%[re]bp\)", stripped
        )
        if m:
            reg = m.group(1)
            slot = m.group(2)
            pos = reg_to_pos.get(reg)
            if pos is not None:
                slot_to_arg[slot] = pos

        # Pattern 1: cmp $0xNNNN,%reg
        m = re.search(
            r"cmp\s+\$0x([0-9a-fA-F]+),\s*%(\w+)", stripped
        )
        if m:
            val = int(m.group(1), 16)
            reg = m.group(2)
            pos = reg_to_pos.get(reg)
            if pos is not None and val > 0xFF:
                found[pos] = val
            continue

        # Pattern: cmp %reg,$0xNNNN (AT&T reversed)
        m = re.search(
            r"cmp\s+%(\w+),\s*\$0x([0-9a-fA-F]+)", stripped
        )
        if m:
            reg = m.group(1)
            val = int(m.group(2), 16)
            pos = reg_to_pos.get(reg)
            if pos is not None and val > 0xFF:
                found[pos] = val
            continue

        # Pattern: mov $0xNNNN,%reg (track for later cmp)
        m = re.search(
            r"mov\s+\$0x([0-9a-fA-F]+),\s*%(\w+)", stripped
        )
        if m:
            val = int(m.group(1), 16)
            reg = m.group(2)
            if val > 0xFF:
                last_mov_imm[reg] = val
            continue

        # Pattern 2: cmp %reg,-0xN(%rbp) — compare reg with stack slot
        # This is the common GCC pattern: mov $val,%eax; cmp %rax,-0x8(%rbp)
        m = re.search(
            r"cmp\s+%(\w+),\s*(-0x[0-9a-fA-F]+)\(%[re]bp\)", stripped
        )
        if m:
            cmp_reg = m.group(1)
            slot = m.group(2)
            # The register holds the immediate value, the slot holds the arg
            base_reg = cmp_reg.replace("e", "r") if cmp_reg.startswith("e") else cmp_reg
            val = last_mov_imm.get(cmp_reg) or last_mov_imm.get(base_reg) or last_mov_imm.get(cmp_reg.replace("r", "e"))
            if val and slot in slot_to_arg:
                pos = slot_to_arg[slot]
                found[pos] = val
            continue

        # Pattern: cmp -0xN(%rbp),%reg — reversed operands
        m = re.search(
            r"cmp\s+(-0x[0-9a-fA-F]+)\(%[re]bp\),\s*%(\w+)", stripped
        )
        if m:
            slot = m.group(1)
            cmp_reg = m.group(2)
            base_reg = cmp_reg.replace("e", "r") if cmp_reg.startswith("e") else cmp_reg
            val = last_mov_imm.get(cmp_reg) or last_mov_imm.get(base_reg) or last_mov_imm.get(cmp_reg.replace("r", "e"))
            if val and slot in slot_to_arg:
                pos = slot_to_arg[slot]
                found[pos] = val
            continue

        # Pattern 3: cmp %regA,%regB (register-register)
        m = re.search(r"cmp\s+%(\w+),\s*%(\w+)", stripped)
        if m:
            reg_a, reg_b = m.group(1), m.group(2)
            if reg_a in last_mov_imm:
                pos = reg_to_pos.get(reg_b)
                if pos is not None:
                    found[pos] = last_mov_imm[reg_a]
            elif reg_b in last_mov_imm:
                pos = reg_to_pos.get(reg_a)
                if pos is not None:
                    found[pos] = last_mov_imm[reg_b]

    if not found:
        return []

    max_pos = max(found.keys())
    args = [found.get(i, 0) for i in range(max_pos + 1)]
    while args and args[-1] == 0:
        args.pop()
    return args
