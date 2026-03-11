"""Program behavior classifier.

Analyzes disassembly/symbols to classify the binary into behavior categories:
- shellcode_runner: mmap(RWX) + read() + call/jmp *reg
- menu_program: loop with switch/case on user input
- simple_io: read input → process → exit (typical BOF/fmt)
- write_primitive: reads address+value, does *addr=value

This classification helps strategies decide applicability.
"""
from __future__ import annotations

import re
import subprocess
from typing import TYPE_CHECKING

from pwn import log

if TYPE_CHECKING:
    from autopwn.context import PwnContext


def classify_behavior(ctx: PwnContext) -> str:
    """Classify binary behavior and populate ctx fields.

    Sets ctx.behavior and ctx.shellcode_info / ctx.input_limit as appropriate.
    Returns the behavior string.
    """
    try:
        result = subprocess.run(
            ["objdump", "-d", ctx.binary_path],
            capture_output=True, timeout=10,
        )
        disasm = result.stdout.decode("utf-8", errors="replace")
    except Exception:
        ctx.behavior = "unknown"
        return "unknown"

    # Check for shellcode runner pattern first (most specific)
    sc_info = _detect_shellcode_runner(ctx, disasm)
    if sc_info:
        ctx.behavior = "shellcode_runner"
        ctx.shellcode_info = sc_info
        log.info(f"行为分类: shellcode_runner (read_size={sc_info.get('read_size', '?')})")
        return "shellcode_runner"

    # Detect input limits from the vulnerable function
    _detect_input_limits(ctx, disasm)

    # Check for menu program
    if _is_menu_program(ctx, disasm):
        ctx.behavior = "menu_program"
        log.info("行为分类: menu_program")
        return "menu_program"

    ctx.behavior = "simple_io"
    log.info("行为分类: simple_io")
    return "simple_io"


def _detect_shellcode_runner(ctx: PwnContext, disasm: str) -> dict | None:
    """Detect the pattern: allocate RWX memory → read input → execute it.

    This covers challenges like:
    - mmap(NULL, size, PROT_RWX, ...) → read(0, buf, size) → call buf
    - buf on stack with NX disabled, read(0, buf, size) → call/jmp to buf
    - Direct shellcode execution challenges
    """
    info: dict = {}

    # Method 1: Look for mmap with RWX (prot=7 or PROT_READ|PROT_WRITE|PROT_EXEC)
    has_mmap = False
    has_read_to_mmap = False
    has_call_reg = False

    functions = _extract_functions(disasm)

    # Also do a flat scan of ALL lines (catches stripped binaries)
    all_lines = disasm.splitlines()
    functions.append(("__all__", all_lines))

    for func_name, lines in functions:
        mmap_result_reg = None
        mmap_result_stored = None
        read_into_mmap = False

        for i, line in enumerate(lines):
            # Detect mmap call with RWX protection
            if "call" in line and "mmap" in line:
                # Check preceding lines for prot argument
                for j in range(max(0, i - 12), i):
                    # x86-64: mov $0x7,%edx (3rd arg = prot)
                    if re.search(r"mov\s+\$0x7,%edx", lines[j]):
                        has_mmap = True
                        info["rwx_via"] = "mmap"
                        break
                    # x86-32: push $0x7 (stack-based args)
                    if re.search(r"push\s+\$0x7\s*$", lines[j]):
                        has_mmap = True
                        info["rwx_via"] = "mmap"
                        break
                    # Also: $0x7 in any mov (generic)
                    if re.search(r"\$0x7\b", lines[j]) and "mov" in lines[j]:
                        has_mmap = True
                        info["rwx_via"] = "mmap"
                        break

            # Detect read() call — check size argument
            if "call" in line and "read" in line.lower() and "readl" not in line.lower():
                for j in range(max(0, i - 10), i):
                    # x86-64: mov $0xNN,%edx
                    m = re.search(r"mov\s+\$0x([0-9a-f]+),%edx", lines[j])
                    if m:
                        read_size = int(m.group(1), 16)
                        info["read_size"] = read_size
                        has_read_to_mmap = True
                        break
                    # x86-32: push $0xNN (size arg pushed on stack)
                    m = re.search(r"push\s+\$0x([0-9a-f]+)", lines[j])
                    if m:
                        val = int(m.group(1), 16)
                        if 8 < val <= 0x10000:  # reasonable read size
                            info["read_size"] = val
                            has_read_to_mmap = True
                            break

            # Detect call/jmp *reg (execute user-controlled pointer)
            if re.search(r"(?:call|jmp)\s+\*%[re]?[a-z]{2,3}", line):
                has_call_reg = True
            # Also detect: call *offset(%rbp) etc
            if re.search(r"(?:call|jmp)\s+\*-?0x[0-9a-f]+\(%[re][a-z]+\)", line):
                has_call_reg = True

    # Also check if NX is disabled (stack executable) — implicit RWX
    if not ctx.nx:
        has_mmap = True  # treat NX-off as having RWX memory
        info["rwx_via"] = "nx_disabled"

    # Check for GNU_STACK with exec permission
    if not has_mmap:
        try:
            readelf = subprocess.run(
                ["readelf", "-l", ctx.binary_path],
                capture_output=True, timeout=5,
            )
            readelf_out = readelf.stdout.decode("utf-8", errors="replace")
            if "GNU_STACK" in readelf_out:
                for line in readelf_out.splitlines():
                    if "GNU_STACK" in line and ("RWE" in line or "E" in line.split()[-1] if line.split() else False):
                        has_mmap = True
                        info["rwx_via"] = "stack_rwx"
                        break
        except Exception:
            pass

    if has_mmap and has_read_to_mmap and has_call_reg:
        # Detect if there's a filter function between read and call
        info["has_filter"] = _detect_shellcode_filter(ctx, disasm)
        return info

    # Method 2: Simple pattern — binary name contains "shell" hints
    # and has RWX + read + call pattern
    if has_mmap and has_call_reg and not has_read_to_mmap:
        # Check if there's any read() call at all
        if "read@plt" in disasm or "read>" in disasm:
            has_read_to_mmap = True
            if "read_size" not in info:
                info["read_size"] = 0x200  # default guess
            info["has_filter"] = _detect_shellcode_filter(ctx, disasm)
            return info

    return None


def _detect_shellcode_filter(ctx: PwnContext, disasm: str) -> bool:
    """Detect if there's a filter/validator between read and call *reg.

    Heuristics:
    - A function is called between read() and call *reg
    - That function has comparison loops (byte-by-byte checking)
    - test eax, eax / je pattern after the call (pass/fail branch)
    """
    functions = _extract_functions(disasm)

    for func_name, lines in functions:
        read_idx = -1
        call_reg_idx = -1
        intermediate_calls = []

        for i, line in enumerate(lines):
            if "call" in line and "read" in line.lower() and "readl" not in line.lower():
                read_idx = i
            if read_idx >= 0 and i > read_idx:
                if re.search(r"(?:call|jmp)\s+\*", line):
                    call_reg_idx = i
                    break
                # Any call between read and exec that's NOT a standard PLT call
                # (a PLT call has format "call XXXX <func@plt>")
                if "call" in line and not re.search(r"<\w+@plt>$", line.strip()):
                    intermediate_calls.append(i)

        if read_idx >= 0 and call_reg_idx >= 0 and intermediate_calls:
            # Check if there's a test/je or test/jne pattern after the call
            for ci in intermediate_calls:
                for j in range(ci + 1, min(ci + 5, len(lines))):
                    if "test" in lines[j]:
                        for k in range(j + 1, min(j + 3, len(lines))):
                            if re.search(r"\bj[en]", lines[k]):
                                return True
    return False


def _detect_input_limits(ctx: PwnContext, disasm: str) -> None:
    """Detect the maximum input size from read()/fgets()/recv() calls.

    Parses the size argument passed to input functions in the vulnerable
    function to determine the maximum payload size.
    """
    functions = _extract_functions(disasm)

    # Prioritize main and functions called by main
    main_funcs = []
    other_funcs = []
    for name, lines in functions:
        if name in ("main", "vuln", "vulnerable", "challenge"):
            main_funcs.append((name, lines))
        else:
            other_funcs.append((name, lines))

    # Also check functions called by main
    for name, lines in functions:
        if name == "main":
            for line in lines:
                if "call" in line:
                    m = re.search(r"call\s+[0-9a-f]+\s+<(\w+)>", line)
                    if m:
                        called = m.group(1)
                        for oname, olines in other_funcs:
                            if oname == called:
                                main_funcs.append((oname, olines))

    read_sizes = []
    for func_name, lines in (main_funcs if main_funcs else functions):
        for i, line in enumerate(lines):
            if "call" in line and any(f in line for f in ["read", "fgets", "recv"]):
                # Look for size argument in preceding lines
                for j in range(max(0, i - 8), i):
                    # x86-64: edx = 3rd arg (read size), or esi = 2nd arg (fgets)
                    m = re.search(r"mov\s+\$0x([0-9a-f]+),%edx", lines[j])
                    if m:
                        size = int(m.group(1), 16)
                        if 0 < size < 0x10000:
                            read_sizes.append(size)
                    # fgets: size is 2nd arg (esi)
                    if "fgets" in line:
                        m2 = re.search(r"mov\s+\$0x([0-9a-f]+),%esi", lines[j])
                        if m2:
                            size = int(m2.group(1), 16)
                            if 0 < size < 0x10000:
                                read_sizes.append(size)
                    # 32-bit: push $0xNN before call
                    m3 = re.search(r"push\s+\$0x([0-9a-f]+)", lines[j])
                    if m3:
                        size = int(m3.group(1), 16)
                        if 8 < size < 0x10000:  # reasonable read size
                            read_sizes.append(size)

    if read_sizes:
        # Use the largest read size as the input limit
        # (the vulnerable read is usually the largest one)
        ctx.input_limit = max(read_sizes)
        log.info(f"输入限制: {ctx.input_limit} bytes")


def _is_menu_program(ctx: PwnContext, disasm: str) -> bool:
    """Detect if the binary is a menu-driven program.

    Heuristics:
    - Has menu-related strings in binary sections (not just ctx.useful_strings)
    - Has heap alloc/free functions (malloc/calloc + free)
    - Has a loop with multiple input calls
    - Has switch/case patterns on user input
    """
    # Static binaries include libc strings that produce false positives
    is_static = ctx.elf and ctx.elf.statically_linked if ctx.elf else False

    # Check ctx.useful_strings first (only high-confidence keywords)
    for s in ctx.useful_strings:
        sl = s.lower()
        if any(kw in sl for kw in ["menu", "choice", "option", "select",
                                    "1.", "2.", "3."]):
            return True
        # "quit", "exit", "add", "delete" etc. only for dynamically linked
        if not is_static and any(kw in sl for kw in ["quit", "exit",
                                                      "add", "delete", "show", "edit"]):
            return True

    # Direct string search in binary sections (skip for static binaries
    # as libc strings produce massive false positives)
    if not is_static:
        menu_score = _score_menu_strings(ctx)
        if menu_score >= 2:
            return True

    # Check for heap alloc+free pattern with multiple input calls (typical heap menu)
    has_alloc = any(f in disasm for f in ["malloc@plt", "calloc@plt"])
    has_free = "free@plt" in disasm
    if has_alloc and has_free:
        # Has both alloc and free — almost certainly a menu program
        # Verify with at least one input call pattern
        has_input = any(f in disasm for f in ["scanf@plt", "read@plt", "fgets@plt",
                                               "gets@plt", "atoi@plt"])
        if has_input:
            return True

    # Check for repeated scanf/read patterns in the same function
    # For static binaries, only check main/user functions, not libc
    functions = _extract_functions(disasm)
    for name, lines in functions:
        if is_static and name not in ("main", "vuln", "menu", "handle",
                                       "do_stuff", "challenge"):
            continue
        input_calls = sum(1 for l in lines if "call" in l and
                          any(f in l for f in ["scanf", "read@", "fgets", "getchar", "gets"]))
        if input_calls >= 3:
            return True

    return False


def _score_menu_strings(ctx: PwnContext) -> int:
    """Score how likely the binary is a menu program by searching raw strings."""
    if not ctx.elf:
        return 0

    score = 0
    try:
        result = subprocess.run(
            ["strings", "-a", ctx.binary_path],
            capture_output=True, timeout=5,
        )
        all_strings = result.stdout.decode("utf-8", errors="replace").lower()
    except Exception:
        return 0

    # Menu keywords (each unique match adds 1 point)
    menu_kws = ["menu", "choice", "option", "select"]
    op_kws = ["add", "delete", "remove", "edit", "show", "create", "alloc", "free"]
    prompt_kws = ["index", "size", "content", "length", "name"]

    if any(kw in all_strings for kw in menu_kws):
        score += 1
    if sum(1 for kw in op_kws if kw in all_strings) >= 2:
        score += 1
    if any(kw in all_strings for kw in prompt_kws):
        score += 1

    return score


def _extract_functions(disasm: str) -> list[tuple[str, list[str]]]:
    """Extract function names and their disassembly lines from objdump output."""
    functions = []
    current_name = ""
    current_lines: list[str] = []

    for line in disasm.splitlines():
        m = re.match(r"[0-9a-f]+ <(\w+)>:", line)
        if m:
            if current_name:
                functions.append((current_name, current_lines))
            current_name = m.group(1)
            current_lines = []
            continue
        current_lines.append(line)

    if current_name:
        functions.append((current_name, current_lines))

    return functions
