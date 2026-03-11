"""Dynamic menu probing for heap-style CTF challenges.

Two-phase approach:
1. Static analysis: Parse disassembly to find switch/case handlers and their
   function names or PLT calls.  This reveals which choice calls malloc (alloc),
   free (del), read/write (edit/show), system (backdoor), etc.
2. Dynamic probing: Run the binary to discover prompt patterns (what each
   choice asks for: size, index, content, etc.)

Combining both phases gives reliable menu mapping even for bare-prompt binaries.
"""
from __future__ import annotations

import re
import subprocess
from typing import TYPE_CHECKING, Any

from pwn import log, process

if TYPE_CHECKING:
    from autopwn.context import PwnContext


def probe_menu(ctx: PwnContext) -> dict[str, Any]:
    """Probe a menu binary to determine its operation mapping.

    Returns a menu_to_heap_map dict suitable for MenuDriver.from_context():
        {"alloc": {"choice": "1", "size_prompt": b"size>", ...},
         "free":  {"choice": "3", "idx_prompt": b"index>"},
         ...}
    """
    # Phase 1: Static analysis — classify handlers by PLT calls
    static_map = _static_classify(ctx)

    # Phase 2: Dynamic probing — discover prompt patterns
    menu_prompt = _find_menu_prompt(ctx.binary_path)
    if not menu_prompt:
        log.info("菜单探测: 未找到菜单提示符")
        if static_map:
            return _finalize_map(static_map, b">")
        return {}

    log.info(f"菜单探测: 提示符={menu_prompt!r}")

    dynamic_info = _dynamic_probe(ctx.binary_path, menu_prompt)

    # Phase 3: Merge static + dynamic results
    heap_map = _merge_results(static_map, dynamic_info, menu_prompt)

    if heap_map:
        ops = list(heap_map.keys())
        log.info(f"菜单探测成功: {ops}")

    return heap_map


# ── Phase 1: Static Analysis ──────────────────────────────────────────────


def _static_classify(ctx: PwnContext) -> dict[str, dict]:
    """Classify menu choices by analyzing the switch/case dispatch in disasm.

    Strategy:
    1. Find the main menu function (has atoi + indirect jump or cmp/je chain)
    2. For each case target, identify the handler function
    3. Classify handler by its PLT calls:
       - has malloc/calloc but NOT free → alloc
       - has free but NOT malloc → del/free
       - has read/write to buffer (not just index read) → edit
       - has puts/printf to output data → show
       - has system → backdoor
    """
    try:
        result = subprocess.run(
            ["objdump", "-d", ctx.binary_path],
            capture_output=True, timeout=10,
        )
        disasm = result.stdout.decode("utf-8", errors="replace")
    except Exception:
        return {}

    # Try named function approach first (non-stripped binaries)
    named_map = _classify_by_function_names(disasm)
    if named_map:
        return named_map

    # For stripped binaries, analyze the switch/case dispatch
    return _classify_by_plt_calls(ctx, disasm)


def _classify_by_function_names(disasm: str) -> dict[str, dict]:
    """If binary has descriptive function names, use them directly.

    Follows the cmp → je → (jump target) → call chain to correctly map
    choice values to handler functions, even when the dispatch block and
    handler blocks are not adjacent.
    """
    # Find choice → function mapping from the menu/main function
    menu_func = None
    for func_name in ("menu", "main"):
        if f"<{func_name}>:" in disasm:
            menu_func = func_name
            break

    if not menu_func:
        return {}

    # Extract the function body with addresses
    in_func = False
    func_lines: list[tuple[int, str]] = []  # (addr, line)
    for line in disasm.splitlines():
        if f"<{menu_func}>:" in line:
            in_func = True
            continue
        if in_func and re.match(r"^[0-9a-f]+ <\w+>:", line):
            break
        if in_func:
            addr_m = re.match(r"\s*([0-9a-f]+):", line)
            addr = int(addr_m.group(1), 16) if addr_m else 0
            func_lines.append((addr, line))

    # Build address → line_index lookup
    addr_to_idx: dict[int, int] = {}
    for i, (addr, _) in enumerate(func_lines):
        if addr:
            addr_to_idx[addr] = i

    # Step 1: Find all cmp/je pairs → choice_value → jump_target_addr
    cmp_je_map: dict[int, int] = {}  # choice_value → target_addr
    last_cmp_val = None

    for i, (addr, line) in enumerate(func_lines):
        m = re.search(r"cmp\s+\$0x([0-9a-f]+),%eax", line)
        if m:
            last_cmp_val = int(m.group(1), 16)

        if last_cmp_val is not None and re.search(r"\bje\s+([0-9a-f]+)", line):
            target_m = re.search(r"\bje\s+([0-9a-f]+)", line)
            if target_m:
                target_addr = int(target_m.group(1), 16)
                cmp_je_map[last_cmp_val] = target_addr
                last_cmp_val = None

    # Step 2: For each jump target, find the call in that block
    choice_handlers: dict[int, str] = {}
    for choice_val, target_addr in cmp_je_map.items():
        target_idx = addr_to_idx.get(target_addr)
        if target_idx is None:
            # Try nearby addresses (alignment issues)
            for off in range(-2, 3):
                if target_addr + off in addr_to_idx:
                    target_idx = addr_to_idx[target_addr + off]
                    break
        if target_idx is None:
            continue

        # Search forward from the target for a call to a user function
        for j in range(target_idx, min(target_idx + 6, len(func_lines))):
            _, target_line = func_lines[j]
            call_m = re.search(r"call\s+[0-9a-f]+\s+<(\w+)>", target_line)
            if call_m:
                name = call_m.group(1)
                if "@plt" not in name and not name.startswith("__"):
                    choice_handlers[choice_val] = name
                    break
            # Stop at unconditional jump (end of case block)
            if re.search(r"\bjmp\s+[0-9a-f]", target_line) and "jmp" in target_line and "call" not in target_line:
                # If the jmp is before a call, it might be the end of this case
                if j > target_idx:
                    break

    if not choice_handlers:
        return {}

    # Classify handlers by name
    result: dict[str, dict] = {}
    name_to_op = {
        "add": "alloc", "create": "alloc", "new": "alloc", "alloc": "alloc",
        "malloc": "alloc", "buy": "alloc", "build": "alloc", "insert": "alloc",
        "push": "alloc", "store": "alloc", "register": "alloc", "checkin": "alloc",
        "del": "free", "delete": "free", "remove": "free", "free_note": "free",
        "sell": "free", "destroy": "free", "drop": "free", "release": "free",
        "checkout": "free", "unregister": "free",
        "edit": "edit", "modify": "edit", "update": "edit", "change": "edit",
        "write": "edit", "upgrade": "edit", "fill": "edit", "rename": "edit",
        "replace": "edit",
        "show": "show", "print_note": "show", "view": "show", "display": "show",
        "read_note": "show", "dump": "show", "see": "show", "list": "show",
        "get": "show", "info": "show", "look": "show", "inspect": "show",
        "detail": "show",
        "backdoor": "backdoor", "shell": "backdoor", "hack": "backdoor",
        "win": "backdoor", "secret": "backdoor", "admin": "backdoor",
        "exit": "exit", "quit": "exit", "leave": "exit", "bye": "exit",
    }

    for choice_val, func_name in choice_handlers.items():
        fname_lower = func_name.lower()
        for keyword, op_type in name_to_op.items():
            if keyword in fname_lower:
                result[op_type] = {"choice": str(choice_val), "_handler": func_name}
                break

    return result


def _classify_by_plt_calls(ctx: PwnContext, disasm: str) -> dict[str, dict]:
    """For stripped binaries, classify handlers by their PLT calls.

    Handles two dispatch patterns:
    1. Jump table: jmp *ADDR(,%rax,8) — read table from ELF, follow targets
    2. Call chain: sequential call instructions after the switch dispatch

    For each handler subroutine, analyze PLT calls to determine operation type.
    """
    all_lines = disasm.splitlines()

    # Parse all lines with addresses
    parsed: list[tuple[int, str]] = []
    for line in all_lines:
        m = re.match(r"\s*([0-9a-f]+):", line)
        if m:
            parsed.append((int(m.group(1), 16), line))

    # Find jump table dispatch: "jmp *ADDR(,%rax,8)"
    jmp_table_addr = None
    for addr, line in parsed:
        m = re.search(r"jmp\s+\*0x([0-9a-f]+)\(,%[re]ax,8\)", line)
        if m:
            jmp_table_addr = int(m.group(1), 16)
            break

    if not jmp_table_addr and ctx.elf:
        # Try alternate pattern: mov TABLE(,%rax,8),%rax; jmp *%rax
        for i, (addr, line) in enumerate(parsed):
            m = re.search(r"mov\s+0x([0-9a-f]+)\(,%[re]ax,8\),%[re]ax", line)
            if m:
                # Check if next non-empty instruction is jmp *%rax
                for j in range(i + 1, min(i + 3, len(parsed))):
                    if re.search(r"jmp\s+\*%[re]ax", parsed[j][1]):
                        jmp_table_addr = int(m.group(1), 16)
                        break
                if jmp_table_addr:
                    break

    if not jmp_table_addr or not ctx.elf:
        return {}

    # Read jump table entries from the ELF
    elf = ctx.elf
    handler_addrs: dict[int, int] = {}  # case_num → handler_addr
    try:
        for case_num in range(8):
            entry_addr = jmp_table_addr + case_num * (ctx.bits // 8)
            data = elf.read(entry_addr, ctx.bits // 8)
            if ctx.bits == 64:
                from pwn import u64
                target = u64(data)
            else:
                from pwn import u32
                target = u32(data)
            # Validate: target should be a reasonable code address
            if 0x400000 <= target <= 0x500000 or 0x8040000 <= target <= 0x8100000:
                handler_addrs[case_num] = target
            else:
                break  # End of table
    except Exception:
        return {}

    if not handler_addrs:
        return {}

    # For each handler target, find the call instruction and trace to the subroutine
    addr_to_line: dict[int, int] = {}
    for i, (addr, _) in enumerate(parsed):
        addr_to_line[addr] = i

    result: dict[str, dict] = {}

    for case_num, target_addr in handler_addrs.items():
        if case_num == 0:
            continue  # case 0 is usually "invalid" or default

        # Find the handler block starting at target_addr
        target_idx = addr_to_line.get(target_addr)
        if target_idx is None:
            continue

        # The handler block typically does: mov $0, %eax; call HANDLER; jmp back
        # Find the call in this block
        handler_func_addr = None
        for j in range(target_idx, min(target_idx + 6, len(parsed))):
            _, line = parsed[j]
            # Check for: call ADDR (skip only REAL PLT calls like <exit@plt>)
            # Stripped binaries label user funcs as <__gmon_start__@plt+0xNN>
            # which is NOT a PLT call — the "+0x" distinguishes it
            call_m = re.search(r"call\s+([0-9a-f]+)", line)
            if call_m:
                is_real_plt = bool(re.search(r"<\w+@plt>", line))
                if is_real_plt and "exit@plt" in line:
                    result["exit"] = {"choice": str(case_num)}
                    break
                if not is_real_plt:
                    handler_func_addr = int(call_m.group(1), 16)
                    break
            # Check for exit call
            if "exit@plt" in line:
                result["exit"] = {"choice": str(case_num)}
                break

        if handler_func_addr is None:
            continue

        # Find the handler subroutine body (from handler_func_addr to next ret)
        handler_start_idx = addr_to_line.get(handler_func_addr)
        if handler_start_idx is None:
            continue

        handler_plt_calls: set[str] = set()
        for j in range(handler_start_idx, min(handler_start_idx + 80, len(parsed))):
            _, line = parsed[j]
            plt_m = re.search(r"call\s+[0-9a-f]+\s+<(\w+)@plt>", line)
            if plt_m:
                handler_plt_calls.add(plt_m.group(1))
            if re.search(r"\bret\b", line):
                break

        # Classify by PLT calls
        has_malloc = "malloc" in handler_plt_calls or "calloc" in handler_plt_calls
        has_free = "free" in handler_plt_calls
        has_read = "read" in handler_plt_calls
        has_fgets = "fgets" in handler_plt_calls
        has_system = "system" in handler_plt_calls
        has_puts = "puts" in handler_plt_calls or "printf" in handler_plt_calls

        if has_system:
            result["backdoor"] = {"choice": str(case_num)}
        elif has_malloc and not has_free:
            result["alloc"] = {"choice": str(case_num)}
        elif has_free and not has_malloc:
            result["free"] = {"choice": str(case_num)}
        elif has_read and not has_malloc and not has_free:
            result["edit"] = {"choice": str(case_num)}
        elif has_puts and not has_malloc and not has_free and not has_read:
            result["show"] = {"choice": str(case_num)}

    return result


def _get_function_body(disasm: str, func_name: str) -> list[str]:
    """Extract the body of a named function from disassembly."""
    lines = []
    in_func = False
    for line in disasm.splitlines():
        if f"<{func_name}>:" in line:
            in_func = True
            continue
        if in_func:
            if re.match(r"^[0-9a-f]+ <\w+>:", line):
                break
            lines.append(line)
    return lines


def _extract_functions(disasm: str) -> list[tuple[str, list[str]]]:
    """Extract all functions from objdump output."""
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


# ── Phase 2: Dynamic Probing ──────────────────────────────────────────────


def _find_menu_prompt(binary_path: str) -> bytes:
    """Detect the menu prompt pattern by running the binary briefly."""
    try:
        p = process(binary_path, level="error")
    except Exception:
        return b""

    try:
        data = p.recv(timeout=2)
        if not data:
            return b""

        # Find prompt pattern in the output
        text = data.decode("utf-8", errors="replace")

        # Try specific patterns first
        prompt_patterns = [
            (b"choice>", b"choice>"),
            (b"your choice?", b"your choice?"),
            (b"Your choice:", b"Your choice:"),
            (b">> ", b">>"),
            (b">>> ", b">>>"),
            (b"> ", b">"),
            (b"choice: ", b"choice:"),
            (b"Choice: ", b"Choice:"),
            (b": ", b":"),
        ]

        text_bytes = data
        for search, prompt in prompt_patterns:
            if search in text_bytes:
                return prompt

        # Generic: last line ending
        lines = text.strip().split("\n")
        if lines:
            last = lines[-1].rstrip()
            if last.endswith(">"):
                return b">"
            if last.endswith("?"):
                return b"?"
            if last.endswith(":"):
                return b":"

        return b">"
    except Exception:
        return b""
    finally:
        try:
            p.close()
        except Exception:
            pass


def _dynamic_probe(binary_path: str, menu_prompt: bytes) -> dict[str, dict]:
    """Probe each menu choice to discover its prompts."""
    results: dict[str, dict] = {}

    for choice_num in range(1, 8):
        info = _probe_single_choice(binary_path, str(choice_num), menu_prompt)
        if info:
            results[str(choice_num)] = info

    return results


def _probe_single_choice(binary_path: str, choice: str, menu_prompt: bytes) -> dict | None:
    """Probe one choice and return prompt info."""
    try:
        p = process(binary_path, level="error")
    except Exception:
        return None

    result: dict[str, Any] = {}

    try:
        initial = p.recv(timeout=2)
        if not initial:
            return None

        p.sendline(choice.encode())
        resp = p.recv(timeout=1.5)

        if not resp:
            # No response → might be exit or blocking on read
            result["type"] = "timeout"
            return result

        resp_text = resp.decode("utf-8", errors="replace").lower()

        # Check for errors
        if any(kw in resp_text for kw in ["no such", "invalid", "error", "not yet", "wrong"]):
            result["type"] = "invalid"
            return result

        # Detect prompts
        result["asks_size"] = bool(re.search(r"size|len(?:gth)?", resp_text))
        result["asks_index"] = bool(re.search(r"idx|index|id\b", resp_text))
        result["asks_content"] = bool(re.search(r"content|data|name", resp_text))
        result["raw_prompt"] = resp

        # Extract specific prompt patterns
        if result["asks_size"]:
            result["size_prompt"] = _extract_prompt_bytes(resp, r"size|len")
        if result["asks_index"]:
            result["idx_prompt"] = _extract_prompt_bytes(resp, r"idx|index|id\b")
        if result["asks_content"]:
            result["data_prompt"] = _extract_prompt_bytes(resp, r"content|data|name")

        # Check what happens after sending dummy input
        if result["asks_size"] or result["asks_index"]:
            p.sendline(b"0")
            resp2 = p.recv(timeout=1)
            if resp2:
                resp2_text = resp2.decode("utf-8", errors="replace").lower()
                if re.search(r"content|data|name|size|len", resp2_text):
                    result["has_secondary_prompt"] = True
                    if re.search(r"size|len", resp2_text) and not result.get("asks_size"):
                        result["size_prompt"] = _extract_prompt_bytes(resp2, r"size|len")
                    if re.search(r"content|data|name", resp2_text):
                        result["data_prompt"] = _extract_prompt_bytes(resp2, r"content|data|name")

    except EOFError:
        result["type"] = "exit"
    except Exception:
        return None
    finally:
        try:
            p.close()
        except Exception:
            pass

    return result


def _extract_prompt_bytes(data: bytes, keyword_pattern: str) -> bytes:
    """Extract prompt bytes matching a keyword pattern."""
    text = data.decode("utf-8", errors="replace")
    for line in text.split("\n"):
        if re.search(keyword_pattern, line, re.IGNORECASE):
            stripped = line.rstrip()
            if stripped:
                return stripped.encode("utf-8", errors="replace")
    return b":"


# ── Phase 3: Merge and Finalize ───────────────────────────────────────────


def _merge_results(static_map: dict, dynamic_info: dict, menu_prompt: bytes) -> dict[str, Any]:
    """Merge static classification with dynamic probe info."""
    heap_map: dict[str, Any] = {}

    for op_type, static_entry in static_map.items():
        choice = static_entry["choice"]
        entry: dict[str, Any] = {"choice": choice}

        # Add prompt info from dynamic probe
        if choice in dynamic_info:
            dyn = dynamic_info[choice]
            for key in ("idx_prompt", "size_prompt", "data_prompt"):
                if key in dyn:
                    entry[key] = dyn[key]

        entry["menu_prompt"] = menu_prompt
        heap_map[op_type] = entry

    return heap_map


def _finalize_map(static_map: dict, menu_prompt: bytes) -> dict[str, Any]:
    """Add menu_prompt to a static-only map."""
    heap_map: dict[str, Any] = {}
    for op_type, entry in static_map.items():
        new_entry = dict(entry)
        new_entry["menu_prompt"] = menu_prompt
        # Remove internal fields
        new_entry.pop("_handler", None)
        heap_map[op_type] = new_entry
    return heap_map
