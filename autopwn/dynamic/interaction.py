from __future__ import annotations

import re
import subprocess
from typing import TYPE_CHECKING, Any

from pwn import log, process

from autopwn.config import RECV_TIMEOUT

if TYPE_CHECKING:
    from autopwn.context import PwnContext


def detect_interaction(ctx: PwnContext) -> dict[str, Any]:
    """探测程序的交互模式。

    Determines:
    - Input type: how the binary reads input (read/gets/scanf/fgets)
    - Interaction pattern: direct / menu / multi_round
    - Initial output (prompt) bytes for later consumption
    """
    result: dict[str, Any] = {
        "type": "direct",
        "initial_output": b"",
        "prompts": [],
        "menu_items": {},
    }

    # Step 1: Detect primary input function from PLT/symbols
    _detect_input_func(ctx)

    # Step 2: Run binary briefly to observe output
    try:
        p = process(ctx.binary_path, level="error")
    except Exception:
        return result

    try:
        initial = p.recv(timeout=RECV_TIMEOUT)
        result["initial_output"] = initial
        ctx.initial_prompt = initial

        if _looks_like_menu(initial):
            result["type"] = "menu"
            result["menu_items"] = _parse_menu(initial)
            log.info(f"检测到菜单程序，选项: {list(result['menu_items'].keys())}")

            ctx.input_type = "menu"
            ctx.menu_map = result["menu_items"]
        elif initial:
            # Try sending a dummy input to see if a menu appears
            menu_after_input = _probe_for_menu(p, initial)
            if menu_after_input:
                result["type"] = "menu"
                result["menu_items"] = _parse_menu(menu_after_input)
                log.info(f"检测到菜单程序(探测后)，选项: {list(result['menu_items'].keys())}")
                ctx.input_type = "menu"
                ctx.menu_map = result["menu_items"]
                ctx.initial_prompt = initial
            else:
                prompts = _extract_prompts(initial)
                if prompts:
                    result["prompts"] = prompts

                loop_result = _has_loop(ctx)
                if loop_result == "loop":
                    result["type"] = "multi_round"
                    if ctx.input_type not in ("menu",):
                        ctx.input_type = "multi_round"
                    ctx.has_loop = True
                elif loop_result == "multi_prompt":
                    ctx.is_multi_prompt = True
                    log.info("交互模式: 检测到多步输入(非循环)")
    except Exception:
        pass
    finally:
        try:
            p.close()
        except Exception:
            pass

    # Override: if behavior classifier already identified as menu_program,
    # force input_type to "menu" — BUT only if input_type wasn't already
    # set to a specific type by symbol/PLT analysis (gets, read, direct).
    # Those are more reliable than the behavior classifier.
    known_types = {"gets", "read", "direct"}
    if ctx.behavior == "menu_program" and ctx.input_type not in ("menu",) \
            and ctx.input_type not in known_types:
        ctx.input_type = "menu"
        ctx.has_loop = True
        log.info("交互模式: 行为分类器确认为菜单程序")

    log.info(f"交互模式: {ctx.input_type}")
    return result


def _detect_input_func(ctx: PwnContext) -> None:
    """Detect the primary input function and set ctx.input_type.

    Checks PLT/symbols first.  Then inspects disassembly of the vulnerable
    function (if known) or main to find which input call is actually used
    on the attacker-controlled buffer.

    Sets ctx.input_type to one of:
    - "read"   : binary uses read() — send() without trailing newline
    - "direct" : binary uses gets()/scanf()/fgets() — sendline() with newline
    """
    if not ctx.elf:
        return

    elf = ctx.elf

    # Collect which input functions are present in PLT
    input_funcs_present: list[str] = []
    for name in ("read", "gets", "fgets", "scanf", "__isoc99_scanf", "recv"):
        if name in (elf.plt or {}):
            input_funcs_present.append(name)
        elif name in (elf.symbols or {}):
            input_funcs_present.append(name)

    if not input_funcs_present:
        # Static binary — check symbols for input functions (not in PLT
        # but in static symbol table).  _IO_gets, __libc_read, etc.
        static_gets = {"gets", "_IO_gets", "__gets"}
        static_read = {"read", "__read", "__libc_read"}
        static_scanf = {"scanf", "__isoc99_scanf", "__scanf", "sscanf"}
        all_syms = set(elf.symbols or {})
        if all_syms & static_gets:
            ctx.input_type = "gets"
            return
        if all_syms & static_scanf:
            # scanf also needs newline
            ctx.input_type = "direct"
            return
        if all_syms & static_read:
            ctx.input_type = "read"
            return
        # Fallback: keep default
        return

    # If the binary ONLY has read() as input (no gets/scanf/fgets),
    # it's clearly a read()-based program
    line_funcs = {"gets", "fgets", "scanf", "__isoc99_scanf"}
    has_line = any(f in line_funcs for f in input_funcs_present)
    has_read = "read" in input_funcs_present or "recv" in input_funcs_present

    if has_read and not has_line:
        ctx.input_type = "read"
        return

    if has_line and not has_read:
        # gets/scanf/fgets → sendline is correct (default "direct")
        return

    # Both present — need to inspect disassembly to determine which is
    # used on the vulnerable buffer.  Check the vulnerable function or main.
    _disambiguate_input_func(ctx, input_funcs_present)


def _disambiguate_input_func(ctx: PwnContext, funcs: list[str]) -> None:
    """When both read() and line-based functions are present, inspect
    disassembly to determine which is called in the vulnerable path."""
    try:
        result = subprocess.run(
            ["objdump", "-d", ctx.binary_path],
            capture_output=True, timeout=10,
        )
        output = result.stdout.decode("utf-8", errors="replace")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return

    # Find the vulnerable function name (from vuln analysis) or use main
    target_funcs = []
    for vuln in ctx.vulnerabilities:
        fn = vuln.get("function", "")
        if fn and fn != "(unknown)":
            target_funcs.append(fn)
    if not target_funcs:
        target_funcs = ["main", "vuln", "overflow"]
    # Also add commonly named overflow/vulnerable functions
    for extra in ["main", "overflow", "vuln", "vulnerable_function",
                   "vulnerable", "pwn", "vul", "hack"]:
        if extra not in target_funcs:
            target_funcs.append(extra)

    # Parse disassembly of ALL functions to find which input calls exist
    # and which is the most likely overflow target (reads the most data)
    all_input_calls: list[str] = []
    for target in target_funcs:
        in_func = False
        for line in output.splitlines():
            if f"<{target}>:" in line:
                in_func = True
                continue
            if in_func and line and not line.startswith(" ") and ">:" in line:
                break
            if in_func and "call" in line:
                for f in funcs:
                    if f"<{f}" in line or (f"@plt" in line and f in line):
                        all_input_calls.append(f)
                # Also match static libc aliases (e.g. _IO_gets -> gets)
                if "<_IO_gets" in line or "<__gets" in line:
                    all_input_calls.append("gets")
                elif "<__isoc99_scanf" in line or "<__scanf" in line:
                    all_input_calls.append("scanf")
                elif "<__read" in line or "<__libc_read" in line:
                    all_input_calls.append("read")

    if not all_input_calls:
        # Fallback: scan ONLY the known vuln/overflow functions for input calls.
        # Don't scan the entire binary since static binaries have many read/gets
        # calls in libc internals.
        pass

    if all_input_calls:
        # Determine the most specific input type from calls found
        line_calls = [f for f in all_input_calls if f in ("gets", "fgets", "scanf", "__isoc99_scanf")]
        read_calls = [f for f in all_input_calls if f in ("read", "recv")]
        if line_calls and not read_calls:
            # Only line-based calls: gets/scanf/fgets need newline
            if "gets" in line_calls:
                ctx.input_type = "gets"
            else:
                ctx.input_type = "direct"
        elif read_calls and not line_calls:
            ctx.input_type = "read"
        elif line_calls and read_calls:
            # Both present — prefer the one in the vulnerable function
            # Default to gets/direct since it's safer (extra \n is handled)
            if "gets" in line_calls:
                ctx.input_type = "gets"
            else:
                ctx.input_type = "read"
        return


def _probe_for_menu(p, initial: bytes) -> bytes | None:
    """Try sending dummy input to see if a full menu appears.

    Some menu programs show only a prompt initially (e.g., "choice>"),
    and the full menu (with numbered options) only appears after the
    first interaction or after invalid input.
    """
    try:
        # Send a likely-invalid choice to trigger menu display
        p.sendline(b"0")
        resp = p.recv(timeout=1.5)
        if resp and _looks_like_menu(resp):
            return resp
        # Try sending newline
        p.sendline(b"")
        resp2 = p.recv(timeout=1.0)
        if resp2 and _looks_like_menu(resp2):
            return resp2
    except Exception:
        pass
    return None


def _looks_like_menu(data: bytes) -> bool:
    """判断输出是否像菜单。"""
    text = data.decode("utf-8", errors="replace").lower()

    menu_patterns = [
        r"\b[1-9]\s*[\.\):\-]\s*\w+",
        r"(add|delete|edit|show|print|create|remove|free|alloc|read|write|exit|quit)",
        r"(menu|choice|option|select|choose)",
        r">>|>\s*$|:\s*$",
    ]

    score = 0
    for pat in menu_patterns:
        if re.search(pat, text):
            score += 1

    numbered = re.findall(r"[1-9]\s*[\.\):\-]\s*\w+", text)
    if len(numbered) >= 3:
        # Only +1 for numbered items alone; need an actual action keyword
        # or prompt to qualify.  Prevents false positives on banners
        # like "1.beautiful 2.lovely 3.xxx" which are not real menus.
        score += 1

    return score >= 3


def _parse_menu(data: bytes) -> dict[str, Any]:
    """解析菜单选项。"""
    text = data.decode("utf-8", errors="replace")
    menu = {}

    numbered = re.findall(r"(\d+)\s*[\.\):\-]\s*(.+)", text)
    for num, desc in numbered:
        desc_lower = desc.strip().lower()

        op_type = "unknown"
        if any(k in desc_lower for k in ["add", "create", "alloc", "new", "malloc",
                                          "buy", "build", "insert", "push", "store",
                                          "register", "sign up", "check in", "checkin"]):
            op_type = "alloc"
        elif any(k in desc_lower for k in ["delete", "remove", "free", "del", "sell",
                                            "destroy", "drop", "release", "check out",
                                            "checkout", "unregister"]):
            op_type = "free"
        elif any(k in desc_lower for k in ["edit", "modify", "update", "change", "write",
                                            "upgrade", "fill", "set", "rename", "replace"]):
            op_type = "edit"
        elif any(k in desc_lower for k in ["show", "print", "view", "display", "read",
                                            "dump", "see", "list", "get", "info",
                                            "detail", "look", "inspect"]):
            op_type = "show"
        elif any(k in desc_lower for k in ["exit", "quit", "leave", "bye", "logout"]):
            op_type = "exit"
        elif any(k in desc_lower for k in ["backdoor", "shell", "hack", "win",
                                            "secret", "admin", "root", "flag"]):
            op_type = "backdoor"

        menu[num.strip()] = {
            "description": desc.strip(),
            "type": op_type,
        }

    return menu


def _extract_prompts(data: bytes) -> list[bytes]:
    """提取输出中的提示符。"""
    prompts = []
    lines = data.split(b"\n")
    for line in lines:
        stripped = line.rstrip()
        if stripped.endswith((b":", b">", b">>", b"? ")):
            prompts.append(stripped)
    return prompts


def _has_loop(ctx: PwnContext) -> str:
    """检测程序是否有循环读取（while/for + input call）。

    Checks main AND all functions called by main for loop patterns,
    not just main itself.

    Returns:
        "loop" if a real loop with input is found,
        "multi_prompt" if multiple distinct input calls but no loop,
        "" if no loop or multi-prompt detected.
    """
    try:
        result = subprocess.run(
            ["objdump", "-d", ctx.binary_path],
            capture_output=True, timeout=10,
        )
        output = result.stdout.decode("utf-8", errors="replace")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""

    # First, find functions called by main
    funcs_to_check = ["main"]
    in_main = False
    main_input_calls = []  # track distinct input call sites in main's call chain
    for line in output.splitlines():
        if "<main>:" in line:
            in_main = True
            continue
        if in_main and line and not line.startswith(" ") and ">:" in line:
            break
        if in_main and "call" in line:
            m = re.search(r"<(\w+)(?:@plt)?>", line)
            if m:
                name = m.group(1)
                if name not in ("__stack_chk_fail", "_init", "setvbuf",
                                "__libc_start_main", "exit",
                                "printf", "puts", "write"):
                    funcs_to_check.append(name)
                # Track input calls directly in main
                input_funcs = {"read", "gets", "scanf", "fgets", "fread", "recv",
                               "__isoc99_scanf"}
                if name in input_funcs:
                    main_input_calls.append(name)

    # Check each function for loop + input call pattern
    for func_name in funcs_to_check:
        if _func_has_loop(output, func_name):
            return "loop"

    # No loop found — check if there are multiple distinct input calls
    # which suggests multi-prompt (e.g. name + password)
    # Also use r2 profile info if available
    r2p = getattr(ctx, "r2_profile", None)
    num_input = len(main_input_calls)
    if r2p and r2p.num_input_calls > num_input:
        num_input = r2p.num_input_calls

    if num_input >= 2:
        return "multi_prompt"

    return ""


def _func_has_loop(disasm: str, func_name: str) -> bool:
    """Check if a function contains a loop with an input call."""
    in_func = False
    func_addrs: list[int] = []
    jmp_targets: list[int] = []
    jmp_sources: list[int] = []
    has_input_call = False

    for line in disasm.splitlines():
        if f"<{func_name}>:" in line:
            in_func = True
            continue
        if in_func and line and not line.startswith(" ") and ">:" in line:
            break
        if not in_func:
            continue

        # Parse instruction address
        stripped = line.strip()
        addr_match = re.match(r"([0-9a-f]+):", stripped)
        if addr_match:
            addr = int(addr_match.group(1), 16)
            func_addrs.append(addr)

        # Check for backward jumps (loop indicator)
        jmp_match = re.search(r"\b(jmp|jne|je|jl|jle|jg|jge|jb|jbe|ja|jae|jns|js)\s+([0-9a-f]+)", stripped)
        if jmp_match:
            target = int(jmp_match.group(2), 16)
            jmp_targets.append(target)
            jmp_sources.append(addr)

        # Check for input calls
        if "call" in stripped:
            input_funcs = ["read", "gets", "scanf", "fgets", "fread", "recv",
                           "__isoc99_scanf"]
            if any(f"<{f}" in stripped for f in input_funcs):
                has_input_call = True

    if not has_input_call or not func_addrs:
        return False

    # A backward jump (target < source) indicates a loop
    for target, source in zip(jmp_targets, jmp_sources):
        if target < source:
            return True

    return False
