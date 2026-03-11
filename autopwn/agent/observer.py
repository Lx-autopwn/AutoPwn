"""Observers — analyze state and populate discovered_facts."""
from __future__ import annotations

import re
import struct
import subprocess
from typing import TYPE_CHECKING

from pwn import log

if TYPE_CHECKING:
    from autopwn.agent.state import AgentState


def observe_all(state: AgentState) -> None:
    """Run all observers."""
    for obs in _ALL_OBSERVERS:
        try:
            obs(state)
        except Exception as exc:
            log.debug(f"observer {obs.__name__} error: {exc}")


# ---------------------------------------------------------------------------
# 1. Sleep trap detection
# ---------------------------------------------------------------------------
def observe_sleep_block(state: AgentState) -> None:
    """Detect if the binary has a sleep(big_number) trap overlapping with input."""
    if state.discovered_facts.get("sleep_info"):
        return

    ctx = state.ctx
    if not ctx.elf:
        return

    disasm = _get_objdump(ctx.binary_path)
    if not disasm:
        return

    # Find all functions (not just main)
    for func_name, func_lines in _iter_functions(disasm):
        sleep_val = 0
        sleep_var_offset = 0
        read_buf_offset = 0
        read_size = 0
        has_sleep_call = False

        for line in func_lines:
            # movl $0x1000, -0x4(%rbp)  (AT&T syntax)
            m = re.search(r'movl?\s+\$(0x[0-9a-f]+),\s*-?(0x[0-9a-f]+)\(%[re]bp\)', line, re.I)
            if m:
                val = int(m.group(1), 16)
                off = int(m.group(2), 16)
                if val >= 0x100:
                    sleep_val = val
                    sleep_var_offset = off

            # Intel: mov DWORD PTR [rbp-0x4], 0x1000
            m2 = re.search(r'mov.*\[[re]bp-(0x[0-9a-f]+)\].*?(0x[0-9a-f]+)', line, re.I)
            if m2:
                off = int(m2.group(1), 16)
                val = int(m2.group(2), 16)
                if val >= 0x100:
                    sleep_val = val
                    sleep_var_offset = off

            if 'sleep' in line and 'call' in line:
                has_sleep_call = True

            # lea -0x8(%rbp), %rax  or  lea rax, [rbp-0x8]
            m3 = re.search(r'lea\s+-(0x[0-9a-f]+)\(%[re]bp\)', line, re.I)
            if not m3:
                m3 = re.search(r'lea\s+\w+,\s*\[[re]bp-(0x[0-9a-f]+)\]', line, re.I)
            if m3:
                read_buf_offset = int(m3.group(1), 16)

            # mov $0x50, %edx  or  mov edx, 0x50
            m4 = re.search(r'mov.*\$?(0x[0-9a-f]+).*%edx', line, re.I)
            if not m4:
                m4 = re.search(r'mov\s+edx.*?(0x[0-9a-f]+)', line, re.I)
            if m4:
                read_size = int(m4.group(1), 16)

        if has_sleep_call and sleep_val >= 0x100 and sleep_var_offset > 0 and read_buf_offset > 0:
            if read_buf_offset >= sleep_var_offset:
                overwrite_offset = read_buf_offset - sleep_var_offset
                state.discovered_facts["sleep_info"] = {
                    "sleep_val": sleep_val,
                    "sleep_var_offset": sleep_var_offset,
                    "read_buf_offset": read_buf_offset,
                    "read_size": read_size,
                    "overwrite_offset": overwrite_offset,
                    "function": func_name,
                }
                log.info(f"Agent observer: sleep({sleep_val:#x}) trap in {func_name}, "
                         f"overwrite at offset {overwrite_offset}")
                return


# ---------------------------------------------------------------------------
# 2. cmp → win pattern detection
# ---------------------------------------------------------------------------
def observe_cmp_win(state: AgentState) -> None:
    """Detect cmp reg, immediate → conditional jump → system/win pattern."""
    if state.discovered_facts.get("win_condition"):
        return

    ctx = state.ctx
    if not ctx.elf:
        return

    disasm = _get_objdump(ctx.binary_path)
    if not disasm:
        return

    lines = disasm.splitlines()

    # Scan per function for better accuracy
    for func_name, func_lines in _iter_functions(disasm):
        # Track mov $imm → local var mappings for indirect cmp resolution
        # e.g., movl $0x10002, -0xc(%rbp)  ... cmp %eax, -0xc(%rbp)
        var_values: dict[str, int] = {}  # var_key → value

        has_system_or_win = False
        system_line_idx = -1
        for idx, fl in enumerate(func_lines):
            if 'call' in fl:
                if 'system' in fl:
                    has_system_or_win = True
                    system_line_idx = idx
                if re.search(r'<(win|flag|shell|backdoor|get_flag|print_flag|'
                             r'cat_flag|getshell|get_shell|GetFlag)>', fl, re.I):
                    has_system_or_win = True
                    system_line_idx = idx

        if not has_system_or_win:
            continue

        for idx, fl in enumerate(func_lines):
            # Track: movl $0x10002, -0xc(%rbp) → var_values["-0xc(%rbp)"] = 0x10002
            m_mov = re.search(r'movl?\s+\$(0x[0-9a-f]+),\s*([-0x0-9a-f]+\(%[re]bp\))', fl, re.I)
            if m_mov:
                val = int(m_mov.group(1), 16)
                var_key = m_mov.group(2)
                if val > 1:
                    var_values[var_key] = val

            # Strategy A: cmp with $ immediate (AT&T syntax: cmp $imm, reg/mem)
            m_cmp = re.search(r'cmp\w*\s+\$(0x[0-9a-f]+)', fl, re.I)
            if m_cmp:
                imm = int(m_cmp.group(1), 16)
                if imm > 1 and imm <= 0xffffffff:
                    # Check if system/win call is within 15 lines
                    if 0 <= system_line_idx - idx <= 15 or 0 <= idx - system_line_idx <= 15:
                        state.discovered_facts["win_condition"] = {
                            "type": "cmp_imm",
                            "value": imm,
                            "description": f"cmp ${imm:#x} in {func_name} → system/win",
                        }
                        log.info(f"Agent observer: cmp→win in {func_name}, value={imm} ({imm:#x})")
                        return

            # Strategy B: cmp %reg, var(%rbp) where var was initialized via mov
            m_cmp2 = re.search(r'cmp\s+%\w+,\s*([-0x0-9a-f]+\(%[re]bp\))', fl, re.I)
            if m_cmp2:
                var_key = m_cmp2.group(1)
                if var_key in var_values:
                    imm = var_values[var_key]
                    if 0 <= system_line_idx - idx <= 15 or 0 <= idx - system_line_idx <= 15:
                        state.discovered_facts["win_condition"] = {
                            "type": "cmp_imm",
                            "value": imm,
                            "description": f"cmp via var in {func_name}, value={imm:#x}",
                        }
                        log.info(f"Agent observer: cmp(indirect)→win in {func_name}, value={imm} ({imm:#x})")
                        return

            # Intel syntax: cmp DWORD PTR [rbp-0x...], 0x...
            m_cmp3 = re.search(r'cmp.*\[[re]bp[-+]0x[0-9a-f]+\].*?(0x[0-9a-f]+)', fl, re.I)
            if m_cmp3:
                imm = int(m_cmp3.group(1), 16)
                if imm > 1 and imm <= 0xffffffff:
                    if 0 <= system_line_idx - idx <= 15 or 0 <= idx - system_line_idx <= 15:
                        state.discovered_facts["win_condition"] = {
                            "type": "cmp_imm",
                            "value": imm,
                            "description": f"cmp in {func_name}, value={imm:#x}",
                        }
                        log.info(f"Agent observer: cmp→win in {func_name}, value={imm} ({imm:#x})")
                        return

            # Strategy C: xor $imm, %reg → test %reg, %reg  (equivalent to cmp $imm)
            # Pattern: xor $0x11, %eax; (or ...); test %eax, %eax; je/jne → system
            m_xor = re.search(r'xor\w*\s+\$(0x[0-9a-f]+),\s*%(\w+)', fl, re.I)
            if m_xor:
                imm = int(m_xor.group(1), 16)
                if imm > 1 and imm <= 0xffffffff:
                    # Look for test/or+test within next few lines
                    for k in range(idx + 1, min(idx + 6, len(func_lines))):
                        if re.search(r'test\s+%\w+,\s*%\w+', func_lines[k], re.I):
                            if 0 <= system_line_idx - idx <= 20 or 0 <= idx - system_line_idx <= 20:
                                # Try to find the array offset from preceding mov
                                check_offset = 0
                                for j in range(max(0, idx - 4), idx):
                                    m_off = re.search(r'mov\w*\s+(0x[0-9a-f]+)\(%\w+\),\s*%',
                                                      func_lines[j], re.I)
                                    if m_off:
                                        check_offset = int(m_off.group(1), 16)
                                state.discovered_facts["win_condition"] = {
                                    "type": "cmp_imm",
                                    "value": imm,
                                    "check_offset": check_offset,
                                    "description": f"xor ${imm:#x}+test in {func_name}",
                                }
                                log.info(f"Agent observer: xor+test→win in {func_name}, "
                                         f"value={imm:#x}, offset={check_offset:#x}")
                                return
                            break

    # Strategy 3: global variable overwrite → cmp → system("cat flag")
    _detect_global_overwrite_win(state, lines)


def _detect_global_overwrite_win(state: AgentState, lines: list[str]) -> None:
    """Detect: scanf writes to stack buf, cmp checks global var, if match → system."""
    for func_name, func_lines in _iter_functions_from_lines(lines):
        has_input = False
        has_system = False
        cmp_globals: list[dict] = []

        for line in func_lines:
            if 'call' in line and any(f in line for f in ['scanf', 'gets', 'read']):
                has_input = True
            if 'call' in line and 'system' in line:
                has_system = True

            # cmp DWORD PTR [rip+0x...], 0xNN  (global var, Intel syntax)
            m = re.search(r'cmp.*\[rip\+(0x[0-9a-f]+)\].*?(0x[0-9a-f]+)', line, re.I)
            if m:
                cmp_globals.append({
                    "rip_offset": int(m.group(1), 16),
                    "value": int(m.group(2), 16),
                })
            # AT&T: cmpl $0x10, 0x30(%ebx) — PIC global access via ebx
            m2 = re.search(r'cmp.*\$(0x[0-9a-f]+).*?(0x[0-9a-f]+)\(%e[bs]', line, re.I)
            if m2:
                val = int(m2.group(1), 16)
                off = int(m2.group(2), 16)
                if val > 1:
                    cmp_globals.append({"value": val, "ebx_offset": off})
            # Also: cmp $0x10, %eax where eax was loaded from global
            # (handled by cmp_win strategy 1 above)
            # Absolute address: cmp DWORD PTR [0xaddr], imm
            m3 = re.search(r'cmp.*\[(0x[0-9a-f]+)\].*?(0x[0-9a-f]+)', line, re.I)
            if m3 and 'rip' not in line and 'rbp' not in line and 'rsp' not in line:
                cmp_globals.append({
                    "abs_addr": int(m3.group(1), 16),
                    "value": int(m3.group(2), 16),
                })

            # xor $imm, %reg (equivalent to cmp when followed by test)
            m4 = re.search(r'xor\w*\s+\$(0x[0-9a-f]+)', line, re.I)
            if m4:
                xor_val = int(m4.group(1), 16)
                if xor_val > 1 and xor_val <= 0xffffffff:
                    cmp_globals.append({"value": xor_val})

        if has_input and has_system and cmp_globals:
            state.discovered_facts["win_condition"] = {
                "type": "overwrite_global",
                "cmp_info": cmp_globals[0],
                "description": f"overwrite global to {cmp_globals[0].get('value', '?'):#x} → system()",
            }
            log.info(f"Agent observer: global var overwrite in {func_name}")
            return


# ---------------------------------------------------------------------------
# 3. Variable overwrite → win function (sum check pattern)
# ---------------------------------------------------------------------------
def observe_var_overwrite_win(state: AgentState) -> None:
    """Detect: read fills buffer beyond local vars, vars checked, then win."""
    if state.discovered_facts.get("var_overwrite_win"):
        return

    ctx = state.ctx
    if not ctx.elf:
        return

    disasm = _get_objdump(ctx.binary_path)
    if not disasm:
        return

    for func_name, func_lines in _iter_functions(disasm):
        has_read = any('call' in l and 'read' in l for l in func_lines)
        has_gets = any('call' in l and 'gets' in l for l in func_lines)
        has_backdoor = any('call' in l and any(w in l for w in
                           ['backdoor', 'win', 'shell', 'flag', 'get_flag',
                            'getshell', 'get_shell']) for l in func_lines)

        if not ((has_read or has_gets) and has_backdoor):
            continue

        # Check if read size covers beyond buffer into other local vars
        buf_offset = 0
        read_size = 0
        cmp_value = 0

        for line in func_lines:
            # lea -0x30(%rbp), %rax → buf at rbp-0x30
            m = re.search(r'lea\s+-(0x[0-9a-f]+)\(%[re]bp\)', line, re.I)
            if not m:
                m = re.search(r'lea\s+\w+,\s*\[[re]bp-(0x[0-9a-f]+)\]', line, re.I)
            if m:
                off = int(m.group(1), 16)
                if off > buf_offset:
                    buf_offset = off

            # mov $0x30, %edx → read size
            m2 = re.search(r'mov.*\$?(0x[0-9a-f]+).*%edx', line, re.I)
            if not m2:
                m2 = re.search(r'mov\s+edx.*?(0x[0-9a-f]+)', line, re.I)
            if m2:
                val = int(m2.group(1), 16)
                if 0x10 <= val <= 0x1000:
                    read_size = val

            # cmp $0x29a, %eax  or  cmp eax, 0x29a
            m3 = re.search(r'cmp\s+.*?\$(0x[0-9a-f]+)', line, re.I)
            if m3:
                val = int(m3.group(1), 16)
                if val > 1 and val < 0x100000000:
                    cmp_value = val

        if cmp_value and buf_offset > 0:
            state.discovered_facts["var_overwrite_win"] = {
                "function": func_name,
                "target_sum": cmp_value,
                "buf_offset": buf_offset,
                "read_size": read_size,
                "description": f"overwrite locals in {func_name}, target=={cmp_value:#x}",
            }
            log.info(f"Agent observer: var overwrite in {func_name}, "
                     f"target={cmp_value:#x}, buf_off={buf_offset:#x}, "
                     f"read_size={read_size:#x}")
            return


# ---------------------------------------------------------------------------
# 4. system@PLT without /bin/sh
# ---------------------------------------------------------------------------
def observe_system_no_binsh(state: AgentState) -> None:
    """Detect: system@PLT exists but no /bin/sh string in binary."""
    if state.discovered_facts.get("system_no_binsh") is not None:
        return

    ctx = state.ctx
    if not ctx.elf:
        return

    has_system = "system" in (ctx.plt_table or {})
    if not has_system:
        return

    has_binsh = False
    try:
        next(ctx.elf.search(b"/bin/sh\x00"))
        has_binsh = True
    except StopIteration:
        pass

    if not has_binsh:
        has_gets = "gets" in (ctx.plt_table or {})
        has_read = "read" in (ctx.plt_table or {})
        state.discovered_facts["system_no_binsh"] = {
            "has_gets": has_gets,
            "has_read": has_read,
        }
        log.info("Agent observer: system@PLT without /bin/sh in binary")


# ---------------------------------------------------------------------------
# 5. Format string + canary + overflow combo
# ---------------------------------------------------------------------------
def observe_fmt_canary_combo(state: AgentState) -> None:
    """Detect: format string vuln + canary + overflow = two-stage attack."""
    if state.discovered_facts.get("fmt_canary_combo"):
        return

    ctx = state.ctx
    if not ctx.canary:
        return
    if ctx.overflow_offset < 0:
        return

    has_fmt = any(
        isinstance(v, dict) and v.get("type", "").startswith("fmt")
        for v in ctx.vulnerabilities
    )
    if not has_fmt:
        has_fmt = _detect_printf_user_buf(ctx)

    if has_fmt:
        state.discovered_facts["fmt_canary_combo"] = {
            "has_pie": ctx.pie,
            "overflow_offset": ctx.overflow_offset,
        }
        log.info("Agent observer: fmt string + canary + overflow combo detected")


def _detect_printf_user_buf(ctx) -> bool:
    """Check if printf is called with user-controlled buffer as format string."""
    disasm = _get_objdump(ctx.binary_path)
    if not disasm:
        return False

    lines = disasm.splitlines()
    for i, line in enumerate(lines):
        if 'call' in line and 'printf' in line and 'fprintf' not in line:
            if i > 0:
                prev = lines[i - 1]
                # lea rdi/edi, [rbp-...]  → stack buffer as fmt arg
                if re.search(r'lea\s+-(0x[0-9a-f]+)\(%[re]bp\)', prev, re.I):
                    return True
                if re.search(r'lea\s+[re]di,\s*\[[re]bp-', prev, re.I):
                    return True
                # mov rdi, rax (where rax was a buffer)
                if re.search(r'mov\s+%[re]a[xp],\s*%[re]di', prev, re.I):
                    return True
                if re.search(r'mov\s+[re]di,\s*[re]a', prev, re.I):
                    return True
    return False


# ---------------------------------------------------------------------------
# 6. close(stdout) detection
# ---------------------------------------------------------------------------
def observe_close_stdout(state: AgentState) -> None:
    """Detect: binary calls close(1) or close(2), need output redirection."""
    if state.discovered_facts.get("close_stdout"):
        return

    ctx = state.ctx
    if not ctx.elf:
        return
    if "close" not in (ctx.plt_table or {}):
        return

    disasm = _get_objdump(ctx.binary_path)
    if not disasm:
        return

    # Look for: mov $0x1, %edi → call close  or  push $0x1 → call close
    lines = disasm.splitlines()
    closed_fds = []
    for i, line in enumerate(lines):
        if 'call' in line and 'close' in line:
            # Check previous lines for fd argument
            for j in range(max(0, i - 3), i):
                prev = lines[j]
                # 64-bit: mov $0x1, %edi
                m = re.search(r'mov.*\$(0x[0-9a-f]+).*%edi', prev, re.I)
                if not m:
                    m = re.search(r'mov\s+edi.*?(0x[0-9a-f]+)', prev, re.I)
                if not m:
                    # 32-bit: push $0x1
                    m = re.search(r'push\s+\$(0x[0-9a-f]+)', prev, re.I)
                if m:
                    fd = int(m.group(1), 16)
                    if fd in (1, 2):
                        closed_fds.append(fd)

    if closed_fds:
        state.discovered_facts["close_stdout"] = {
            "closed_fds": closed_fds,
        }
        log.info(f"Agent observer: close() called on fd {closed_fds}")


# ---------------------------------------------------------------------------
# 7. Shellcode injection detection (read to exec buffer)
# ---------------------------------------------------------------------------
def observe_shellcode_exec(state: AgentState) -> None:
    """Detect: read(0, buf, N) → call *reg / jmp reg (shellcode injection)."""
    if state.discovered_facts.get("shellcode_exec"):
        return

    ctx = state.ctx
    if not ctx.elf:
        return

    disasm = _get_objdump(ctx.binary_path)
    if not disasm:
        return

    lines = disasm.splitlines()
    for i, line in enumerate(lines):
        # call *%eax / call *%rax / jmp *%eax etc
        if re.search(r'(call|jmp)\s+\*%[er]', line, re.I):
            # Check if there's a read() before this
            for j in range(max(0, i - 20), i):
                if 'call' in lines[j] and 'read' in lines[j]:
                    # Find the buffer address
                    buf_addr = 0
                    for k in range(max(0, j - 5), j):
                        m = re.search(r'push\s+\$(0x[0-9a-f]+)', lines[k], re.I)
                        if m:
                            addr = int(m.group(1), 16)
                            if addr > 0x8000000:  # looks like an address
                                buf_addr = addr
                        m2 = re.search(r'mov\s+\$(0x[0-9a-f]+).*%[er]si', lines[k], re.I)
                        if m2:
                            addr = int(m2.group(1), 16)
                            if addr > 0x8000000:
                                buf_addr = addr
                    state.discovered_facts["shellcode_exec"] = {
                        "buf_addr": buf_addr,
                    }
                    log.info(f"Agent observer: shellcode exec pattern, buf={buf_addr:#x}")
                    return


# ---------------------------------------------------------------------------
# 8. Expanded win function detection
# ---------------------------------------------------------------------------
def observe_expanded_win(state: AgentState) -> None:
    """Detect functions that call system() internally (like GetFlag)."""
    if state.discovered_facts.get("expanded_win"):
        return

    ctx = state.ctx
    if not ctx.elf:
        return
    # Only if engine didn't find win functions
    if ctx.win_funcs:
        return

    disasm = _get_objdump(ctx.binary_path)
    if not disasm:
        return

    # Find non-standard functions that call system()
    for func_name, func_lines in _iter_functions(disasm):
        if func_name in ('main', '_start', '__libc_csu_init', 'init',
                         'register_tm_clones', 'deregister_tm_clones',
                         'frame_dummy', '__do_global_dtors_aux'):
            continue
        for line in func_lines:
            if 'call' in line and 'system' in line:
                # This function calls system() — treat as win function
                # Get the function address
                func_addr = 0
                if ctx.elf and func_name in ctx.elf.symbols:
                    func_addr = ctx.elf.symbols[func_name]

                if func_addr:
                    state.discovered_facts["expanded_win"] = {
                        "name": func_name,
                        "addr": func_addr,
                    }
                    log.info(f"Agent observer: {func_name}@{func_addr:#x} calls system()")
                    return


# ---------------------------------------------------------------------------
# 9. strcmp/strncmp gate detection
# ---------------------------------------------------------------------------
def observe_strcmp_gate(state: AgentState) -> None:
    """Detect: strcmp(input, "password") gate before vulnerable function."""
    if state.discovered_facts.get("strcmp_gate"):
        return

    ctx = state.ctx
    if not ctx.elf:
        return

    disasm = _get_objdump(ctx.binary_path)
    if not disasm:
        return

    # Find strcmp calls and extract the constant string argument
    lines = disasm.splitlines()
    for i, line in enumerate(lines):
        if 'call' not in line or 'strcmp' not in line:
            continue
        # Look backward for lea with string address
        for j in range(max(0, i - 5), i):
            prev = lines[j]
            addrs_to_try = []

            # Strategy 1: objdump comment with computed address (most reliable)
            # e.g. "lea 0x18a(%rip),%rsi  # 40093e <_IO_stdin_used+0x1c>"
            m_comment = re.search(r'#\s*([0-9a-f]+)\b', prev)
            if m_comment and ('%rip' in prev or '%eip' in prev):
                addrs_to_try.append(int(m_comment.group(1), 16))

            # Strategy 2: absolute address or push immediate
            m = re.search(r'(?:lea|mov).*?(0x[0-9a-f]+).*%[re][ds]i', prev, re.I)
            if not m:
                m = re.search(r'push\s+\$(0x[0-9a-f]+)', prev, re.I)
            if m:
                addrs_to_try.append(int(m.group(1), 16))

            for str_addr in addrs_to_try:
                try:
                    s = ctx.elf.string(str_addr)
                    if s and len(s) < 64 and s.isascii():
                        gate_str = s.decode() if isinstance(s, bytes) else s
                        state.discovered_facts["strcmp_gate"] = {
                            "string": gate_str,
                            "addr": str_addr,
                        }
                        # Also set payload_prefix on ctx so engine exploits
                        # automatically include the gate bypass.
                        ctx.payload_prefix = s + b"\x00"
                        log.info(f"Agent observer: strcmp gate '{gate_str}' → payload_prefix set")
                        return
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# 10. Local variable overwrite → system (gets overflow, canary safe)
# ---------------------------------------------------------------------------
def observe_local_overwrite(state: AgentState) -> None:
    """Detect: gets/read/scanf fills buffer adjacent to a local variable
    that is compared (via custom check func, strcmp, or inline cmp) against
    a known string.  If comparison succeeds → system/win.

    Pattern (mrctf2020_easyoverflow etc.):
      1. main: lea -0x70(%rbp),%rax → call gets   (buf at rbp-0x70)
      2. main: movabs $imm,%rax → mov %rax,-0x40(%rbp)  (init local with fake string)
      3. main: lea -0x40(%rbp),%rax → call check   (pass local to check func)
      4. main: test %eax → je/jne → system("/bin/sh")
      5. check: loads global string pointer → char-by-char cmp

    Exploit: padding(buf_off - var_off) + target_string
    """
    if state.discovered_facts.get("local_overwrite"):
        return

    ctx = state.ctx
    if not ctx.elf:
        return

    # Must have an unbounded-ish input function and system/win target
    plt = ctx.plt_table or {}
    syms = {}
    try:
        syms = ctx.elf.symbols or {}
    except Exception:
        pass
    has_input = any(f in plt or f in syms for f in ("gets", "read", "__isoc99_scanf", "scanf"))
    has_system = any(f in plt or f in syms for f in ("system",))
    if not has_input or not has_system:
        return

    disasm = _get_objdump(ctx.binary_path)
    if not disasm:
        return

    # Build function map for cross-function analysis
    all_funcs: dict[str, list[str]] = {}
    for fname, flines in _iter_functions(disasm):
        all_funcs[fname] = flines

    bp = r'%[re]bp'  # works for both 32-bit (ebp) and 64-bit (rbp)

    for func_name, func_lines in all_funcs.items():
        if func_name.startswith("_") or func_name in (
            'register_tm_clones', 'deregister_tm_clones',
            'frame_dummy', '__do_global_dtors_aux',
            '__libc_csu_init', '__libc_csu_fini',
        ):
            continue

        input_buf_off = 0        # rbp-offset of input buffer
        input_func = ""
        local_var_offsets: list[int] = []  # offsets of initialized local vars
        check_callee = ""        # name of comparison function called
        check_arg_offset = 0     # rbp-offset passed to check function
        has_system_call = False
        has_win_call = False
        last_lea_off = 0
        last_lea_idx = -1

        for idx, line in enumerate(func_lines):
            # Track lea -OFF(%rbp) for correlating with subsequent calls
            m_lea = re.search(r'lea\s+-(0x[0-9a-f]+)\(' + bp + r'\)', line, re.I)
            if m_lea:
                last_lea_off = int(m_lea.group(1), 16)
                last_lea_idx = idx

            # --- Detect input call + buffer offset ---
            if 'call' in line:
                if 'gets' in line and 'fgets' not in line:
                    if last_lea_idx >= 0 and idx - last_lea_idx <= 4:
                        input_buf_off = last_lea_off
                        input_func = "gets"
                elif re.search(r'(scanf|__isoc99_scanf)', line):
                    # scanf with %s format can overflow too
                    if last_lea_idx >= 0 and idx - last_lea_idx <= 6:
                        if not input_buf_off or last_lea_off > input_buf_off:
                            input_buf_off = last_lea_off
                            input_func = "scanf"
                elif 'read' in line and 'readl' not in line:
                    if last_lea_idx >= 0 and idx - last_lea_idx <= 6:
                        if not input_buf_off or last_lea_off > input_buf_off:
                            input_buf_off = last_lea_off
                            input_func = "read"

                # --- Detect system/win call ---
                if 'system' in line:
                    has_system_call = True
                if re.search(r'<(win|flag|shell|backdoor|get_flag|print_flag|'
                             r'cat_flag|getshell|get_shell)>', line, re.I):
                    has_win_call = True

                # --- Detect non-library function call (potential check function) ---
                if '<' in line and '@plt' not in line:
                    m_call = re.search(r'call\s+[0-9a-f]+\s+<(\w+)>', line)
                    if m_call:
                        callee = m_call.group(1)
                        if callee not in ('main', '__libc_csu_init', 'init'):
                            if last_lea_idx >= 0 and idx - last_lea_idx <= 4:
                                check_callee = callee
                                check_arg_offset = last_lea_off

                # --- Detect direct strcmp/strncmp call ---
                if 'strcmp' in line or 'strncmp' in line:
                    if last_lea_idx >= 0 and idx - last_lea_idx <= 4:
                        check_callee = 'strcmp'
                        check_arg_offset = last_lea_off

            # --- Detect local variable initialization (movabs/mov to stack) ---
            # movabs $0x665f405f7433756a, %rax (64-bit string constant)
            m_movabs = re.search(r'movabs\s+\$(0x[0-9a-f]+),\s*%(\w+)', line, re.I)
            if m_movabs:
                reg = m_movabs.group(2).lower()
                for k in range(idx, min(idx + 4, len(func_lines))):
                    m_st = re.search(r'mov\s+%' + reg + r',\s*-(0x[0-9a-f]+)\(' + bp + r'\)',
                                     func_lines[k], re.I)
                    if m_st:
                        off = int(m_st.group(1), 16)
                        if off not in local_var_offsets:
                            local_var_offsets.append(off)
                        break

            # mov $0xNNNNNN, %reg → mov %reg, -OFF(%rbp)  (32-bit or small string)
            m_mov = re.search(r'mov\w*\s+\$(0x[0-9a-f]{6,}),\s*%(\w+)', line, re.I)
            if m_mov and not m_movabs:
                reg = m_mov.group(2).lower()
                for k in range(idx, min(idx + 4, len(func_lines))):
                    m_st = re.search(r'mov\s+%' + reg + r',\s*-(0x[0-9a-f]+)\(' + bp + r'\)',
                                     func_lines[k], re.I)
                    if m_st:
                        off = int(m_st.group(1), 16)
                        if off not in local_var_offsets:
                            local_var_offsets.append(off)
                        break

            # Direct store: movl $0xNNNNNN, -OFF(%rbp)  (inline string init, 32-bit)
            m_direct = re.search(
                r'movl?\s+\$(0x[0-9a-f]{6,}),\s*-(0x[0-9a-f]+)\(' + bp + r'\)',
                line, re.I)
            if m_direct:
                off = int(m_direct.group(2), 16)
                if off not in local_var_offsets:
                    local_var_offsets.append(off)

        if not input_buf_off or not (has_system_call or has_win_call):
            continue

        # --- Find comparison variable offset ---
        # Require either a check function call or direct strcmp with the local var.
        # Without a comparison mechanism, this is likely a different pattern
        # (e.g., command injection via strcat+system).
        cmp_var_offset = 0
        if check_arg_offset and check_arg_offset < input_buf_off:
            cmp_var_offset = check_arg_offset
        elif check_callee == 'strcmp' and local_var_offsets:
            # strcmp was called; use the closest local var
            candidates = [o for o in local_var_offsets if o < input_buf_off]
            if candidates:
                cmp_var_offset = max(candidates)

        if cmp_var_offset == 0:
            continue

        pad_size = input_buf_off - cmp_var_offset
        if pad_size <= 0 or pad_size > 0x200:
            continue

        # --- Find the actual comparison target string ---
        # Priority 1: Analyze the check function for global string references
        priority_strings: list[bytes] = []
        if check_callee and check_callee in all_funcs and check_callee != 'strcmp':
            priority_strings = _find_check_func_strings(ctx, all_funcs[check_callee])

        # Priority 2: For direct strcmp, find the other string argument
        if not priority_strings and check_callee == 'strcmp':
            s = _find_strcmp_other_arg(ctx, func_lines)
            if s:
                priority_strings = [s]

        # Priority 3: Scan non-main functions for string comparisons
        if not priority_strings:
            for fname, flines in all_funcs.items():
                if fname.startswith("_") or fname == func_name:
                    continue
                if fname in ('register_tm_clones', 'deregister_tm_clones',
                             'frame_dummy', '__do_global_dtors_aux',
                             '__libc_csu_init', '__libc_csu_fini'):
                    continue
                # Does this function do char-by-char comparison?
                has_cmp = any(re.search(r'cmp\s+%[a-d]l,\s*%[a-d]l', l, re.I)
                             for l in flines)
                has_strcmp_call = any('strcmp' in l and 'call' in l for l in flines)
                if has_cmp or has_strcmp_call:
                    strs = _find_check_func_strings(ctx, flines)
                    priority_strings.extend(strs)

        # Fallback: all .rodata strings (filtered)
        fallback_strings = _extract_rodata_strings(ctx)

        # Merge: priority strings first, then fallback (deduped)
        all_target_strings: list[str] = []
        seen: set[str] = set()
        for s in priority_strings:
            text = s.decode("latin-1", errors="replace")
            if text not in seen:
                all_target_strings.append(text)
                seen.add(text)
        for s in fallback_strings:
            text = s.decode("latin-1", errors="replace")
            if text not in seen:
                all_target_strings.append(text)
                seen.add(text)

        state.discovered_facts["local_overwrite"] = {
            "function": func_name,
            "gets_buf_offset": input_buf_off,
            "cmp_var_offset": cmp_var_offset,
            "pad_size": pad_size,
            "target_strings": all_target_strings[:15],
            "input_func": input_func,
            "check_callee": check_callee,
            "description": (f"{input_func}@rbp-{input_buf_off:#x} → overflow to "
                           f"cmp_var@rbp-{cmp_var_offset:#x}, pad={pad_size}"),
        }
        log.info(f"Agent observer: local overwrite in {func_name}, "
                 f"pad={pad_size}, input={input_func}, check={check_callee}, "
                 f"targets={len(all_target_strings)} "
                 f"(priority={len(priority_strings)})")
        return


def _find_check_func_strings(ctx, callee_lines: list[str]) -> list[bytes]:
    """Analyze a check function's disassembly to find the comparison target string.

    Looks for:
    1. Global pointer loads: mov OFFSET(%rip),%rax  # <global_symbol>
       → resolve via relocations to get the pointed-to string
    2. Direct lea references: lea OFFSET(%rip),%reg  # addr
       → read string at that address
    """
    elf = ctx.elf
    if not elf:
        return []

    found: list[bytes] = []
    for line in callee_lines:
        # Pattern 1: mov with RIP-relative → global pointer (PIE)
        # "mov 0x200863(%rip),%rax  # 201010 <fake_flag>"
        m = re.search(r'#\s*([0-9a-f]+)\s+<(\w+)>', line)
        if m and 'mov' in line and '%rip' in line:
            global_addr = int(m.group(1), 16)
            # Resolve the pointer via relocations
            ptr_val = _resolve_global_ptr(elf, global_addr)
            if ptr_val:
                try:
                    s = elf.string(ptr_val)
                    if s and 2 < len(s) < 128 and _is_mostly_printable(s):
                        if s not in (b'/bin/sh', b'sh', b'%s', b'%d', b'%x'):
                            found.append(s)
                except Exception:
                    pass

        # Pattern 2: lea with RIP-relative → direct .rodata string
        # "lea 0xd0(%rip),%rdi  # 954 <_IO_stdin_used+0x14>"
        m2 = re.search(r'#\s*([0-9a-f]+)\b', line)
        if m2 and 'lea' in line and '%rip' in line:
            str_addr = int(m2.group(1), 16)
            try:
                s = elf.string(str_addr)
                if s and 2 < len(s) < 128 and _is_mostly_printable(s):
                    if s not in (b'/bin/sh', b'sh', b'%s', b'%d', b'%x', b'%ld'):
                        found.append(s)
            except Exception:
                pass

        # Pattern 3: 32-bit absolute address (push $0xaddr or mov $0xaddr)
        m3 = re.search(r'(?:push|mov)\s+\$(0x[0-9a-f]{5,})', line, re.I)
        if m3:
            addr = int(m3.group(1), 16)
            try:
                s = elf.string(addr)
                if s and 2 < len(s) < 128 and _is_mostly_printable(s):
                    if s not in (b'/bin/sh', b'sh', b'%s', b'%d'):
                        found.append(s)
            except Exception:
                pass

    return found


def _resolve_global_ptr(elf, addr: int) -> int:
    """Resolve a global pointer value, checking relocations first."""
    # Check relocations for R_X86_64_RELATIVE (PIE) or similar
    try:
        for reloc in elf.relocs:
            if reloc.r_offset == addr:
                if hasattr(reloc, 'r_addend') and reloc.r_addend:
                    return reloc.r_addend
    except Exception:
        pass

    # Fallback: read raw pointer bytes
    try:
        data = elf.read(addr, 8 if elf.bits == 64 else 4)
        if elf.bits == 64:
            return struct.unpack("<Q", data)[0]
        else:
            return struct.unpack("<I", data)[0]
    except Exception:
        pass
    return 0


def _find_strcmp_other_arg(ctx, func_lines: list[str]) -> bytes:
    """For direct strcmp calls in the function, find the constant string argument."""
    elf = ctx.elf
    if not elf:
        return b""

    for idx, line in enumerate(func_lines):
        if 'call' not in line or 'strcmp' not in line:
            continue
        # Look backward for lea/push with string address
        for j in range(max(0, idx - 6), idx):
            prev = func_lines[j]
            # RIP-relative lea
            m = re.search(r'#\s*([0-9a-f]+)\b', prev)
            if m and 'lea' in prev and '%rip' in prev:
                str_addr = int(m.group(1), 16)
                try:
                    s = elf.string(str_addr)
                    if s and 2 < len(s) < 128 and _is_mostly_printable(s):
                        if s not in (b'/bin/sh', b'sh'):
                            return s
                except Exception:
                    pass
            # Absolute address
            m2 = re.search(r'(?:push|mov)\s+\$(0x[0-9a-f]{5,})', prev, re.I)
            if m2:
                addr = int(m2.group(1), 16)
                try:
                    s = elf.string(addr)
                    if s and 2 < len(s) < 128 and _is_mostly_printable(s):
                        if s not in (b'/bin/sh', b'sh'):
                            return s
                except Exception:
                    pass
    return b""


def _extract_rodata_strings(ctx) -> list[bytes]:
    """Extract printable strings from .rodata as fallback candidates."""
    result: list[bytes] = []
    try:
        rodata = ctx.elf.get_section_by_name(".rodata")
        if not rodata:
            return result
        data = rodata.data()
        cur = b""
        for byte in data:
            if byte == 0:
                if len(cur) >= 4 and cur.isascii():
                    text = cur.decode("ascii", errors="replace")
                    skip = any(k in text.lower() for k in [
                        "libc", "gmon", "frame", "gcc", "gnu",
                        "/bin/sh", "system", "printf", "exit",
                        "usage", "error", "help", "version",
                    ])
                    if not skip:
                        result.append(cur)
                cur = b""
            else:
                cur += bytes([byte])
    except Exception:
        pass
    return result


def _is_mostly_printable(s: bytes) -> bool:
    """Check if bytes are mostly printable ASCII."""
    if not s:
        return False
    printable = sum(1 for b in s if 0x20 <= b < 0x7f)
    return printable >= len(s) * 0.8


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
_objdump_cache: dict[str, str] = {}


def _get_objdump(binary_path: str) -> str:
    """Get objdump disassembly, cached."""
    if binary_path in _objdump_cache:
        return _objdump_cache[binary_path]
    try:
        result = subprocess.run(
            ["objdump", "-d", binary_path],
            capture_output=True, text=True, timeout=10,
        )
        _objdump_cache[binary_path] = result.stdout
        return result.stdout
    except Exception:
        return ""


def _iter_functions(disasm: str):
    """Yield (func_name, [lines]) from objdump output."""
    func_name = ""
    func_lines: list[str] = []
    for line in disasm.splitlines():
        m = re.match(r'[0-9a-f]+ <(\w+)>:', line)
        if m:
            if func_name and func_lines:
                yield func_name, func_lines
            func_name = m.group(1)
            func_lines = []
            continue
        if func_name:
            func_lines.append(line)
    if func_name and func_lines:
        yield func_name, func_lines


def _iter_functions_from_lines(lines: list[str]):
    """Same as _iter_functions but from pre-split lines."""
    func_name = ""
    func_lines: list[str] = []
    for line in lines:
        m = re.match(r'[0-9a-f]+ <(\w+)>:', line)
        if m:
            if func_name and func_lines:
                yield func_name, func_lines
            func_name = m.group(1)
            func_lines = []
            continue
        if func_name:
            func_lines.append(line)
    if func_name and func_lines:
        yield func_name, func_lines


_ALL_OBSERVERS = [
    observe_sleep_block,
    observe_cmp_win,
    observe_var_overwrite_win,
    observe_system_no_binsh,
    observe_fmt_canary_combo,
    observe_close_stdout,
    observe_shellcode_exec,
    observe_expanded_win,
    observe_strcmp_gate,
    observe_local_overwrite,
]
