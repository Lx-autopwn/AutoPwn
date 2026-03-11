from __future__ import annotations

import re
import subprocess
from typing import TYPE_CHECKING, Any

from pwn import log

if TYPE_CHECKING:
    from autopwn.context import PwnContext


def analyze_seccomp(ctx: PwnContext) -> None:
    """Analyze seccomp rules via seccomp-tools, write to ctx.seccomp_rules and ctx.execve_allowed."""
    if not ctx.binary_path:
        log.warn("seccomp: no binary path")
        return

    ctx.execve_allowed = True
    ctx.seccomp_rules = {}

    try:
        proc = subprocess.run(
            ["seccomp-tools", "dump", ctx.binary_path],
            capture_output=True, timeout=10,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        log.debug("seccomp: seccomp-tools not found, skipping")
        return
    except subprocess.TimeoutExpired:
        log.debug("seccomp: timed out (binary may not use seccomp)")
        return

    raw = proc.stdout + proc.stderr
    output = raw.decode("utf-8", errors="replace")
    if not output.strip():
        log.debug("seccomp: no rules detected")
        return

    rules = _parse_seccomp_output(output)
    if not rules:
        log.debug("seccomp: no parseable rules")
        return

    ctx.seccomp_rules = rules

    # check if execve is blocked
    execve_blocked = False
    for syscall, action in rules.items():
        if "execve" in syscall.lower():
            if "kill" in str(action).lower() or "errno" in str(action).lower():
                execve_blocked = True
                break

    # also check for whitelist mode (default kill/errno)
    default_action = str(rules.get("default", "")).upper()
    if default_action in ("KILL", "KILL_PROCESS", "TRAP") or "ERRNO" in default_action:
        # whitelist mode: execve allowed only if explicitly listed as ALLOW
        if "execve" not in rules or rules.get("execve", "").upper() != "ALLOW":
            execve_blocked = True

    ctx.execve_allowed = not execve_blocked
    log.info(f"seccomp: {len(rules)} rules, execve_allowed={ctx.execve_allowed}")


def _parse_seccomp_output(output: str) -> dict[str, Any]:
    """Parse seccomp-tools dump output into a dict.

    Handles goto-based BPF rules where syscall comparisons jump to
    a target line containing the action (whitelist/blacklist patterns).

    Example BPF (whitelist):
        0007: if (A == open)  goto 0011
        0008: if (A == read)  goto 0011
        0009: if (A == write) goto 0011
        0010: return ERRNO(38)
        0011: return ALLOW

    Example BPF (blacklist):
        0005: if (A == execve) goto 0007
        0006: return ALLOW
        0007: return KILL
    """
    rules: dict[str, Any] = {}

    # Parse all lines into structured form, indexed by line number
    line_re = re.compile(r"^\s*(\d{4}):\s*(.*)")
    syscall_goto_re = re.compile(
        r"if\s*\(\s*A\s*==\s*(\w+)\s*\)\s*goto\s+(\d{4})", re.IGNORECASE
    )
    # "if (A != X) goto NNNN" — negated: if X matches, fall through to next line
    syscall_neq_goto_re = re.compile(
        r"if\s*\(\s*A\s*!=\s*(\w+)\s*\)\s*goto\s+(\d{4})", re.IGNORECASE
    )
    action_re = re.compile(
        r"return\s+(ALLOW|KILL|KILL_PROCESS|TRAP|ERRNO\(\d+\))", re.IGNORECASE
    )
    # Fallback: "if (A == X) ... else ..." without goto (next-line style)
    syscall_nogo_re = re.compile(r"if\s*\(\s*A\s*==\s*(\w+)\s*\)", re.IGNORECASE)

    # First pass: collect line contents and identify actions at each line
    line_contents: dict[int, str] = {}
    line_actions: dict[int, str] = {}  # linenum -> action string
    for raw in output.splitlines():
        m = line_re.match(raw)
        if m:
            num = int(m.group(1))
            content = m.group(2).strip()
            line_contents[num] = content
            am = action_re.search(content)
            if am:
                line_actions[num] = am.group(1).upper()

    # Second pass: map syscalls to their actions via goto targets
    eq_goto_targets: set[int] = set()   # targets of "==" goto (allow/deny for matched syscall)
    neq_goto_targets: set[int] = set()  # targets of "!=" goto (deny path for unmatched)
    syscall_to_target: dict[str, int] = {}
    fallthrough_syscalls: list[str] = []  # syscalls without goto

    # Also track "!=" negated goto: syscall falls through to next line
    neq_syscall_fallthrough: dict[str, int] = {}  # syscall -> next_line_num

    sorted_lines = sorted(line_contents)
    for idx, num in enumerate(sorted_lines):
        content = line_contents[num]
        gm = syscall_goto_re.search(content)
        if gm:
            syscall = gm.group(1)
            target = int(gm.group(2))
            syscall_to_target[syscall] = target
            eq_goto_targets.add(target)
        else:
            nm = syscall_neq_goto_re.search(content)
            if nm:
                # "if (A != X) goto N" means: if A == X, fall through to next line
                syscall = nm.group(1)
                neg_target = int(nm.group(2))
                neq_goto_targets.add(neg_target)
                # The match case falls through to the next line
                if idx + 1 < len(sorted_lines):
                    next_line = sorted_lines[idx + 1]
                    neq_syscall_fallthrough[syscall] = next_line
            else:
                # Check for syscall comparison without goto (next-line action)
                sm = syscall_nogo_re.search(content)
                if sm and "goto" not in content.lower():
                    fallthrough_syscalls.append(sm.group(1))

    # Resolve goto-based syscalls (A == X goto target)
    for syscall, target in syscall_to_target.items():
        if target in line_actions:
            rules[syscall] = line_actions[target]

    # Resolve negated-goto syscalls (A != X goto target → X falls to next line)
    for syscall, next_line in neq_syscall_fallthrough.items():
        if next_line in line_actions and syscall not in rules:
            rules[syscall] = line_actions[next_line]

    # Resolve fallthrough syscalls (legacy sequential parsing)
    if fallthrough_syscalls and not syscall_to_target:
        # Only use fallthrough if there are no goto-based rules
        current_syscall = None
        for num in sorted(line_contents):
            content = line_contents[num]
            sm = syscall_nogo_re.search(content)
            if sm:
                current_syscall = sm.group(1)
                continue
            am = action_re.search(content)
            if am and current_syscall:
                rules[current_syscall] = am.group(1).upper()
                current_syscall = None

    # Determine default action.
    # Lines targeted by "==" goto are syscall-specific actions, not default.
    # Lines targeted by "!=" goto are the "no match" path = default action.
    # Lines not targeted by any goto that have a return action are also default.
    all_goto_targets = eq_goto_targets | neq_goto_targets
    for num in sorted(line_actions):
        if num not in eq_goto_targets:
            # This is either a "!=" goto target (default deny) or
            # an untargeted return (also default)
            rules["default"] = line_actions[num]

    return rules
