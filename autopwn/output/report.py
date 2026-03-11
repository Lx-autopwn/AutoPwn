from __future__ import annotations

from typing import TYPE_CHECKING

from pwn import log

if TYPE_CHECKING:
    from autopwn.context import PwnContext


def _section(title: str) -> None:
    line = "=" * 60
    log.info(f"\033[1;36m{line}\033[0m")
    log.info(f"\033[1;36m  {title}\033[0m")
    log.info(f"\033[1;36m{line}\033[0m")


def _subsection(title: str) -> None:
    log.info(f"\033[1;33m--- {title} ---\033[0m")


def print_full_report(ctx: PwnContext) -> None:
    _section("AUTOPWN ANALYSIS REPORT")

    _subsection("Target")
    log.info(f"  Binary  : {ctx.binary_path}")
    log.info(f"  Arch    : {ctx.arch} ({ctx.bits}-bit, {ctx.endian})")

    _subsection("Checksec")
    green = "\033[0;32m"
    red = "\033[0;31m"
    yellow = "\033[0;33m"
    reset = "\033[0m"
    nx_c = green if ctx.nx else red
    pie_c = green if ctx.pie else red
    can_c = green if ctx.canary else red
    relro_c = green if ctx.relro == "full" else (yellow if ctx.relro == "partial" else red)
    log.info(f"  NX      : {nx_c}{ctx.nx}{reset}")
    log.info(f"  PIE     : {pie_c}{ctx.pie}{reset}")
    log.info(f"  Canary  : {can_c}{ctx.canary}{reset}")
    log.info(f"  RELRO   : {relro_c}{ctx.relro}{reset}")
    log.info(f"  Fortify : {ctx.fortify}")

    if ctx.dangerous_funcs:
        _subsection("Dangerous Functions")
        for f in ctx.dangerous_funcs:
            name = f.get("name", "?") if isinstance(f, dict) else getattr(f, "name", "?")
            addr = f.get("addr", 0) if isinstance(f, dict) else getattr(f, "addr", 0)
            log.info(f"  {red}{name}{reset} @ {addr:#x}")

    if ctx.win_funcs:
        _subsection("Win Functions")
        for f in ctx.win_funcs:
            name = f.get("name", "?") if isinstance(f, dict) else getattr(f, "name", "?")
            addr = f.get("addr", 0) if isinstance(f, dict) else getattr(f, "addr", 0)
            log.info(f"  {green}{name}{reset} @ {addr:#x}")

    if ctx.input_funcs:
        _subsection("Input Functions")
        for f in ctx.input_funcs:
            name = f.get("name", "?") if isinstance(f, dict) else getattr(f, "name", "?")
            addr = f.get("addr", 0) if isinstance(f, dict) else getattr(f, "addr", 0)
            log.info(f"  {name} @ {addr:#x}")

    if ctx.output_funcs:
        _subsection("Output Functions")
        for f in ctx.output_funcs:
            name = f.get("name", "?") if isinstance(f, dict) else getattr(f, "name", "?")
            addr = f.get("addr", 0) if isinstance(f, dict) else getattr(f, "addr", 0)
            log.info(f"  {name} @ {addr:#x}")

    if ctx.useful_strings:
        _subsection("Useful Strings")
        for s, addr in ctx.useful_strings.items():
            display = repr(s) if len(s) <= 60 else repr(s[:60]) + "..."
            log.info(f"  {addr:#x}: {display}")

    if ctx.got_table:
        _subsection("GOT Table")
        for name, addr in ctx.got_table.items():
            log.info(f"  {name:30s} @ {addr:#x}")

    if ctx.seccomp_rules:
        _subsection("Seccomp Rules")
        log.info(f"  execve allowed: {ctx.execve_allowed}")
        for syscall, action in ctx.seccomp_rules.items():
            log.info(f"  {syscall}: {action}")

    print_vuln_report(ctx)

    if ctx.primitives:
        _subsection("Exploit Primitives")
        for p in ctx.primitives:
            pname = p.get("name", str(p)) if isinstance(p, dict) else getattr(p, "name", str(p))
            pdesc = p.get("description", "") if isinstance(p, dict) else getattr(p, "description", "")
            log.info(f"  {green}[+]{reset} {pname}")
            if pdesc:
                log.info(f"      {pdesc}")

    if ctx.exploit_paths:
        _subsection("Exploit Paths (ranked)")
        for i, ep in enumerate(ctx.exploit_paths, 1):
            desc = ep.get("description", str(ep)) if isinstance(ep, dict) else getattr(ep, "description", str(ep))
            score = ep.get("score", 0) if isinstance(ep, dict) else getattr(ep, "score", 0)
            log.info(f"  #{i} [score={score:>5.1f}] {desc}")

    if ctx.overflow_offset >= 0:
        _subsection("Dynamic Analysis")
        log.info(f"  Overflow offset : {ctx.overflow_offset}")
        if ctx.canary_offset:
            log.info(f"  Canary offset   : {ctx.canary_offset}")
        log.info(f"  Input type      : {ctx.input_type}")
        if ctx.bad_bytes:
            log.info(f"  Bad bytes       : {ctx.bad_bytes.hex()}")
        if ctx.input_max_len:
            log.info(f"  Max input len   : {ctx.input_max_len}")

    if ctx.leaked_addrs:
        _subsection("Runtime Leaks")
        for name, addr in ctx.leaked_addrs.items():
            log.info(f"  {name:20s} = {addr:#x}")

    _section("END OF REPORT")


def print_vuln_report(ctx: PwnContext) -> None:
    if not ctx.vulnerabilities:
        return
    _subsection("Vulnerabilities")
    red = "\033[0;31m"
    yellow = "\033[0;33m"
    reset = "\033[0m"
    for v in ctx.vulnerabilities:
        if isinstance(v, dict):
            vtype = v.get("type", "unknown")
            conf = v.get("confidence", "suspected")
            desc = v.get("description", "")
            func = v.get("function", "")
        else:
            vtype = getattr(v, "type", "unknown")
            conf = getattr(v, "confidence", "suspected")
            desc = getattr(v, "description", "")
            func = getattr(v, "function", "")

        color = red if conf in ("confirmed_static", "confirmed_dynamic") else yellow
        tag = "CONFIRMED" if "confirmed" in conf else "SUSPECTED"
        loc = f" in {func}" if func else ""
        log.info(f"  {color}[{tag}]{reset} {vtype}{loc}")
        if desc:
            log.info(f"    {desc}")

    heap_vulns = []
    if ctx.has_uaf:
        heap_vulns.append("UAF")
    if ctx.has_double_free:
        heap_vulns.append("Double Free")
    if ctx.has_heap_overflow:
        heap_vulns.append("Heap Overflow")
    if ctx.has_off_by_one:
        heap_vulns.append("Off-by-One")
    if heap_vulns:
        log.info(f"  Heap vuln flags: {', '.join(heap_vulns)}")
        if ctx.glibc_version:
            log.info(f"  glibc: {ctx.glibc_version}")
