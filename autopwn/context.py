from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Any

from pwn import ELF, log


@dataclass
class PwnContext:
    # target info
    binary_path: str = ""
    elf: ELF | None = None
    arch: str = "amd64"
    bits: int = 64
    endian: str = "little"

    # security
    nx: bool = False
    pie: bool = False
    canary: bool = False
    relro: str = "no"
    fortify: bool = False

    # white-box analysis results
    decompiled: dict[str, Any] = field(default_factory=dict)
    cfg: Any = None
    callgraph: Any = None
    taint_flows: list[Any] = field(default_factory=list)
    vulnerabilities: list[Any] = field(default_factory=list)
    primitives: list[Any] = field(default_factory=list)
    exploit_paths: list[Any] = field(default_factory=list)

    # recon results
    dangerous_funcs: list[dict[str, Any]] = field(default_factory=list)
    win_funcs: list[dict[str, Any]] = field(default_factory=list)
    input_funcs: list[dict[str, Any]] = field(default_factory=list)
    output_funcs: list[dict[str, Any]] = field(default_factory=list)
    useful_strings: dict[str, int] = field(default_factory=dict)
    gadgets: dict[str, int] = field(default_factory=dict)
    got_table: dict[str, int] = field(default_factory=dict)
    plt_table: dict[str, int] = field(default_factory=dict)
    seccomp_rules: dict[str, Any] = field(default_factory=dict)
    execve_allowed: bool = True

    # dynamic results
    overflow_offset: int = -1  # -1 = not detected, >= 0 = valid offset
    overflow_prefix: bytes = b""  # bytes to send before overflow payload (e.g. scanf bypass)
    payload_prefix: bytes = b""  # prepended to overflow payload (e.g. strcmp gate bypass)
    canary_offset: int = 0
    input_type: str = "direct"
    menu_map: dict[str, Any] = field(default_factory=dict)
    bad_bytes: bytes = b""
    input_max_len: int = 0
    has_loop: bool = False
    is_forking: bool = False
    initial_prompt: bytes = b""

    # program behavior classification
    behavior: str = ""  # "shellcode_runner", "menu_program", "simple_io", etc.
    shellcode_info: dict[str, Any] = field(default_factory=dict)
    # e.g. {"rwx_addr": 0, "read_size": 512, "has_filter": True, "filter_type": "whitelist"}
    input_limit: int = 0  # max bytes the vulnerable read() accepts
    interaction_model: Any = None  # InteractionModel from interaction_prober
    r2_profile: Any = None  # R2Profile from r2_analyzer
    is_multi_prompt: bool = False  # True if binary has multiple distinct prompts (not a loop)

    # heap state
    heap_state: Any = None
    heap_ops_log: list[Any] = field(default_factory=list)
    menu_to_heap_map: dict[str, Any] = field(default_factory=dict)

    # runtime
    leaked_addrs: dict[str, int] = field(default_factory=dict)
    canary_value: int = 0
    pie_base: int = 0
    libc: ELF | None = None
    libc_base: int = 0
    stack_addr: int = 0
    heap_base: int = 0

    # heap vuln flags
    has_uaf: bool = False
    has_double_free: bool = False
    has_heap_overflow: bool = False
    has_off_by_one: bool = False
    glibc_version: str = ""

    def print_report(self) -> None:
        hdr = lambda t: log.info(f"{'=' * 20} {t} {'=' * 20}")

        hdr("Target")
        log.info(f"  Binary : {self.binary_path}")
        log.info(f"  Arch   : {self.arch} ({self.bits}-bit, {self.endian})")

        hdr("Security")
        log.info(f"  NX     : {self.nx}")
        log.info(f"  PIE    : {self.pie}")
        log.info(f"  Canary : {self.canary}")
        log.info(f"  RELRO  : {self.relro}")
        log.info(f"  Fortify: {self.fortify}")

        if self.dangerous_funcs:
            hdr("Dangerous Functions")
            for f in self.dangerous_funcs:
                log.info(f"  {f.get('name', '?')} @ {f.get('addr', 0):#x}")

        if self.win_funcs:
            hdr("Win Functions")
            for f in self.win_funcs:
                log.info(f"  {f.get('name', '?')} @ {f.get('addr', 0):#x}")

        if self.vulnerabilities:
            hdr("Vulnerabilities")
            for v in self.vulnerabilities:
                vtype = v.get("type", "unknown") if isinstance(v, dict) else getattr(v, "type", "unknown")
                vconf = v.get("confidence", "?") if isinstance(v, dict) else getattr(v, "confidence", "?")
                log.info(f"  [{vconf}] {vtype}")

        if self.primitives:
            hdr("Exploit Primitives")
            for p in self.primitives:
                pname = p.get("name", str(p)) if isinstance(p, dict) else getattr(p, "name", str(p))
                log.info(f"  - {pname}")

        if self.exploit_paths:
            hdr("Exploit Paths")
            for i, ep in enumerate(self.exploit_paths, 1):
                desc = ep.get("description", str(ep)) if isinstance(ep, dict) else getattr(ep, "description", str(ep))
                score = ep.get("score", 0) if isinstance(ep, dict) else getattr(ep, "score", 0)
                log.info(f"  #{i} [score={score}] {desc}")

        if self.overflow_offset >= 0:
            hdr("Dynamic")
            log.info(f"  Overflow offset: {self.overflow_offset}")
            if self.canary_offset:
                log.info(f"  Canary offset  : {self.canary_offset}")
            log.info(f"  Input type     : {self.input_type}")
            if self.bad_bytes:
                log.info(f"  Bad bytes      : {self.bad_bytes.hex()}")

        if self.leaked_addrs:
            hdr("Leaked Addresses")
            for name, addr in self.leaked_addrs.items():
                log.info(f"  {name} = {addr:#x}")

        if self.gadgets:
            hdr("Key Gadgets")
            shown = 0
            for g, addr in self.gadgets.items():
                if shown >= 15:
                    log.info(f"  ... and {len(self.gadgets) - shown} more")
                    break
                log.info(f"  {addr:#x}: {g}")
                shown += 1

        if self.seccomp_rules:
            hdr("Seccomp")
            log.info(f"  execve allowed: {self.execve_allowed}")
            for syscall, action in self.seccomp_rules.items():
                log.info(f"  {syscall}: {action}")

        if any([self.has_uaf, self.has_double_free, self.has_heap_overflow, self.has_off_by_one]):
            hdr("Heap Vulns")
            if self.has_uaf:
                log.info("  UAF detected")
            if self.has_double_free:
                log.info("  Double free detected")
            if self.has_heap_overflow:
                log.info("  Heap overflow detected")
            if self.has_off_by_one:
                log.info("  Off-by-one detected")
            if self.glibc_version:
                log.info(f"  glibc version: {self.glibc_version}")

    def find_gadget(self, pattern: str) -> int:
        """Find a ROP gadget matching *pattern*.

        Search order (most specific to least):
        1. Exact string match
        2. Case-insensitive exact match
        3. Clean match: ``{pattern} ; ret`` (the minimal gadget)
        4. Prefix match: gadget starts with *pattern*, only pops
           follow, and ends with ``ret`` (e.g. "pop rdx ; pop rbx ; ret")
        5. Substring match but only in gadgets ending with ``; ret``
           (avoids dirty gadgets like ``imul al ; pop rdx ; ret 0``)
        """
        # 1. Exact
        if pattern in self.gadgets:
            return self.gadgets[pattern]

        pattern_lower = pattern.lower().strip()

        # Normalize semicolons: "pop rdi ; ret" ↔ "pop rdi; ret"
        import re
        pattern_norm = re.sub(r'\s*;\s*', '; ', pattern_lower)

        # 2. Case-insensitive exact (with semicolon normalization)
        for g, addr in self.gadgets.items():
            gn = re.sub(r'\s*;\s*', '; ', g.lower().strip())
            if pattern_norm == gn:
                return addr

        # 3. Clean minimal: "{pattern} ; ret"
        clean = pattern_norm + " ; ret"
        # Also handle "pattern; ret" without leading space
        clean2 = pattern_norm.rstrip() + "; ret"
        for g, addr in self.gadgets.items():
            gn = re.sub(r'\s*;\s*', '; ', g.lower().strip())
            if gn == clean or gn == clean2:
                return addr

        # 4. Prefix match: gadget starts with pattern, rest is pops/ret
        for g, addr in self.gadgets.items():
            gn = re.sub(r'\s*;\s*', '; ', g.lower().strip())
            if gn.startswith(pattern_norm) and gn.endswith("; ret"):
                # Only allow additional pop instructions between
                rest = gn[len(pattern_norm):].strip().lstrip(";").strip()
                parts = [p.strip() for p in rest.split(";")]
                if all(p.startswith("pop ") or p == "ret" for p in parts):
                    return addr

        # 5. Substring match but only clean gadgets (ending with "; ret",
        #    no side-effect instructions)
        for g, addr in self.gadgets.items():
            gn = re.sub(r'\s*;\s*', '; ', g.lower().strip())
            if pattern_norm in gn and gn.endswith("; ret"):
                # Reject gadgets with side effects before our pattern
                before = gn[:gn.index(pattern_norm)].strip().rstrip(";").strip()
                if not before:  # pattern is at the start
                    return addr

        # Fallback: ROPgadget direct search
        if self.elf and not self.gadgets:
            return self._search_gadget_ropgadget(pattern)
        return 0

    def _search_gadget_ropgadget(self, pattern: str) -> int:
        try:
            result = subprocess.run(
                ["ROPgadget", "--binary", self.binary_path, "--string", pattern],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and line.startswith("0x"):
                    parts = line.split(" : ", 1)
                    if len(parts) == 2:
                        addr = int(parts[0], 16)
                        if pattern.lower() in parts[1].lower():
                            return addr
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass
        return 0
