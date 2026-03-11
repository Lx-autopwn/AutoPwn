from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from pwn import cyclic, cyclic_find, log

from autopwn.config import GDB_TIMEOUT, MAX_PATTERN_LEN

if TYPE_CHECKING:
    from autopwn.context import PwnContext


def find_overflow_offset(ctx: PwnContext) -> int:
    """用GDB自动探测栈溢出偏移。返回偏移(>=0)或-1（未找到）。"""
    offset = _gdb_pattern_method(ctx)
    if offset >= 0:
        offset = _validate_offset_with_r2(ctx, offset)
        log.success(f"溢出偏移: {offset}")
        ctx.overflow_offset = offset
        return offset

    offset = _coredump_method(ctx)
    if offset >= 0:
        offset = _validate_offset_with_r2(ctx, offset)
        log.success(f"溢出偏移 (coredump): {offset}")
        ctx.overflow_offset = offset
        return offset

    # Fallback: try prefixed patterns for binaries that read formatted
    # input (e.g. scanf) before the vulnerable read()
    offset = _prefixed_pattern_method(ctx)
    if offset >= 0:
        log.success(f"溢出偏移 (prefixed): {offset}")
        ctx.overflow_offset = offset
        return offset

    # Last resort: static analysis of disassembly
    offset = _static_offset_from_disasm(ctx)
    if offset >= 0:
        log.success(f"溢出偏移 (static): {offset}")
        ctx.overflow_offset = offset
        # If plain GDB method failed but static found an offset, the binary
        # likely needs formatted pre-input (e.g. scanf before read).
        # Try to discover the correct prefix.
        _detect_overflow_prefix(ctx, offset)
        return offset

    log.warning("未能自动检测溢出偏移")
    return -1


def _validate_offset_with_r2(ctx: PwnContext, offset: int) -> int:
    """Cross-validate GDB offset against r2 analysis.

    For loop binaries, the GDB cyclic pattern may span multiple iterations,
    producing an inflated offset.  If r2_profile knows the read size and
    buffer stack offset, we can detect and correct this:

    - If offset > read_size, the real offset is offset % read_size
      (each loop iteration re-reads into the same buffer)
    - If r2 buf_stack_offset gives a static offset, prefer it when the
      dynamic offset seems unreasonable
    """
    r2p = getattr(ctx, "r2_profile", None)
    if not r2p:
        return offset

    read_size = r2p.input_max_size
    word = ctx.bits // 8

    # If the detected offset exceeds the single-read size, the pattern
    # was consumed across multiple loop iterations.
    if read_size > 0 and offset >= read_size:
        corrected = offset % read_size
        if corrected > 0:
            log.info(f"Offset {offset} > read_size {read_size} (loop?), "
                     f"corrected to {corrected}")
            return corrected

    # Sanity check: if r2 found a buffer offset, the dynamic offset should
    # be close to buf_stack_offset + word_size.
    if r2p.buf_stack_offset > 0:
        expected = r2p.buf_stack_offset + word
        if offset > 0 and abs(offset - expected) > 32:
            log.debug(f"Offset {offset} differs from r2 expected {expected}, "
                      f"keeping dynamic result")

    return offset


def _gdb_pattern_method(ctx: PwnContext) -> int:
    """GDB批处理方法：写pattern到文件，GDB读取并检查崩溃寄存器。

    Strategy:
    1. Try cyclic_find on EIP/RIP register directly (works when ret
       completes and jumps to pattern address — always on 32-bit, and
       on 64-bit when the pattern is a canonical address).
    2. Fall back to the value at ESP/RSP (works on 64-bit when the
       pattern is a non-canonical address — ret faults before
       completing so RSP still points to the return address).

    For loop binaries, limits pattern length to the input read size
    (from r2_profile) so only one iteration gets pattern data.
    """
    n = ctx.bits // 8

    # For loop/multi-read binaries, limit pattern to one read's worth
    # so the cyclic offset is not shifted by prior iterations consuming data.
    pat_len = MAX_PATTERN_LEN
    r2p = getattr(ctx, "r2_profile", None)
    if r2p and r2p.input_max_size > 0 and r2p.input_max_size < pat_len:
        pat_len = r2p.input_max_size

    pattern = cyclic(pat_len, n=n)

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as pf:
        pf.write(pattern)
        pattern_file = pf.name

    ip_reg = "rip" if ctx.bits == 64 else "eip"
    sp_reg = "rsp" if ctx.bits == 64 else "esp"
    ptr_fmt = "gx" if ctx.bits == 64 else "wx"
    gdb_script = f"""
set pagination off
set confirm off
set disable-randomization on
run < {pattern_file}
if $_siginfo
  info registers {ip_reg} {sp_reg}
  x/{ptr_fmt} ${sp_reg}
end
quit
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as sf:
        sf.write(gdb_script)
        script_file = sf.name

    try:
        result = subprocess.run(
            ["gdb", "-batch", "-nx", "-x", script_file, ctx.binary_path],
            capture_output=True, timeout=GDB_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
        output = (result.stdout + result.stderr).decode("utf-8", errors="replace")

        ip_val = 0
        sp_mem_val = 0

        for line in output.splitlines():
            line = line.strip()
            # Parse "info registers" output: "eip  0x61616174  0x61616174"
            if line.startswith(ip_reg):
                parts = line.split()
                for part in parts[1:]:
                    if part.startswith("0x"):
                        try:
                            ip_val = int(part, 16)
                        except ValueError:
                            pass
                        break
            # Parse "x/..." output: "0xffffcc20:  0x61616175"
            elif line.startswith("0x") and ":" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    val_str = parts[1].strip()
                    if val_str.startswith("0x"):
                        try:
                            sp_mem_val = int(val_str, 16)
                        except ValueError:
                            pass

        # Strategy 1: EIP/RIP is a pattern value (ret completed)
        if ip_val:
            try:
                offset = cyclic_find(ip_val, n=n)
                if 0 <= offset < MAX_PATTERN_LEN:
                    return offset
            except (ValueError, AssertionError):
                pass

        # Strategy 2: value at ESP/RSP (ret faulted, RSP unchanged)
        if sp_mem_val:
            try:
                offset = cyclic_find(sp_mem_val, n=n)
                if 0 <= offset < MAX_PATTERN_LEN:
                    return offset
            except (ValueError, AssertionError):
                pass

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    finally:
        Path(pattern_file).unlink(missing_ok=True)
        Path(script_file).unlink(missing_ok=True)

    return -1


def _coredump_method(ctx: PwnContext) -> int:
    """Core dump方法：发送pattern，从core文件提取RSP/EIP值。"""
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))

    pattern = cyclic(MAX_PATTERN_LEN, n=ctx.bits // 8)

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as pf:
        pf.write(pattern)
        pattern_file = pf.name

    core_pattern = "/tmp/autopwn_core"
    try:
        # Try to set core pattern WITHOUT sudo to avoid blocking on password prompt.
        # Use direct write first; fall back to tee without sudo.
        core_pattern_path = Path("/proc/sys/kernel/core_pattern")
        try:
            core_pattern_path.write_text(core_pattern + "\n")
        except PermissionError:
            # Not root — try without sudo; if it fails, just skip coredump method.
            log.debug("Cannot set core_pattern (no root), skipping coredump method")
            Path(pattern_file).unlink(missing_ok=True)
            return -1
    except Exception:
        pass

    try:
        with open(pattern_file, "rb") as stdin_f:
            subprocess.run(
                [ctx.binary_path],
                stdin=stdin_f,
                capture_output=True,
                timeout=GDB_TIMEOUT,
            )
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        pass

    core_file = Path(core_pattern)
    if not core_file.exists():
        for p in Path("/tmp").glob("autopwn_core*"):
            core_file = p
            break

    if core_file.exists():
        try:
            result = subprocess.run(
                ["gdb", "-batch", "-nx", "-ex", "info registers", ctx.binary_path, str(core_file)],
                capture_output=True, timeout=GDB_TIMEOUT,
            )
            reg = "rsp" if ctx.bits == 64 else "esp"
            stdout_text = result.stdout.decode("utf-8", errors="replace")
            for line in stdout_text.splitlines():
                if line.strip().startswith(reg):
                    parts = line.split()
                    for part in parts:
                        if part.startswith("0x"):
                            try:
                                val = int(part, 16)
                                offset = cyclic_find(val, n=ctx.bits // 8)
                                if 0 < offset < MAX_PATTERN_LEN:
                                    return offset
                            except (ValueError, AssertionError):
                                pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        finally:
            core_file.unlink(missing_ok=True)

    Path(pattern_file).unlink(missing_ok=True)
    return -1


def _prefixed_pattern_method(ctx: PwnContext) -> int:
    """Handle binaries that read formatted input (scanf) before the overflow.

    Tries common prefixes like "-1\\n", "9999\\n" etc. before the cyclic
    pattern.  This handles the common CTF pattern:
        scanf("%d", &n);
        if (n <= LIMIT) { read(0, buf, n); }
    where a negative or large value bypasses the check.
    """
    n = ctx.bits // 8
    pattern = cyclic(MAX_PATTERN_LEN, n=n)

    # Common bypass values: negative (signed bypass), large, zero
    prefixes = [
        b"-1\n",       # signed bypass: -1 <= any_limit, read count = 0xFFFFFFFF
        b"9999\n",     # large value
        b"999999\n",   # very large
        b"256\n",      # common buffer size
        b"1024\n",     # larger buffer
        b"-1\n-1\n",   # double scanf bypass
        b"1\n-1\n",    # first choice then bypass
        b"2\n-1\n",    # menu choice then bypass
    ]

    ip_reg = "rip" if ctx.bits == 64 else "eip"
    sp_reg = "rsp" if ctx.bits == 64 else "esp"
    ptr_fmt = "gx" if ctx.bits == 64 else "wx"

    for prefix in prefixes:
        data = prefix + pattern

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as pf:
            pf.write(data)
            pattern_file = pf.name

        gdb_script = f"""
set pagination off
set confirm off
set disable-randomization on
run < {pattern_file}
if $_siginfo
  info registers {ip_reg} {sp_reg}
  x/{ptr_fmt} ${sp_reg}
end
quit
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as sf:
            sf.write(gdb_script)
            script_file = sf.name

        try:
            result = subprocess.run(
                ["gdb", "-batch", "-nx", "-x", script_file, ctx.binary_path],
                capture_output=True, timeout=GDB_TIMEOUT,
                stdin=subprocess.DEVNULL,
            )
            output = (result.stdout + result.stderr).decode("utf-8", errors="replace")

            ip_val = 0
            sp_mem_val = 0

            for line in output.splitlines():
                line = line.strip()
                if line.startswith(ip_reg):
                    parts = line.split()
                    for part in parts[1:]:
                        if part.startswith("0x"):
                            try:
                                ip_val = int(part, 16)
                            except ValueError:
                                pass
                            break
                elif line.startswith("0x") and ":" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        val_str = parts[1].strip()
                        if val_str.startswith("0x"):
                            try:
                                sp_mem_val = int(val_str, 16)
                            except ValueError:
                                pass

            # Check IP register
            if ip_val:
                try:
                    offset = cyclic_find(ip_val, n=n)
                    if 0 <= offset < MAX_PATTERN_LEN:
                        log.info(f"Prefixed method: prefix={prefix!r} worked (IP)")
                        ctx.overflow_prefix = prefix
                        return offset
                except (ValueError, AssertionError):
                    pass

            # Check SP memory
            if sp_mem_val:
                try:
                    offset = cyclic_find(sp_mem_val, n=n)
                    if 0 <= offset < MAX_PATTERN_LEN:
                        log.info(f"Prefixed method: prefix={prefix!r} worked (SP)")
                        ctx.overflow_prefix = prefix
                        return offset
                except (ValueError, AssertionError):
                    pass

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        finally:
            Path(pattern_file).unlink(missing_ok=True)
            Path(script_file).unlink(missing_ok=True)

    return -1


def _detect_overflow_prefix(ctx: PwnContext, offset: int) -> None:
    """Detect if the binary needs a prefix before the overflow payload.

    Uses pipe-based interaction (not file redirection) to handle the
    common case where scanf() and read() share stdin.  With file
    redirection, stdio buffering causes scanf to consume the entire file,
    leaving read() with EOF.  With pipes, data arrives incrementally.

    Tries common bypass values (negative numbers, large numbers) as prefix
    input.  Verifies by sending prefix, waiting, then sending overflow
    payload and checking if the binary crashes (non-zero exit).
    """
    try:
        _detect_overflow_prefix_impl(ctx, offset)
    except Exception as exc:
        log.debug(f"_detect_overflow_prefix failed: {exc}")


def _detect_overflow_prefix_impl(ctx: PwnContext, offset: int) -> None:
    import time

    word_size = ctx.bits // 8
    marker = b"\x42" * word_size  # non-canonical address to cause crash

    prefixes = [
        b"-1\n",
        b"999\n",
        b"9999\n",
        b"256\n",
        b"1024\n",
        b"-1\n-1\n",
        b"1\n-1\n",
        b"2\n-1\n",
        b"1\n",
    ]

    # First: check if the binary crashes WITHOUT any prefix (simple overflow)
    # If it does, no prefix needed
    try:
        p = subprocess.Popen(
            [ctx.binary_path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        payload = b"A" * offset + marker
        p.stdin.write(payload)
        p.stdin.flush()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
        if p.returncode and p.returncode < 0:
            # Crashed without prefix — no prefix needed
            log.debug("Binary crashes without prefix (direct overflow)")
            return
    except Exception:
        pass

    # Try each prefix
    for prefix in prefixes:
        try:
            p = subprocess.Popen(
                [ctx.binary_path],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # Send prefix (e.g. "-1\n" for scanf)
            p.stdin.write(prefix)
            p.stdin.flush()
            time.sleep(0.2)

            # Send overflow payload
            payload = b"A" * offset + marker
            p.stdin.write(payload)
            p.stdin.flush()

            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()

            if p.returncode and p.returncode < 0:
                # Process crashed — this prefix works
                ctx.overflow_prefix = prefix
                log.info(f"Overflow prefix detected: {prefix!r}")
                return
        except Exception:
            pass


def _static_offset_from_disasm(ctx: PwnContext) -> int:
    """Statically determine overflow offset from disassembly.

    For non-canary binaries, finds the buffer offset from:
        lea -0xNN(%rbp), %reg  (before a read/gets call)
    Then overflow_offset = NN + ptr_size (to reach past saved_rbp to saved_rip).
    """
    import re

    try:
        result = subprocess.run(
            ["objdump", "-d", ctx.binary_path],
            capture_output=True, timeout=10,
        )
        output = result.stdout.decode("utf-8", errors="replace")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1

    word_size = ctx.bits // 8

    # Collect all (func_name, offset) candidates
    candidates: list[tuple[str, int]] = []
    current_name = ""
    current_lines: list[str] = []

    for line in output.splitlines():
        m = re.match(r"[0-9a-f]+ <([^>]+)>:", line)
        if m:
            if current_name and current_lines:
                off = _extract_buf_offset(current_lines, word_size)
                if off > 0:
                    candidates.append((current_name, off))
                    log.debug(f"Static offset: func {current_name} → {off}")
            current_name = m.group(1)
            current_lines = []
            continue
        current_lines.append(line)

    # Process last function
    if current_name and current_lines:
        off = _extract_buf_offset(current_lines, word_size)
        if off > 0:
            candidates.append((current_name, off))

    if not candidates:
        return -1

    # Prefer non-main vulnerable functions (the actual vuln is usually not in main)
    non_main = [(n, o) for n, o in candidates if n != "main"]
    if non_main:
        # Pick the largest offset among non-main functions
        return max(non_main, key=lambda x: x[1])[1]

    # Fallback: largest offset from any function
    return max(candidates, key=lambda x: x[1])[1]


def _extract_buf_offset(func_lines: list[str], word_size: int) -> int:
    """Extract buffer-to-return-address offset from function disassembly."""
    import re

    has_dangerous_call = False
    buffer_offsets = []

    for i, line in enumerate(func_lines):
        # Detect lea -0xNN(%rbp) before a read/gets/fgets call
        m = re.search(r"lea\s+-0x([0-9a-f]+)\(%[re]bp\)", line)
        if m:
            buf_off = int(m.group(1), 16)
            # Check if next few lines have a dangerous call
            for j in range(i, min(i + 8, len(func_lines))):
                if "call" in func_lines[j] and any(
                    f in func_lines[j] for f in
                    ["read", "gets", "fgets", "recv", "strcpy", "scanf"]
                ):
                    buffer_offsets.append(buf_off)
                    has_dangerous_call = True
                    break

    if not has_dangerous_call or not buffer_offsets:
        return -1

    # Use the largest buffer offset (furthest from rbp)
    buf_to_rbp = max(buffer_offsets)
    # overflow_offset = distance from buf to saved_rip
    # buf at rbp-N, saved_rbp at rbp+0, saved_rip at rbp+word_size
    return buf_to_rbp + word_size


def find_canary_offset(ctx: PwnContext) -> int:
    """Detect canary and return-address offsets from buffer start.

    Uses disassembly analysis to find:
    - The buffer start position (``lea -0xNN(%rbp), ...`` before a large ``read``/``gets``)
    - The canary position (``mov %rax, -0x8(%rbp)`` from ``fs:0x28``)

    Then: canary_offset = buffer_to_rbp - 8, overflow_offset = buffer_to_rbp + word_size.

    Falls back to GDB breakpoint at ``__stack_chk_fail`` if disassembly fails.

    Sets ctx.canary_offset, ctx.overflow_offset.
    Returns canary_offset or 0 on failure.
    """
    import re

    if not ctx.canary:
        return 0
    if ctx.canary_offset > 0:
        return ctx.canary_offset

    word_size = ctx.bits // 8

    # --- Method 1: Disassembly analysis ---
    offset = _canary_offset_from_disasm(ctx, word_size)
    if offset > 0:
        return offset

    # --- Method 2: GDB breakpoint at __stack_chk_fail ---
    offset = _canary_offset_from_gdb(ctx, word_size)
    if offset > 0:
        return offset

    log.warning("未能检测canary偏移")
    return 0


def _canary_offset_from_disasm(ctx: PwnContext, word_size: int) -> int:
    """Detect canary offset by analyzing disassembly of vulnerable functions.

    Looks for the pattern:
      mov %rax, fs:0x28      → canary load
      mov %rax, -0x8(%rbp)   → canary stored at rbp-8
      lea -0xNN(%rbp), ...   → buffer at rbp-NN (before a large read/gets call)

    canary_offset = NN - 8
    overflow_offset = NN + word_size
    """
    import re

    try:
        result = subprocess.run(
            ["objdump", "-d", ctx.binary_path],
            capture_output=True, timeout=10,
        )
        output = result.stdout.decode("utf-8", errors="replace")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return 0

    # Find functions that have __stack_chk_fail (canary-protected)
    # and dangerous input calls
    functions = _find_canary_functions(output)

    # Collect all candidates across all functions and pick the best one
    # (largest buffer = most likely the actual overflow target)
    best_canary_off = 0
    best_buf_to_rbp = 0
    best_canary_at = 0

    for func_name, func_lines in functions:
        # Parse buffer offset from lea instructions before read/gets calls
        buffer_offsets = []
        canary_at_rbp_minus = 0

        for i, line in enumerate(func_lines):
            # Detect canary store: mov %rax,-0x8(%rbp)
            if "fs:0x28" in line or "fs:40" in line:
                # Next line should be: mov %rax,-0xN(%rbp)
                for j in range(i + 1, min(i + 3, len(func_lines))):
                    m = re.search(r"mov\s+%[re]ax,-0x([0-9a-f]+)\(%[re]bp\)", func_lines[j])
                    if m:
                        canary_at_rbp_minus = int(m.group(1), 16)
                        break

            # Detect buffer address: lea -0xNN(%rbp),%rax/rdi/rsi before read/gets
            m = re.search(r"lea\s+-0x([0-9a-f]+)\(%[re]bp\)", line)
            if m:
                buf_off = int(m.group(1), 16)
                # Check if next few lines have a dangerous call
                for j in range(i, min(i + 6, len(func_lines))):
                    if "call" in func_lines[j] and any(
                        f in func_lines[j] for f in
                        ["read", "gets", "fgets", "scanf", "recv"]
                    ):
                        buffer_offsets.append(buf_off)
                        break

        if not canary_at_rbp_minus or not buffer_offsets:
            continue

        # Use the largest buffer offset (the one that's furthest from rbp,
        # most likely the overflow target)
        buf_to_rbp = max(buffer_offsets)
        canary_off = buf_to_rbp - canary_at_rbp_minus

        if canary_off > best_canary_off:
            best_canary_off = canary_off
            best_buf_to_rbp = buf_to_rbp
            best_canary_at = canary_at_rbp_minus

    if best_canary_off > 0:
        ctx.canary_offset = best_canary_off
        computed_overflow = best_buf_to_rbp + word_size
        if ctx.overflow_offset < 0:
            ctx.overflow_offset = computed_overflow
        log.success(
            f"Canary偏移 (反汇编): {best_canary_off}, "
            f"溢出偏移: {ctx.overflow_offset} "
            f"(buf@rbp-0x{best_buf_to_rbp:x}, canary@rbp-0x{best_canary_at:x})"
        )
        return best_canary_off

    return 0


def _find_canary_functions(disasm: str) -> list[tuple[str, list[str]]]:
    """Find functions that have both canary check and dangerous input calls."""
    import re
    functions = []
    current_name = ""
    current_lines: list[str] = []
    has_chk_fail = False
    has_input = False

    for line in disasm.splitlines():
        # New function
        m = re.match(r"[0-9a-f]+ <([^>]+)>:", line)
        if m:
            if current_name and has_chk_fail and has_input:
                functions.append((current_name, current_lines))
            current_name = m.group(1)
            current_lines = []
            has_chk_fail = False
            has_input = False
            continue

        current_lines.append(line)
        if "__stack_chk_fail" in line:
            has_chk_fail = True
        if "call" in line and any(
            f in line for f in ["read", "gets", "fgets", "scanf", "recv"]
        ):
            has_input = True

    if current_name and has_chk_fail and has_input:
        functions.append((current_name, current_lines))

    return functions


def _canary_offset_from_gdb(ctx: PwnContext, word_size: int) -> int:
    """Fallback: use GDB breakpoint at __stack_chk_fail to detect canary offset.

    Sends cyclic pattern and finds where the canary was overwritten.

    NOTE: This may report incorrect offsets when the binary has multiple
    reads (the pattern gets split across them).  Prefer disassembly method.
    """
    pattern = cyclic(MAX_PATTERN_LEN, n=word_size)

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as pf:
        pf.write(pattern)
        pattern_file = pf.name

    rbp_reg = "rbp" if ctx.bits == 64 else "ebp"
    ptr_size = "gx" if ctx.bits == 64 else "wx"
    gdb_script = f"""
set pagination off
set confirm off
set disable-randomization on
break __stack_chk_fail
run < {pattern_file}
frame 1
x/{ptr_size} ${rbp_reg}-{word_size}
quit
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as sf:
        sf.write(gdb_script)
        script_file = sf.name

    canary_offset = 0
    try:
        result = subprocess.run(
            ["gdb", "-batch", "-nx", "-x", script_file, ctx.binary_path],
            capture_output=True, timeout=GDB_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
        output = (result.stdout + result.stderr).decode("utf-8", errors="replace")

        for line in output.splitlines():
            line = line.strip()
            if line.startswith("0x") and ":" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    val_str = parts[1].strip()
                    if val_str.startswith("0x"):
                        try:
                            val = int(val_str, 16)
                            offset = cyclic_find(val, n=word_size)
                            if 0 < offset < MAX_PATTERN_LEN:
                                canary_offset = offset
                                break
                        except (ValueError, AssertionError):
                            pass
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    finally:
        Path(pattern_file).unlink(missing_ok=True)
        Path(script_file).unlink(missing_ok=True)

    if canary_offset > 0:
        ctx.canary_offset = canary_offset
        ctx.overflow_offset = canary_offset + 2 * word_size
        log.success(
            f"Canary偏移 (GDB): {canary_offset}, "
            f"溢出偏移: {ctx.overflow_offset}"
        )
    return canary_offset


def verify_offset(ctx: PwnContext, offset: int) -> bool:
    """用GDB验证偏移是否正确。"""
    word_size = ctx.bits // 8
    payload = b"A" * offset + b"B" * word_size

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as pf:
        pf.write(payload)
        pattern_file = pf.name

    ip_reg = "rip" if ctx.bits == 64 else "eip"
    expected = int.from_bytes(b"B" * word_size, "little")

    gdb_script = f"""
set pagination off
set confirm off
run < {pattern_file}
if $_siginfo
  info registers {ip_reg}
end
quit
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as sf:
        sf.write(gdb_script)
        script_file = sf.name

    try:
        result = subprocess.run(
            ["gdb", "-batch", "-nx", "-x", script_file, ctx.binary_path],
            capture_output=True, timeout=GDB_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
        output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
        expected_hex = hex(expected)[2:]
        for line in output.splitlines():
            if line.strip().startswith(ip_reg):
                if expected_hex in line.lower():
                    return True
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    finally:
        Path(pattern_file).unlink(missing_ok=True)
        Path(script_file).unlink(missing_ok=True)
