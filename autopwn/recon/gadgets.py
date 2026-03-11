from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from pwn import log

from autopwn.config import CACHE_DIR

if TYPE_CHECKING:
    from autopwn.context import PwnContext

GADGET_CACHE_DIR: Path = CACHE_DIR / "gadgets"

KEY_GADGET_PATTERNS_64: list[str] = [
    "pop rdi ; ret",
    "pop rsi ; ret",
    "pop rdx ; ret",
    "pop rax ; ret",
    "pop rcx ; ret",
    "pop rdi ; pop rsi ; ret",
    "pop rsi ; pop r15 ; ret",
    "pop rdx ; pop rbx ; ret",
    "pop rdx ; pop r12 ; ret",
    "syscall",
    "syscall ; ret",
    "leave ; ret",
    "ret",
    "jmp rsp",
    "call rsp",
    "mov rdi, rax",
    "xor eax, eax ; ret",
    "pop rbp ; ret",
    "pop rsp ; ret",
]

KEY_GADGET_PATTERNS_32: list[str] = [
    "pop eax ; ret",
    "pop ebx ; ret",
    "pop ecx ; ret",
    "pop edx ; ret",
    "pop esi ; ret",
    "pop edi ; ret",
    "pop ebx ; pop ecx ; pop edx ; ret",
    "int 0x80",
    "leave ; ret",
    "ret",
    "jmp esp",
    "call esp",
    "xor eax, eax ; ret",
    "pop ebp ; ret",
]


def _cache_path(binary_path: str) -> Path:
    """Generate cache file path based on binary hash."""
    data = Path(binary_path).read_bytes()
    h = hashlib.md5(data).hexdigest()
    return GADGET_CACHE_DIR / f"{h}.json"


def _load_cache(binary_path: str) -> dict[str, int] | None:
    path = _cache_path(binary_path)
    if path.exists():
        try:
            data = json.loads(path.read_text())
            log.info(f"gadgets: loaded {len(data)} from cache")
            return data
        except (json.JSONDecodeError, OSError):
            pass
    return None


def _save_cache(binary_path: str, gadgets: dict[str, int]) -> None:
    try:
        GADGET_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_path(binary_path).write_text(json.dumps(gadgets))
    except OSError:
        pass


def _parse_ropgadget_output(output: str) -> dict[str, int]:
    """Parse ROPgadget output into {gadget_string: address}."""
    gadgets: dict[str, int] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("0x"):
            continue
        parts = line.split(" : ", 1)
        if len(parts) != 2:
            continue
        try:
            addr = int(parts[0], 16)
            gadget = parts[1].strip()
            if gadget and addr:
                gadgets[gadget] = addr
        except ValueError:
            continue
    return gadgets


def search_gadgets(ctx: PwnContext) -> None:
    """Search ROP gadgets via ROPgadget, write to ctx.gadgets."""
    if not ctx.binary_path:
        log.warn("gadgets: no binary path")
        return

    # try cache first
    cached = _load_cache(ctx.binary_path)
    if cached is not None:
        ctx.gadgets = cached
        return

    try:
        proc = subprocess.run(
            ["ROPgadget", "--binary", ctx.binary_path],
            capture_output=True, text=True, timeout=60,
        )
        all_gadgets = _parse_ropgadget_output(proc.stdout)
    except FileNotFoundError:
        log.warn("gadgets: ROPgadget not found, skipping")
        return
    except subprocess.TimeoutExpired:
        log.warn("gadgets: ROPgadget timed out")
        return

    # filter to key gadgets
    patterns = KEY_GADGET_PATTERNS_64 if ctx.bits == 64 else KEY_GADGET_PATTERNS_32
    key_gadgets: dict[str, int] = {}

    for pattern in patterns:
        p_lower = pattern.lower().strip()
        # exact match first
        for g, addr in all_gadgets.items():
            if g.lower().strip() == p_lower:
                key_gadgets[g] = addr
                break
        else:
            # fuzzy: gadget contains pattern
            for g, addr in all_gadgets.items():
                if p_lower in g.lower():
                    key_gadgets[g] = addr
                    break

    # Supplement with pwntools ROP for key gadgets that ROPgadget missed
    _supplement_with_pwntools(ctx, key_gadgets, patterns)

    # Search raw byte patterns for critical non-ret-terminated gadgets
    # (ROPgadget only finds gadgets ending with ret/syscall/int, but
    # misses combinations like "pop rax ; syscall" which are vital for SROP)
    _search_raw_gadgets(ctx, key_gadgets)

    ctx.gadgets = key_gadgets
    _save_cache(ctx.binary_path, key_gadgets)
    log.info(f"gadgets: found {len(key_gadgets)} key gadgets (from {len(all_gadgets)} total)")


# Raw byte patterns for gadgets that ROPgadget misses (non-ret terminators).
# These are critical for SROP and other techniques.
_RAW_GADGET_PATTERNS_64: list[tuple[str, bytes]] = [
    ("pop rax ; syscall", b"\x58\x0f\x05"),        # SROP: set rax then syscall
    ("pop rdi ; syscall", b"\x5f\x0f\x05"),
    ("pop rsi ; syscall", b"\x5e\x0f\x05"),
    ("xor rax, rax ; syscall", b"\x48\x31\xc0\x0f\x05"),
]

_RAW_GADGET_PATTERNS_32: list[tuple[str, bytes]] = [
    ("pop eax ; int 0x80", b"\x58\xcd\x80"),
    ("pop ebx ; int 0x80", b"\x5b\xcd\x80"),
    ("xor eax, eax ; int 0x80", b"\x31\xc0\xcd\x80"),
]


def _search_raw_gadgets(ctx: PwnContext, key_gadgets: dict[str, int]) -> None:
    """Search for critical gadgets by raw byte patterns in the ELF."""
    if not ctx.elf:
        return

    patterns = _RAW_GADGET_PATTERNS_64 if ctx.bits == 64 else _RAW_GADGET_PATTERNS_32

    for name, pattern in patterns:
        if name in key_gadgets:
            continue
        try:
            addr = next(ctx.elf.search(pattern, executable=True))
            key_gadgets[name] = addr
            log.debug(f"gadgets: raw search found '{name}' at {addr:#x}")
        except StopIteration:
            continue
        except Exception:
            continue


def _supplement_with_pwntools(ctx: PwnContext, key_gadgets: dict[str, int],
                              patterns: list[str]) -> None:
    """Use pwntools ROP to find key gadgets that ROPgadget missed."""
    if not ctx.elf:
        return

    # Only bother if we're missing some patterns
    found_lower = {g.lower().strip() for g in key_gadgets}
    missing = []
    for p in patterns:
        p_lower = p.lower().strip()
        # Check if already found (exact or as substring)
        if any(p_lower == f or p_lower in f for f in found_lower):
            continue
        missing.append(p)

    if not missing:
        return

    try:
        from pwn import ROP
        rop = ROP(ctx.elf, badchars=b"")

        # Map pattern text to instruction lists for pwntools
        for pattern in missing:
            insns = [i.strip() for i in pattern.split(";")]
            try:
                g = rop.find_gadget(insns)
                if g:
                    key_gadgets[pattern] = g.address
                    log.debug(f"gadgets: pwntools found '{pattern}' at {g.address:#x}")
            except Exception:
                continue
    except Exception as exc:
        log.debug(f"gadgets: pwntools ROP supplement failed: {exc}")


def search_one_gadget(libc_path: str) -> list[int]:
    """Call one_gadget to find magic gadgets in libc."""
    try:
        proc = subprocess.run(
            ["one_gadget", libc_path],
            capture_output=True, text=True, timeout=30,
        )
        addrs = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("0x"):
                try:
                    addrs.append(int(line.split()[0], 16))
                except ValueError:
                    continue
        log.info(f"one_gadget: found {len(addrs)} gadgets")
        return addrs
    except FileNotFoundError:
        log.warn("one_gadget: tool not found")
        return []
    except subprocess.TimeoutExpired:
        log.warn("one_gadget: timed out")
        return []
