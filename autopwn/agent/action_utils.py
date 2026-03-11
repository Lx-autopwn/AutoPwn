"""Shared utilities for rule actions."""
from __future__ import annotations

import sys
import signal
import time
from typing import TYPE_CHECKING

from pwn import process, remote, log, context as pwn_context

from autopwn.config import SHELL_MARKER, SHELL_VERIFY_TIMEOUT

if TYPE_CHECKING:
    from autopwn.context import PwnContext


def open_target(ctx: PwnContext, target: str | None = None, **kwargs):
    """Open a pwntools tube to the target.

    Extra *kwargs* are forwarded to ``process()`` (e.g. ``stdin=PTY``).
    """
    pwn_context.binary = ctx.elf
    if target:
        host, port = target.rsplit(":", 1)
        return remote(host, int(port))
    return process(ctx.binary_path, **kwargs)


def verify_shell(io, retries: int = 2) -> bool:
    """Check if we have a live shell."""
    for attempt in range(retries):
        try:
            try:
                io.recv(timeout=0.3)
            except Exception:
                pass
            if attempt > 0:
                time.sleep(0.5)
            else:
                time.sleep(0.1)
            io.sendline(b"echo " + SHELL_MARKER)
            resp = io.recvuntil(SHELL_MARKER, timeout=SHELL_VERIFY_TIMEOUT)
            if SHELL_MARKER in resp:
                return True
        except Exception:
            pass
    return False


def verify_flag_output(io, timeout: float = 3.0) -> bool:
    """Check if the output contains a flag-like string."""
    try:
        output = io.recv(timeout=timeout)
        text = output.decode("utf-8", errors="replace")
        # Common flag patterns
        if any(p in text.lower() for p in ["flag{", "ctf{", "flag is", "cat /flag",
                                             "congratul", "correct", "success"]):
            return True
    except Exception:
        pass
    return False


def interactive_or_close(io, success: bool) -> bool:
    """On success, enter interactive mode (if tty) or close."""
    if success:
        log.success("Agent: shell obtained!")
        try:
            io.recv(timeout=0.3)
        except Exception:
            pass
        if sys.stdin.isatty():
            try:
                signal.signal(signal.SIGINT, signal.SIG_DFL)
            except Exception:
                pass
            io.interactive()
        else:
            try:
                io.close()
            except Exception:
                pass
        return True
    try:
        io.close()
    except Exception:
        pass
    return False


def safe_close(io) -> None:
    """Close a tube ignoring errors."""
    try:
        io.close()
    except Exception:
        pass
