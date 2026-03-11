from __future__ import annotations

import time
from typing import TYPE_CHECKING

from pwn import context as pwn_context
from pwn import log, process, remote

from autopwn.config import RECV_TIMEOUT, SHELL_MARKER, SHELL_VERIFY_TIMEOUT

if TYPE_CHECKING:
    from pwn import tube as _Tube

    from autopwn.context import PwnContext


class SmartTube:
    """Unified connection manager wrapping process/remote."""

    def __init__(
        self,
        binary_path: str,
        remote_addr: str | None = None,
        ctx: PwnContext | None = None,
        env: dict[str, str] | None = None,
        timeout: float = RECV_TIMEOUT,
    ) -> None:
        self.binary_path = binary_path
        self.remote_addr = remote_addr
        self.ctx = ctx
        self.env = env
        self.timeout = timeout
        self._tube: _Tube | None = None
        self._connect()

    # ------------------------------------------------------------------
    # connection management
    # ------------------------------------------------------------------

    def _connect(self) -> None:
        """Create the underlying tube (process or remote)."""
        if self.remote_addr:
            host, port = self._parse_remote(self.remote_addr)
            log.info(f"Connecting to {host}:{port}")
            self._tube = remote(host, int(port), timeout=self.timeout)
        else:
            log.info(f"Spawning local process: {self.binary_path}")
            self._tube = process(self.binary_path, env=self.env, timeout=self.timeout)

    @staticmethod
    def _parse_remote(addr: str) -> tuple[str, str]:
        """Parse 'host:port' string."""
        if ":" not in addr:
            raise ValueError(f"Invalid remote format (expect host:port): {addr}")
        parts = addr.rsplit(":", 1)
        return parts[0], parts[1]

    def reconnect(self) -> None:
        """Close current connection and create a new one (for multi-stage exploits)."""
        self.close()
        time.sleep(0.3)
        self._connect()

    def close(self) -> None:
        if self._tube:
            try:
                self._tube.close()
            except Exception:
                pass
            self._tube = None

    @property
    def tube(self) -> _Tube:
        if self._tube is None:
            raise RuntimeError("Tube is closed")
        return self._tube

    # ------------------------------------------------------------------
    # send helpers
    # ------------------------------------------------------------------

    def send_payload(self, payload: bytes, newline: bool = False) -> None:
        """Send payload, choosing send/sendline based on *newline* flag.

        For ``read()``-based inputs use ``newline=False`` (raw send).
        For ``gets()``/``scanf()``-based inputs use ``newline=True``.
        """
        if newline:
            self.tube.sendline(payload)
        else:
            self.tube.send(payload)

    def sendline(self, data: bytes) -> None:
        self.tube.sendline(data)

    def send(self, data: bytes) -> None:
        self.tube.send(data)

    def sendafter(self, delim: bytes, data: bytes, timeout: float | None = None) -> None:
        self.tube.sendafter(delim, data, timeout=timeout or self.timeout)

    def sendlineafter(self, delim: bytes, data: bytes, timeout: float | None = None) -> None:
        self.tube.sendlineafter(delim, data, timeout=timeout or self.timeout)

    # ------------------------------------------------------------------
    # recv helpers
    # ------------------------------------------------------------------

    def recv(self, numb: int = 4096, timeout: float | None = None) -> bytes:
        return self.tube.recv(numb, timeout=timeout or self.timeout)

    def recvline(self, timeout: float | None = None) -> bytes:
        return self.tube.recvline(timeout=timeout or self.timeout)

    def recvuntil(self, delim: bytes, drop: bool = True, timeout: float | None = None) -> bytes:
        return self.tube.recvuntil(delim, drop=drop, timeout=timeout or self.timeout)

    def recv_until_prompt(self, prompt: bytes = b"", timeout: float | None = None) -> bytes:
        """Receive until *prompt* appears, or just drain available data."""
        t = timeout or self.timeout
        if prompt:
            return self.tube.recvuntil(prompt, drop=True, timeout=t)
        # no prompt: just drain whatever is available
        try:
            return self.tube.recv(timeout=t)
        except Exception:
            return b""

    def recv_leak(self, length: int = 6, timeout: float | None = None) -> int:
        """Receive raw leaked bytes and unpack as a little-endian address.

        Handles short reads (null-truncated puts output) by right-padding with
        zero bytes.
        """
        bits = 64
        if self.ctx:
            bits = self.ctx.bits
        addr_len = bits // 8

        t = timeout or self.timeout
        try:
            raw = self.tube.recv(length, timeout=t)
        except Exception:
            raw = b""
        if not raw:
            return 0

        # pad to full address width
        raw = raw.ljust(addr_len, b"\x00")
        endian = "little"
        if self.ctx and self.ctx.endian == "big":
            endian = "big"
        return int.from_bytes(raw[:addr_len], endian)

    # ------------------------------------------------------------------
    # menu helpers
    # ------------------------------------------------------------------

    def menu_select(self, choice: int | str, prompt: bytes = b"") -> None:
        """Wait for menu prompt then send choice."""
        if prompt:
            self.tube.recvuntil(prompt, timeout=self.timeout)
        self.tube.sendline(str(choice).encode())

    # ------------------------------------------------------------------
    # shell verification
    # ------------------------------------------------------------------

    def verify_shell(self, timeout: float = SHELL_VERIFY_TIMEOUT) -> bool:
        """Send ``echo P_W_N_E_D`` and check for marker in response."""
        try:
            time.sleep(0.2)
            self.tube.sendline(b"echo " + SHELL_MARKER)
            resp = self.tube.recv(timeout=timeout)
            if SHELL_MARKER in resp:
                log.success("Shell verified!")
                return True
            # try once more (sometimes the first echo is eaten by the binary)
            self.tube.sendline(b"echo " + SHELL_MARKER)
            resp = self.tube.recv(timeout=timeout)
            return SHELL_MARKER in resp
        except Exception:
            return False

    # ------------------------------------------------------------------
    # interactive
    # ------------------------------------------------------------------

    def interactive(self) -> None:
        """Drop into interactive mode."""
        log.success("Entering interactive mode")
        self.tube.interactive()

    # ------------------------------------------------------------------
    # context-manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> SmartTube:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
