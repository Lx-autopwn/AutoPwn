from __future__ import annotations

from typing import TYPE_CHECKING

from pwn import log, process

from autopwn.config import RECV_TIMEOUT

if TYPE_CHECKING:
    from autopwn.context import PwnContext


def probe_bad_bytes(ctx: PwnContext) -> bytes:
    """探测程序不接受的坏字节。

    逐个测试 0x00-0xff，看哪些字节会导致输入截断。
    """
    bad = bytearray()

    for byte_val in [0x00, 0x0a, 0x0d, 0x20, 0x09, 0x0b, 0x0c]:
        if _is_bad_byte(ctx, byte_val):
            bad.append(byte_val)

    if bad:
        ctx.bad_bytes = bytes(bad)
        log.info(f"坏字节: {ctx.bad_bytes.hex()}")

    return bytes(bad)


def _is_bad_byte(ctx: PwnContext, byte_val: int) -> bool:
    """测试某个字节是否为坏字节。"""
    test_payload = b"A" * 16 + bytes([byte_val]) + b"B" * 16

    try:
        p = process(ctx.binary_path, level="error")
        p.recv(timeout=0.5)
        p.send(test_payload)
        try:
            resp = p.recv(timeout=1)
        except Exception:
            resp = b""
        p.close()
    except Exception:
        return False

    verify_payload = b"A" * 16 + b"C" + b"B" * 16
    try:
        p2 = process(ctx.binary_path, level="error")
        p2.recv(timeout=0.5)
        p2.send(verify_payload)
        try:
            resp2 = p2.recv(timeout=1)
        except Exception:
            resp2 = b""
        p2.close()
    except Exception:
        return False

    if len(resp) < len(resp2) * 0.5:
        return True

    return False


def probe_input_length(ctx: PwnContext) -> int:
    """探测最大输入长度。"""
    lengths = [0x100, 0x200, 0x400, 0x800, 0x1000]

    max_accepted = 0
    for length in lengths:
        try:
            p = process(ctx.binary_path, level="error")
            p.recv(timeout=0.5)
            p.send(b"A" * length)
            try:
                p.recv(timeout=1)
                max_accepted = length
            except Exception:
                pass
            p.close()
        except Exception:
            break

    if max_accepted:
        ctx.input_max_len = max_accepted
        log.info(f"最大输入长度: >= {max_accepted}")

    return max_accepted


def probe_forking(ctx: PwnContext) -> bool:
    """检测程序是否fork子进程处理请求。"""
    import subprocess

    try:
        result = subprocess.run(
            ["objdump", "-d", ctx.binary_path],
            capture_output=True, text=True, timeout=10,
        )
        if "fork" in result.stdout and ("accept" in result.stdout or "listen" in result.stdout):
            ctx.is_forking = True
            log.info("检测到forking server")
            return True

        if "<fork" in result.stdout:
            ctx.is_forking = True
            return True

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return False
