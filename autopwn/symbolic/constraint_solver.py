from __future__ import annotations

from typing import Any

from pwn import log


def solve_payload_constraints(payload_size: int, constraints: list[dict],
                               bad_bytes: bytes = b"") -> bytes | None:
    """用z3求解满足所有约束的payload。

    constraints格式:
    [{"offset": 0, "value": 0x41, "size": 1},           # 固定字节
     {"offset": 8, "value": 0xdeadbeef, "size": 8},     # 固定值
     {"offset": 16, "range": (0x20, 0x7e), "size": 1},  # 范围约束
     {"offset": 24, "not_in": [0x00, 0x0a], "size": 1}] # 排除字节
    """
    try:
        import z3
    except ImportError:
        log.warning("z3未安装")
        return None

    solver = z3.Solver()
    payload_vars = [z3.BitVec(f"b{i}", 8) for i in range(payload_size)]

    # 坏字节约束
    for i, var in enumerate(payload_vars):
        for bad in bad_bytes:
            solver.add(var != bad)

    # 用户约束
    for c in constraints:
        offset = c.get("offset", 0)
        size = c.get("size", 1)

        if "value" in c:
            value = c["value"]
            if size == 1:
                if offset < payload_size:
                    solver.add(payload_vars[offset] == (value & 0xff))
            else:
                for j in range(min(size, 8)):
                    idx = offset + j
                    if idx < payload_size:
                        byte_val = (value >> (j * 8)) & 0xff
                        solver.add(payload_vars[idx] == byte_val)

        if "range" in c:
            lo, hi = c["range"]
            if offset < payload_size:
                solver.add(payload_vars[offset] >= lo)
                solver.add(payload_vars[offset] <= hi)

        if "not_in" in c:
            for bad_val in c["not_in"]:
                if offset < payload_size:
                    solver.add(payload_vars[offset] != bad_val)

    if solver.check() == z3.sat:
        model = solver.model()
        result = bytearray(payload_size)
        for i, var in enumerate(payload_vars):
            val = model.eval(var)
            if val is not None:
                try:
                    result[i] = val.as_long()
                except Exception:
                    result[i] = 0x41
            else:
                result[i] = 0x41

        return bytes(result)

    log.warning("约束不可满足")
    return None


def check_address_constraints(addr: int, bad_bytes: bytes = b"") -> bool:
    """检查地址是否包含坏字节。"""
    addr_bytes = addr.to_bytes(8, "little")
    for b in bad_bytes:
        if b in addr_bytes:
            return False
    return True


def find_alternative_address(base_addr: int, search_range: int = 0x1000,
                              bad_bytes: bytes = b"\x00\x0a") -> int | None:
    """找到附近不包含坏字节的地址。"""
    for offset in range(0, search_range):
        candidate = base_addr + offset
        if check_address_constraints(candidate, bad_bytes):
            return candidate
        if offset > 0:
            candidate = base_addr - offset
            if candidate > 0 and check_address_constraints(candidate, bad_bytes):
                return candidate
    return None
