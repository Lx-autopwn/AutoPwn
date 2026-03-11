from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pwn import log

if TYPE_CHECKING:
    from autopwn.context import PwnContext


@dataclass
class StructField:
    offset: int = 0
    size: int = 0
    name: str = ""
    field_type: str = ""  # int / pointer / buffer / char


@dataclass
class RecoveredStruct:
    name: str = ""
    size: int = 0
    fields: list[StructField] = field(default_factory=list)
    alloc_site: int = 0
    alloc_size: int = 0


def recover_heap_structs(ctx: PwnContext) -> list[RecoveredStruct]:
    """从反编译结果恢复堆对象的结构布局。

    分析malloc分配后的写入模式来推断结构体字段。
    """
    structs = []

    try:
        import angr
    except ImportError:
        return structs

    if not ctx.decompiled:
        return structs

    try:
        proj = angr.Project(ctx.binary_path, auto_load_libs=False)
        cfg = ctx.cfg or proj.analyses.CFGFast()

        for func_name, dec in ctx.decompiled.items():
            for call in dec.calls:
                if call.target in ("malloc", "calloc"):
                    struct = _recover_from_alloc_site(proj, cfg, func_name, call)
                    if struct and struct.fields:
                        structs.append(struct)

    except Exception as e:
        log.debug(f"结构恢复失败: {e}")

    if structs:
        log.info(f"恢复了 {len(structs)} 个堆结构")

    return structs


def _recover_from_alloc_site(proj, cfg, func_name: str, call) -> RecoveredStruct | None:
    """从malloc调用点恢复结构布局。"""
    struct = RecoveredStruct(
        name=f"struct_{func_name}_{call.addr:x}",
        alloc_site=call.addr,
    )

    try:
        func = proj.kb.functions.get(call.addr)
        if not func:
            # 找包含这个地址的函数
            for f_addr, f in cfg.functions.items():
                if call.addr in range(f.addr, f.addr + f.size):
                    func = f
                    break

        if not func:
            return None

        # 扫描malloc后的指令，找到写入模式
        found_malloc = False
        for block in func.blocks:
            if block.addr < call.addr:
                continue

            b = proj.factory.block(block.addr)
            for insn in b.capstone.insns:
                if insn.address == call.addr:
                    found_malloc = True
                    continue

                if not found_malloc:
                    continue

                # mov [rax+offset], value → 结构体字段
                if insn.mnemonic == "mov" and "[" in insn.op_str:
                    parts = insn.op_str.split(",")
                    if len(parts) == 2 and ("rax" in parts[0] or "rbx" in parts[0]):
                        offset = _extract_offset(parts[0])
                        if offset is not None:
                            size = _infer_field_size(parts[0])
                            struct.fields.append(StructField(
                                offset=offset,
                                size=size,
                                name=f"field_{offset:x}",
                            ))

                # 遇到下一个call就停止
                if insn.mnemonic == "call":
                    break

            if found_malloc and block.addr > call.addr + 0x80:
                break

    except Exception:
        pass

    return struct


def _extract_offset(operand: str) -> int | None:
    """从 [reg+offset] 中提取偏移。"""
    import re
    m = re.search(r'\+\s*([0-9a-fA-Fx]+)\]', operand)
    if m:
        try:
            return int(m.group(1), 0)
        except ValueError:
            pass

    if "]" in operand and "+" not in operand and "-" not in operand:
        return 0

    return None


def _infer_field_size(operand: str) -> int:
    """从操作数推断字段大小。"""
    if "qword" in operand:
        return 8
    if "dword" in operand:
        return 4
    if "word" in operand and "dword" not in operand and "qword" not in operand:
        return 2
    if "byte" in operand:
        return 1
    return 8  # 默认64位
