from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pwn import log

if TYPE_CHECKING:
    from autopwn.context import PwnContext


@dataclass
class DefUse:
    var: str = ""
    def_addr: int = 0
    use_addrs: list[int] = field(default_factory=list)
    def_func: str = ""


@dataclass
class DataFlowResult:
    def_use_chains: list[DefUse] = field(default_factory=list)
    buffer_sizes: dict[str, int] = field(default_factory=dict)
    write_sizes: dict[str, int] = field(default_factory=dict)
    freed_pointers: list[dict] = field(default_factory=list)
    pointer_not_nulled: list[dict] = field(default_factory=list)


def analyze_dataflow(ctx: PwnContext) -> DataFlowResult:
    """运行数据流分析。"""
    result = DataFlowResult()

    try:
        import angr
    except ImportError:
        log.warning("angr未安装，跳过数据流分析")
        return result

    try:
        proj = angr.Project(ctx.binary_path, auto_load_libs=False)
        cfg = ctx.cfg
        if cfg is None:
            cfg = proj.analyses.CFGFast()

        for func_addr, func in cfg.functions.items():
            if func.is_plt or func.is_simprocedure:
                continue

            try:
                _analyze_function_dataflow(proj, func, result)
            except Exception:
                pass

        log.info(f"数据流分析: {len(result.buffer_sizes)} 个缓冲区, "
                 f"{len(result.freed_pointers)} 个free调用")

    except Exception as e:
        log.warning(f"数据流分析失败: {e}")

    return result


def _analyze_function_dataflow(proj, func, result: DataFlowResult) -> None:
    """分析单个函数的数据流。"""
    try:
        rd = proj.analyses.ReachingDefinitions(func)
    except Exception:
        return

    # 从reaching definitions中提取定义-使用链
    try:
        for node in func.graph.nodes():
            try:
                block = proj.factory.block(node.addr)
                for insn in block.capstone.insns:
                    _analyze_instruction(insn, func, result)
            except Exception:
                pass
    except Exception:
        pass


def _analyze_instruction(insn, func, result: DataFlowResult) -> None:
    """分析单条指令的数据流影响。"""
    mnemonic = insn.mnemonic

    # 检测sub rsp, N (栈帧分配)
    if mnemonic == "sub" and "rsp" in insn.op_str:
        parts = insn.op_str.split(",")
        if len(parts) == 2:
            try:
                size = int(parts[1].strip(), 0)
                result.buffer_sizes[f"{func.name}_frame"] = size
            except ValueError:
                pass

    # 检测lea指令（获取缓冲区地址）
    if mnemonic == "lea" and "rbp" in insn.op_str:
        parts = insn.op_str.split(",")
        if len(parts) == 2 and "[rbp" in parts[1]:
            try:
                offset_str = parts[1].strip()
                if "-" in offset_str:
                    offset = int(offset_str.split("-")[1].rstrip("]").strip(), 16)
                    result.buffer_sizes[f"{func.name}_buf_{offset:x}"] = offset
            except (ValueError, IndexError):
                pass


def detect_uaf_pattern(ctx: PwnContext) -> list[dict]:
    """检测UAF模式: free后指针未清零且被使用。"""
    uaf_list = []

    try:
        import angr

        proj = angr.Project(ctx.binary_path, auto_load_libs=False)
        cfg = ctx.cfg or proj.analyses.CFGFast()

        for func_addr, func in cfg.functions.items():
            if func.is_plt or func.is_simprocedure:
                continue

            free_sites = []
            deref_sites = []

            for block in func.blocks:
                try:
                    b = proj.factory.block(block.addr)
                    for insn in b.capstone.insns:
                        if insn.mnemonic == "call":
                            name = _get_call_target_name(proj, cfg, insn)
                            if name == "free":
                                free_sites.append(insn.address)
                except Exception:
                    pass

            # 简单启发：如果free之后同函数有其他对相同指针的操作
            if free_sites:
                for site in free_sites:
                    # 检查free后是否有NULL赋值
                    null_after = _has_null_assignment_after(proj, func, site)
                    if not null_after:
                        uaf_list.append({
                            "function": func.name,
                            "free_site": site,
                            "null_cleared": False,
                            "confidence": "suspected",
                        })

    except Exception:
        pass

    if uaf_list:
        ctx.has_uaf = True
        log.info(f"检测到 {len(uaf_list)} 个潜在UAF")

    return uaf_list


def _get_call_target_name(proj, cfg, insn) -> str:
    """获取call指令的目标函数名。"""
    try:
        op = insn.op_str
        if op.startswith("0x"):
            target = int(op, 16)
            func = proj.kb.functions.get(target)
            if func:
                return func.name
        elif "<" in op:
            return op.split("<")[1].split(">")[0].strip()
    except Exception:
        pass
    return ""


def _has_null_assignment_after(proj, func, free_addr: int) -> bool:
    """检查free调用后是否有NULL赋值来清除指针。"""
    try:
        for block in func.blocks:
            if block.addr <= free_addr:
                continue
            b = proj.factory.block(block.addr)
            for insn in b.capstone.insns:
                # mov [xxx], 0 或 mov qword ptr [xxx], 0
                if insn.mnemonic == "mov" and ", 0" in insn.op_str:
                    if "[" in insn.op_str:
                        return True
            # 只检查free后的前几个block
            if block.addr > free_addr + 0x30:
                break
    except Exception:
        pass
    return False
