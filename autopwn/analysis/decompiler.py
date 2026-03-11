from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pwn import log

from autopwn.config import SKIP_FUNCS

if TYPE_CHECKING:
    from autopwn.context import PwnContext


@dataclass
class Variable:
    name: str = ""
    offset: int = 0  # 栈偏移（相对rbp）
    size: int = 0
    var_type: str = ""  # buffer / int / pointer


@dataclass
class CallSite:
    addr: int = 0
    target: str = ""
    args: list[Any] = field(default_factory=list)
    return_var: str = ""


@dataclass
class BufferVar:
    name: str = ""
    stack_offset: int = 0
    size: int = 0
    actual_max_write: int = 0


@dataclass
class DecompiledFunction:
    name: str = ""
    addr: int = 0
    args: list[Variable] = field(default_factory=list)
    local_vars: list[Variable] = field(default_factory=list)
    calls: list[CallSite] = field(default_factory=list)
    stack_frame_size: int = 0
    buffer_vars: list[BufferVar] = field(default_factory=list)
    pseudo_code: str = ""
    raw_blocks: list[Any] = field(default_factory=list)


def decompile_all(ctx: PwnContext) -> dict[str, DecompiledFunction]:
    """反编译所有用户函数。"""
    results = {}

    try:
        import angr
    except ImportError:
        log.warning("angr未安装，跳过反编译")
        return results

    try:
        proj = angr.Project(ctx.binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        for func_addr, func in cfg.functions.items():
            if func.name in SKIP_FUNCS or func.is_plt or func.is_simprocedure:
                continue
            if func.name.startswith("_") and func.name not in ("_start",):
                if func.name.startswith("__"):
                    continue

            try:
                dec = _decompile_function(proj, func)
                if dec:
                    results[func.name] = dec
            except Exception as e:
                log.debug(f"反编译 {func.name} 失败: {e}")

        log.info(f"反编译了 {len(results)} 个函数")
        ctx.decompiled = results

    except Exception as e:
        log.warning(f"反编译失败: {e}")

    return results


def decompile_function(ctx: PwnContext, func_name: str) -> DecompiledFunction | None:
    """反编译单个函数。"""
    try:
        import angr

        proj = angr.Project(ctx.binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        for func_addr, func in cfg.functions.items():
            if func.name == func_name:
                return _decompile_function(proj, func)

    except Exception as e:
        log.warning(f"反编译 {func_name} 失败: {e}")
    return None


def _decompile_function(proj, func) -> DecompiledFunction | None:
    """用angr反编译一个函数。"""
    dec = DecompiledFunction(name=func.name, addr=func.addr)

    # 提取调用信息
    try:
        for block in func.blocks:
            try:
                vex_block = proj.factory.block(block.addr)
                irsb = vex_block.vex

                for stmt in irsb.statements:
                    pass  # VEX IR分析

                if irsb.jumpkind == "Ijk_Call":
                    call_target = _resolve_call_target(proj, irsb, block.addr)
                    if call_target:
                        cs = CallSite(addr=block.addr, target=call_target)
                        dec.calls.append(cs)

            except Exception:
                pass
    except Exception:
        pass

    # 尝试angr decompiler获取伪代码
    try:
        dec_result = proj.analyses.Decompiler(func)
        if dec_result and dec_result.codegen:
            dec.pseudo_code = dec_result.codegen.text
    except Exception:
        pass

    # 分析栈帧
    try:
        dec.stack_frame_size = func.sp_delta if hasattr(func, 'sp_delta') and func.sp_delta else 0
        if dec.stack_frame_size:
            dec.stack_frame_size = abs(dec.stack_frame_size)
    except Exception:
        pass

    # 提取局部变量和缓冲区
    _extract_stack_vars(proj, func, dec)

    return dec


def _resolve_call_target(proj, irsb, block_addr: int) -> str:
    """解析调用目标的函数名。"""
    try:
        cfg = proj.kb.cfgs.get_most_accurate()
        if cfg:
            node = cfg.get_any_node(block_addr)
            if node and node.successors:
                for succ in node.successors:
                    func = proj.kb.functions.get(succ.addr)
                    if func:
                        return func.name

        # 直接从VEX的constant jump target获取
        if hasattr(irsb, 'next') and hasattr(irsb.next, 'con'):
            target_addr = irsb.next.con.value
            func = proj.kb.functions.get(target_addr)
            if func:
                return func.name
    except Exception:
        pass
    return ""


def _extract_stack_vars(proj, func, dec: DecompiledFunction) -> None:
    """从函数中提取栈变量和缓冲区信息。"""
    try:
        if not hasattr(proj.analyses, 'VariableRecoveryFast'):
            return

        vr = proj.analyses.VariableRecoveryFast(func)

        for var in vr.variable_manager[func.addr].get_variables():
            if hasattr(var, 'region') and var.region == 'stack':
                v = Variable(
                    name=var.name or f"var_{abs(var.offset):x}",
                    offset=var.offset,
                    size=var.size,
                )
                dec.local_vars.append(v)

                if var.size >= 8:
                    bv = BufferVar(
                        name=v.name,
                        stack_offset=var.offset,
                        size=var.size,
                    )
                    dec.buffer_vars.append(bv)

    except Exception:
        pass
