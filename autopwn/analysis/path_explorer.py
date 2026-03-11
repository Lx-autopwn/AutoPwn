from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pwn import log

from autopwn.config import ANGR_TIMEOUT

if TYPE_CHECKING:
    from autopwn.context import PwnContext


@dataclass
class ExplorationResult:
    found: bool = False
    target_addr: int = 0
    input_bytes: bytes = b""
    constraints: list[str] = field(default_factory=list)
    path_length: int = 0


def explore_to_address(ctx: PwnContext, target_addr: int,
                        avoid_addrs: list[int] = None,
                        timeout: int = ANGR_TIMEOUT) -> ExplorationResult:
    """用angr符号执行找到到达target_addr的输入。"""
    result = ExplorationResult(target_addr=target_addr)

    try:
        import angr
        import claripy
    except ImportError:
        log.warning("angr未安装，跳过路径探索")
        return result

    try:
        proj = angr.Project(ctx.binary_path, auto_load_libs=False)

        # 创建符号输入
        input_size = ctx.input_max_len or 256
        sym_input = claripy.BVS("input", input_size * 8)

        state = proj.factory.entry_state(
            stdin=angr.SimFile("/dev/stdin", content=sym_input),
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )

        simgr = proj.factory.simulation_manager(state)

        avoid = avoid_addrs or []

        simgr.explore(
            find=target_addr,
            avoid=avoid,
            timeout=timeout,
        )

        if simgr.found:
            found_state = simgr.found[0]
            result.found = True

            try:
                concrete_input = found_state.solver.eval(sym_input, cast_to=bytes)
                result.input_bytes = concrete_input
            except Exception:
                pass

            result.path_length = found_state.history.block_count
            log.success(f"找到路径到 {target_addr:#x} (长度: {result.path_length})")
        else:
            log.info(f"未找到到达 {target_addr:#x} 的路径")

    except Exception as e:
        log.warning(f"路径探索失败: {e}")

    return result


def explore_to_function(ctx: PwnContext, func_name: str,
                         timeout: int = ANGR_TIMEOUT) -> ExplorationResult:
    """找到到达指定函数的输入。"""
    # 从ELF符号表获取函数地址
    if ctx.elf and func_name in ctx.elf.symbols:
        target_addr = ctx.elf.symbols[func_name]
        return explore_to_address(ctx, target_addr, timeout=timeout)

    log.warning(f"函数 {func_name} 未找到")
    return ExplorationResult()


def explore_vulnerability(ctx: PwnContext, vuln: dict,
                           timeout: int = ANGR_TIMEOUT) -> ExplorationResult:
    """找到触发特定漏洞的输入。"""
    vuln_addr = vuln.get("address", 0)
    if vuln_addr:
        return explore_to_address(ctx, vuln_addr, timeout=timeout)

    vuln_func = vuln.get("function", "")
    if vuln_func:
        return explore_to_function(ctx, vuln_func, timeout=timeout)

    return ExplorationResult()
