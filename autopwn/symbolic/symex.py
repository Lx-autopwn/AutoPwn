from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pwn import log

from autopwn.config import ANGR_TIMEOUT, SYMEX_TIMEOUT

if TYPE_CHECKING:
    from autopwn.context import PwnContext


@dataclass
class SymExResult:
    found: bool = False
    input_bytes: bytes = b""
    stdout: bytes = b""
    constraints: list[str] = field(default_factory=list)
    states_explored: int = 0


def find_input_to_address(binary_path: str, target_addr: int,
                           avoid: list[int] = None,
                           stdin_size: int = 256,
                           timeout: int = ANGR_TIMEOUT) -> SymExResult:
    """符号执行找到到达target_addr的输入。"""
    result = SymExResult()

    try:
        import angr
        import claripy
    except ImportError:
        log.warning("angr未安装")
        return result

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        sym_input = claripy.BVS("stdin", stdin_size * 8)

        state = proj.factory.entry_state(
            stdin=angr.SimFile("/dev/stdin", content=sym_input),
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )

        # 约束输入为可打印字符（减少搜索空间）
        for i in range(min(stdin_size, 64)):
            byte = sym_input.get_byte(i)
            state.solver.add(byte >= 0x20)
            state.solver.add(byte <= 0x7e)

        simgr = proj.factory.simulation_manager(state)
        simgr.explore(find=target_addr, avoid=avoid or [], timeout=timeout)

        if simgr.found:
            found_state = simgr.found[0]
            result.found = True
            result.input_bytes = found_state.solver.eval(sym_input, cast_to=bytes)
            result.states_explored = len(simgr.deadended) + len(simgr.found)

            try:
                result.stdout = found_state.posix.dumps(1)
            except Exception:
                pass

            log.success(f"符号执行成功: 到达 {target_addr:#x}")

    except Exception as e:
        log.warning(f"符号执行失败: {e}")

    return result


def find_input_for_output(binary_path: str, expected_output: bytes,
                           stdin_size: int = 128,
                           timeout: int = SYMEX_TIMEOUT) -> SymExResult:
    """找到产生特定输出的输入。"""
    result = SymExResult()

    try:
        import angr
        import claripy

        proj = angr.Project(binary_path, auto_load_libs=False)
        sym_input = claripy.BVS("stdin", stdin_size * 8)

        state = proj.factory.entry_state(
            stdin=angr.SimFile("/dev/stdin", content=sym_input),
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )

        simgr = proj.factory.simulation_manager(state)

        def check_output(s):
            try:
                out = s.posix.dumps(1)
                return expected_output in out
            except Exception:
                return False

        simgr.explore(
            find=check_output,
            timeout=timeout,
        )

        if simgr.found:
            found_state = simgr.found[0]
            result.found = True
            result.input_bytes = found_state.solver.eval(sym_input, cast_to=bytes)
            result.stdout = found_state.posix.dumps(1)

    except Exception as e:
        log.warning(f"符号执行失败: {e}")

    return result


def solve_constraints(binary_path: str, func_addr: int,
                       target_branch: int,
                       stdin_size: int = 128,
                       timeout: int = SYMEX_TIMEOUT) -> bytes | None:
    """求解到达特定分支的输入约束。"""
    try:
        import angr
        import claripy

        proj = angr.Project(binary_path, auto_load_libs=False)
        sym_input = claripy.BVS("stdin", stdin_size * 8)

        state = proj.factory.call_state(
            func_addr,
            stdin=angr.SimFile("/dev/stdin", content=sym_input),
        )

        simgr = proj.factory.simulation_manager(state)
        simgr.explore(find=target_branch, timeout=timeout)

        if simgr.found:
            return simgr.found[0].solver.eval(sym_input, cast_to=bytes)

    except Exception as e:
        log.debug(f"约束求解失败: {e}")

    return None
