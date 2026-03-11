from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pwn import log

from autopwn.config import SKIP_FUNCS

if TYPE_CHECKING:
    from autopwn.context import PwnContext


@dataclass
class CallGraphNode:
    name: str = ""
    addr: int = 0
    callees: list[str] = field(default_factory=list)
    callers: list[str] = field(default_factory=list)


def build_cfg(ctx: PwnContext) -> Any:
    """构建控制流图。"""
    try:
        import angr

        proj = angr.Project(ctx.binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        ctx.cfg = cfg
        node_count = sum(1 for _ in cfg.graph.nodes())
        log.info(f"CFG构建完成: {node_count} 个节点")
        return cfg

    except ImportError:
        log.warning("angr未安装，跳过CFG构建")
    except Exception as e:
        log.warning(f"CFG构建失败: {e}")

    return None


def build_callgraph(ctx: PwnContext) -> dict[str, CallGraphNode]:
    """构建函数调用图。"""
    callgraph: dict[str, CallGraphNode] = {}

    try:
        import angr

        proj = angr.Project(ctx.binary_path, auto_load_libs=False)
        cfg = ctx.cfg
        if cfg is None:
            cfg = proj.analyses.CFGFast()
            ctx.cfg = cfg

        for func_addr, func in cfg.functions.items():
            if func.name in SKIP_FUNCS:
                continue

            node = CallGraphNode(name=func.name, addr=func_addr)

            # 获取被调用的函数
            try:
                for site in func.get_call_sites():
                    target = func.get_call_target(site)
                    if target and target in cfg.functions:
                        callee_name = cfg.functions[target].name
                        node.callees.append(callee_name)
            except Exception:
                pass

            callgraph[func.name] = node

        # 反向填充callers
        for name, node in callgraph.items():
            for callee in node.callees:
                if callee in callgraph:
                    callgraph[callee].callers.append(name)

        ctx.callgraph = callgraph
        log.info(f"调用图构建完成: {len(callgraph)} 个函数")

    except ImportError:
        log.warning("angr未安装，跳过调用图构建")
    except Exception as e:
        log.warning(f"调用图构建失败: {e}")

    return callgraph


def find_path_to_function(callgraph: dict[str, CallGraphNode],
                           start: str, target: str) -> list[str] | None:
    """在调用图中找从start到target的路径（BFS）。"""
    if start not in callgraph or target not in callgraph:
        return None

    from collections import deque
    queue = deque([(start, [start])])
    visited = {start}

    while queue:
        current, path = queue.popleft()
        if current == target:
            return path

        node = callgraph.get(current)
        if not node:
            continue

        for callee in node.callees:
            if callee not in visited:
                visited.add(callee)
                queue.append((callee, path + [callee]))

    return None


def find_reachable_from_main(callgraph: dict[str, CallGraphNode]) -> set[str]:
    """找到从main可达的所有函数。"""
    start = "main"
    if start not in callgraph:
        return set()

    from collections import deque
    reachable = set()
    queue = deque([start])

    while queue:
        current = queue.popleft()
        if current in reachable:
            continue
        reachable.add(current)

        node = callgraph.get(current)
        if node:
            for callee in node.callees:
                if callee not in reachable:
                    queue.append(callee)

    return reachable
