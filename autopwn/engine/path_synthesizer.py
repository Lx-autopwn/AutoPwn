from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pwn import log

if TYPE_CHECKING:
    from autopwn.context import PwnContext


@dataclass
class ExploitStep:
    action: str = ""
    target: str = ""
    value: Any = None
    description: str = ""
    requires: list[str] = field(default_factory=list)
    provides: list[str] = field(default_factory=list)


@dataclass
class SynthesizedPath:
    steps: list[ExploitStep] = field(default_factory=list)
    score: float = 0
    description: str = ""
    feasible: bool = True


# 目标依赖图
GOAL_REQUIREMENTS: dict[str, list[list[str]]] = {
    "get_shell": [
        ["system_call"],       # system("/bin/sh")
        ["execve_call"],       # execve
        ["one_gadget_call"],   # one_gadget
    ],
    "read_flag": [
        ["orw_chain"],         # open-read-write
        ["sendfile_chain"],    # sendfile
    ],
    "system_call": [
        ["rip_control", "libc_base", "set_arg1"],
    ],
    "execve_call": [
        ["rip_control", "set_arg1", "set_arg2", "set_arg3", "syscall"],
    ],
    "one_gadget_call": [
        ["rip_control", "libc_base"],
    ],
    "orw_chain": [
        ["rip_control", "set_arg1", "set_arg2", "set_arg3", "syscall"],
        ["rip_control", "libc_base"],  # 用libc的ORW gadgets
    ],
    "rip_control": [
        ["stack_bof"],           # 栈溢出
        ["got_overwrite"],       # GOT覆写
        ["free_hook_overwrite"], # __free_hook
    ],
    "libc_base": [
        ["libc_leak"],
    ],
    "libc_leak": [
        ["got_leak"],           # puts(GOT entry)
        ["fmt_leak"],           # 格式化字符串泄露
        ["heap_libc_leak"],     # 堆泄露libc
    ],
    "got_leak": [
        ["plt_got"],            # 有puts@plt + GOT
    ],
    "got_overwrite": [
        ["arbitrary_write"],
    ],
    "free_hook_overwrite": [
        ["arbitrary_write", "libc_base"],
    ],
}


def synthesize_paths(ctx: PwnContext) -> list[SynthesizedPath]:
    """从最终目标反向搜索，找到所有可行的利用路径。"""
    available = _collect_available_primitives(ctx)

    goal = "get_shell" if ctx.execve_allowed else "read_flag"
    log.info(f"目标: {goal}")
    log.info(f"可用原语: {available}")

    paths = []
    _search(goal, available, [], set(), paths, ctx)

    # 评分和排序
    for path in paths:
        path.score = _score_path(path, ctx)

    paths.sort(key=lambda p: -p.score)

    if paths:
        log.info(f"合成了 {len(paths)} 条利用路径:")
        for i, p in enumerate(paths[:5], 1):
            log.info(f"  #{i} [{p.score:.1f}] {p.description}")

    ctx.exploit_paths = [
        {"description": p.description, "score": p.score,
         "steps": [{"action": s.action, "description": s.description} for s in p.steps]}
        for p in paths
    ]

    return paths


def _collect_available_primitives(ctx: PwnContext) -> set[str]:
    """收集所有可用的原语。"""
    available = set()

    for p in ctx.primitives:
        if isinstance(p, dict):
            for prov in p.get("provides", []):
                available.add(prov)
            available.add(p.get("name", ""))

    # 直接可用的能力
    if ctx.overflow_offset >= 0 and not ctx.canary:
        available.add("stack_bof")
        available.add("rip_control")

    if ctx.overflow_offset >= 0 and ctx.canary and ctx.canary_value:
        available.add("stack_bof")
        available.add("rip_control")

    if ctx.win_funcs:
        available.add("direct_shell")

    if ctx.gadgets:
        if ctx.find_gadget("pop rdi"):
            available.add("set_arg1")
        if ctx.find_gadget("pop rsi"):
            available.add("set_arg2")
        if ctx.find_gadget("pop rdx"):
            available.add("set_arg3")
        if ctx.find_gadget("syscall"):
            available.add("syscall")

    if "puts" in ctx.plt_table or "printf" in ctx.plt_table:
        if ctx.got_table:
            available.add("plt_got")
            available.add("got_leak")

    if ctx.libc_base:
        available.add("libc_base")
        available.add("libc_leak")

    if ctx.relro != "full":
        available.add("got_writable")

    return available


def _search(goal: str, available: set[str], current_steps: list[ExploitStep],
            visited: set[str], results: list[SynthesizedPath], ctx: PwnContext,
            depth: int = 0) -> None:
    """递归搜索利用路径。"""
    if depth > 10:
        return

    if goal in visited:
        return
    visited.add(goal)

    # 目标已满足
    if goal in available:
        path = SynthesizedPath(
            steps=list(current_steps),
            description=" → ".join(s.action for s in current_steps) or goal,
            feasible=True,
        )
        results.append(path)
        visited.discard(goal)
        return

    # 查找满足方式
    requirements = GOAL_REQUIREMENTS.get(goal, [])
    if not requirements:
        visited.discard(goal)
        return

    for req_set in requirements:
        # 检查这组需求是否都能满足（直接或递归）
        all_met = True
        sub_steps = []

        for req in req_set:
            if req in available:
                sub_steps.append(ExploitStep(
                    action=req,
                    description=f"使用已有原语: {req}",
                ))
            else:
                # 递归搜索
                sub_results: list[SynthesizedPath] = []
                _search(req, available, [], set(visited), sub_results, ctx, depth + 1)
                if sub_results:
                    sub_steps.extend(sub_results[0].steps)
                    sub_steps.append(ExploitStep(
                        action=req,
                        description=f"通过子路径获得: {req}",
                    ))
                else:
                    all_met = False
                    break

        if all_met:
            full_steps = list(current_steps) + sub_steps
            full_steps.append(ExploitStep(
                action=goal,
                description=f"实现目标: {goal}",
            ))

            path = SynthesizedPath(
                steps=full_steps,
                description=" → ".join(s.action for s in full_steps),
                feasible=True,
            )
            results.append(path)

    visited.discard(goal)


def _score_path(path: SynthesizedPath, ctx: PwnContext) -> float:
    """对利用路径评分。"""
    score = 100.0

    # 步骤越少越好
    score -= len(path.steps) * 5

    # 包含确认的漏洞加分
    for vuln in ctx.vulnerabilities:
        conf = vuln.get("confidence", "") if isinstance(vuln, dict) else ""
        if "confirmed" in conf:
            score += 10
            break

    # 安全机制惩罚
    if ctx.canary and not ctx.canary_value:
        score -= 15
    if ctx.pie and not ctx.pie_base:
        score -= 10

    return max(0, score)
