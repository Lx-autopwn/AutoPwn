from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pwn import log

if TYPE_CHECKING:
    from autopwn.context import PwnContext


@dataclass
class ExploitPlan:
    strategy: str = ""
    steps: list[dict[str, Any]] = field(default_factory=list)
    score: float = 0
    description: str = ""
    requirements: list[str] = field(default_factory=list)
    estimated_success: float = 0


def generate_plans(ctx: PwnContext) -> list[ExploitPlan]:
    """根据分析结果生成利用计划。"""
    plans = []

    # 直接利用计划
    if ctx.win_funcs and ctx.overflow_offset >= 0 and not ctx.canary:
        plan = ExploitPlan(
            strategy="ret2win",
            description="直接栈溢出到win函数",
            score=90,
            estimated_success=0.95,
            steps=[
                {"action": "overflow", "offset": ctx.overflow_offset},
                {"action": "call_win", "target": ctx.win_funcs[0]},
            ],
        )
        plans.append(plan)

    # ret2libc计划
    if ctx.overflow_offset >= 0 and not ctx.canary:
        output_funcs = [f for f in ["puts", "printf", "write"] if f in ctx.plt_table]
        if output_funcs and ctx.find_gadget("pop rdi"):
            plan = ExploitPlan(
                strategy="ret2libc",
                description=f"2阶段ret2libc (通过{output_funcs[0]}泄露)",
                score=70,
                estimated_success=0.75,
                steps=[
                    {"action": "stage1_leak", "func": output_funcs[0]},
                    {"action": "resolve_libc"},
                    {"action": "stage2_shell"},
                ],
            )
            plans.append(plan)

    # 格式化字符串计划
    fmt_vulns = [v for v in ctx.vulnerabilities
                  if isinstance(v, dict) and v.get("type") == "fmt_string"]
    if fmt_vulns and ctx.relro != "full":
        plan = ExploitPlan(
            strategy="fmt_string",
            description="格式化字符串: 泄露libc → GOT覆写",
            score=75,
            estimated_success=0.7,
            steps=[
                {"action": "probe_offset"},
                {"action": "leak_got", "target": "puts"},
                {"action": "resolve_libc"},
                {"action": "overwrite_got", "target": "system"},
                {"action": "trigger_shell"},
            ],
        )
        plans.append(plan)

    # 堆利用计划
    if ctx.input_type == "menu":
        if ctx.has_uaf:
            plan = ExploitPlan(
                strategy="tcache_poison_uaf",
                description="UAF → tcache poison → __free_hook → system",
                score=60,
                estimated_success=0.6,
                steps=[
                    {"action": "leak_libc", "method": "unsorted_bin"},
                    {"action": "tcache_poison", "target": "__free_hook"},
                    {"action": "write_system"},
                    {"action": "trigger_free_binsh"},
                ],
            )
            plans.append(plan)

        if ctx.has_double_free:
            plan = ExploitPlan(
                strategy="fastbin_dup",
                description="Double free → fastbin/tcache dup → 任意写",
                score=55,
                estimated_success=0.5,
                steps=[
                    {"action": "leak_libc"},
                    {"action": "double_free_chain"},
                    {"action": "alloc_to_hook"},
                    {"action": "trigger_shell"},
                ],
            )
            plans.append(plan)

    # ORW计划
    if not ctx.execve_allowed and ctx.overflow_offset >= 0:
        plan = ExploitPlan(
            strategy="orw",
            description="seccomp绕过: open-read-write读flag",
            score=65,
            estimated_success=0.6,
            steps=[
                {"action": "build_orw_chain"},
                {"action": "send_rop"},
            ],
        )
        plans.append(plan)

    # SROP计划
    if ctx.overflow_offset >= 0 and ctx.find_gadget("syscall"):
        plan = ExploitPlan(
            strategy="srop",
            description="Sigreturn ROP",
            score=45,
            estimated_success=0.5,
            steps=[
                {"action": "build_sigreturn_frame"},
                {"action": "trigger_sigreturn"},
            ],
        )
        plans.append(plan)

    # 按分数排序
    plans.sort(key=lambda p: -p.score)

    if plans:
        log.info(f"生成了 {len(plans)} 个利用计划:")
        for i, p in enumerate(plans, 1):
            log.info(f"  #{i} [{p.score:.0f}] {p.description}")

    ctx.exploit_paths = [
        {"description": p.description, "score": p.score, "strategy": p.strategy, "steps": p.steps}
        for p in plans
    ]

    return plans
