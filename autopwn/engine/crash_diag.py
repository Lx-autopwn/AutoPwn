from __future__ import annotations

from typing import TYPE_CHECKING

from pwn import log

if TYPE_CHECKING:
    from autopwn.context import PwnContext
    from autopwn.dynamic.crash_triage import CrashInfo


def diagnose(crash: CrashInfo, ctx: PwnContext) -> dict:
    """诊断crash原因并给出修复建议。"""
    diagnosis = {
        "crash_type": crash.crash_type,
        "description": crash.description,
        "root_cause": "",
        "fix_suggestions": [],
        "should_retry": False,
        "retry_adjustments": {},
    }

    if crash.crash_type == "canary":
        diagnosis["root_cause"] = "Stack canary被破坏"
        if ctx.is_forking:
            diagnosis["fix_suggestions"].append("forking server: 逐字节爆破canary")
            diagnosis["should_retry"] = True
            diagnosis["retry_adjustments"]["needs_canary_brute"] = True
        else:
            # 检查是否有泄露canary的方式
            has_fmt = any(
                isinstance(v, dict) and v.get("type") == "fmt_string"
                for v in ctx.vulnerabilities
            )
            if has_fmt:
                diagnosis["fix_suggestions"].append("用格式化字符串泄露canary")
                diagnosis["should_retry"] = True
                diagnosis["retry_adjustments"]["needs_canary_leak"] = True
            else:
                diagnosis["fix_suggestions"].append("需要找到canary泄露途径")

    elif crash.crash_type == "stack_misalign":
        diagnosis["root_cause"] = "x86_64栈未16字节对齐"
        diagnosis["fix_suggestions"].append("在ROP链开头添加一个 ret gadget")
        diagnosis["should_retry"] = True
        diagnosis["retry_adjustments"]["add_ret_gadget"] = True

    elif crash.crash_type == "rip_control":
        diagnosis["root_cause"] = "RIP已被控制（来自输入pattern）"
        diagnosis["fix_suggestions"].append("溢出偏移正确，检查目标地址")
        if ctx.pie:
            diagnosis["fix_suggestions"].append("PIE启用，需要先泄露程序基址")
            diagnosis["should_retry"] = True
            diagnosis["retry_adjustments"]["needs_pie_leak"] = True

    elif crash.crash_type == "null_deref":
        diagnosis["root_cause"] = "空指针解引用"
        diagnosis["fix_suggestions"].append("检查ROP链中的参数设置")
        diagnosis["fix_suggestions"].append("可能需要设置更多寄存器")

    elif crash.crash_type == "sigsegv":
        diagnosis["root_cause"] = f"段错误 @ {crash.fault_addr:#x}"
        if crash.fault_addr and 0x7f0000000000 <= crash.fault_addr <= 0x7fffffffffff:
            diagnosis["fix_suggestions"].append("目标地址在libc范围，可能libc基址计算错误")
            diagnosis["should_retry"] = True
        elif crash.fault_addr and crash.fault_addr < 0x1000:
            diagnosis["fix_suggestions"].append("低地址段错误，可能ROP链构造错误")

    elif crash.crash_type == "timeout":
        diagnosis["root_cause"] = "程序超时"
        diagnosis["fix_suggestions"].append("程序可能在等待输入或陷入死循环")
        diagnosis["fix_suggestions"].append("检查payload是否完整（可能缺少换行符）")

    return diagnosis


def apply_fix(ctx: PwnContext, adjustment: dict) -> None:
    """应用诊断建议的修复。"""
    if adjustment.get("add_ret_gadget"):
        ret = ctx.find_gadget("ret")
        if ret:
            log.info(f"添加ret gadget进行栈对齐: {ret:#x}")
            ctx.gadgets["_alignment_ret"] = ret

    if adjustment.get("needs_canary_brute"):
        log.info("标记需要canary爆破")
        ctx.leaked_addrs["canary_needed"] = 1

    if adjustment.get("needs_canary_leak"):
        log.info("标记需要canary泄露")
        ctx.leaked_addrs["canary_leak_needed"] = 1

    if adjustment.get("needs_pie_leak"):
        log.info("标记需要PIE基址泄露")
        ctx.leaked_addrs["pie_leak_needed"] = 1
