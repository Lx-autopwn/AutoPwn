from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pwn import log

from autopwn.config import FORMAT_FUNCS, INPUT_FUNC_NAMES

if TYPE_CHECKING:
    from autopwn.context import PwnContext


@dataclass
class Vulnerability:
    vuln_type: str = ""  # stack_bof / heap_overflow / fmt_string / uaf / double_free / off_by_one
    confidence: str = "suspected"  # suspected / confirmed_static / confirmed_dynamic
    function: str = ""
    address: int = 0
    description: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.vuln_type,
            "confidence": self.confidence,
            "function": self.function,
            "address": self.address,
            "description": self.description,
            **self.details,
        }


def find_vulnerabilities(ctx: PwnContext) -> list[dict]:
    """综合所有分析结果，定位漏洞。"""
    vulns = []

    vulns.extend(_check_stack_bof(ctx))
    vulns.extend(_check_fmt_string(ctx))
    vulns.extend(_check_heap_vulns(ctx))
    vulns.extend(_check_dangerous_patterns(ctx))

    ctx.vulnerabilities = vulns
    if vulns:
        log.info(f"发现 {len(vulns)} 个漏洞")
        for v in vulns:
            vtype = v.get("type", "unknown")
            conf = v.get("confidence", "?")
            func = v.get("function", "")
            log.info(f"  [{conf}] {vtype} in {func}")

    return vulns


def _check_stack_bof(ctx: PwnContext) -> list[dict]:
    """检测栈缓冲区溢出。"""
    vulns = []

    # 从反编译结果检测
    for func_name, dec in ctx.decompiled.items():
        for call in dec.calls:
            if call.target == "gets":
                vulns.append(Vulnerability(
                    vuln_type="stack_bof",
                    confidence="confirmed_static",
                    function=func_name,
                    address=call.addr,
                    description=f"gets() 无长度限制",
                ).to_dict())

            elif call.target in ("read", "fread", "recv"):
                for buf in dec.buffer_vars:
                    if buf.actual_max_write > buf.size > 0:
                        vulns.append(Vulnerability(
                            vuln_type="stack_bof",
                            confidence="confirmed_static",
                            function=func_name,
                            address=call.addr,
                            description=f"read {buf.actual_max_write} bytes into {buf.size} byte buffer",
                            details={
                                "buffer_size": buf.size,
                                "read_size": buf.actual_max_write,
                                "overflow_amount": buf.actual_max_write - buf.size,
                                "buffer_offset": buf.stack_offset,
                            },
                        ).to_dict())

            elif call.target in ("strcpy", "strcat"):
                vulns.append(Vulnerability(
                    vuln_type="stack_bof",
                    confidence="suspected",
                    function=func_name,
                    address=call.addr,
                    description=f"{call.target}() 可能导致溢出",
                ).to_dict())

    # 从危险函数列表检测（无反编译时的降级）
    if not ctx.decompiled:
        for func_info in ctx.dangerous_funcs:
            name = func_info.get("name", "")
            if name == "gets":
                vulns.append(Vulnerability(
                    vuln_type="stack_bof",
                    confidence="confirmed_static",
                    function="(unknown)",
                    description="gets() 无长度限制",
                ).to_dict())
            elif name in ("strcpy", "strcat", "sprintf", "vsprintf"):
                vulns.append(Vulnerability(
                    vuln_type="stack_bof",
                    confidence="suspected",
                    function="(unknown)",
                    description=f"{name}() 可能导致溢出",
                ).to_dict())

    return vulns


def _check_fmt_string(ctx: PwnContext) -> list[dict]:
    """检测格式化字符串漏洞。"""
    vulns = []

    # 从污点分析结果
    for flow in ctx.taint_flows:
        if hasattr(flow, 'sink') and flow.sink.sink_type == "fmt_arg":
            vulns.append(Vulnerability(
                vuln_type="fmt_string",
                confidence="confirmed_static",
                function=flow.sink.in_function,
                address=flow.sink.addr,
                description=f"用户输入作为{flow.sink.func}的格式参数",
            ).to_dict())

    # 从反编译结果检测
    for func_name, dec in ctx.decompiled.items():
        for call in dec.calls:
            if call.target in FORMAT_FUNCS:
                # 检查第一个参数是否来自用户输入
                # 简化：如果同一函数中有read/gets后跟printf → 可疑
                has_input = any(c.target in INPUT_FUNC_NAMES for c in dec.calls)
                if has_input and call.addr > 0:
                    # 避免重复
                    already = any(v.get("address") == call.addr for v in vulns)
                    if not already:
                        vulns.append(Vulnerability(
                            vuln_type="fmt_string",
                            confidence="suspected",
                            function=func_name,
                            address=call.addr,
                            description=f"{call.target}() 可能接受用户控制的格式字符串",
                        ).to_dict())

    return vulns


def _check_heap_vulns(ctx: PwnContext) -> list[dict]:
    """检测堆漏洞。"""
    vulns = []

    # 从数据流分析
    if ctx.has_uaf:
        vulns.append(Vulnerability(
            vuln_type="uaf",
            confidence="suspected",
            description="Use-After-Free: free后指针未清零",
        ).to_dict())

    if ctx.has_double_free:
        vulns.append(Vulnerability(
            vuln_type="double_free",
            confidence="suspected",
            description="同一指针被free两次",
        ).to_dict())

    if ctx.has_heap_overflow:
        vulns.append(Vulnerability(
            vuln_type="heap_overflow",
            confidence="suspected",
            description="堆缓冲区溢出",
        ).to_dict())

    if ctx.has_off_by_one:
        vulns.append(Vulnerability(
            vuln_type="off_by_one",
            confidence="suspected",
            description="Off-by-one/null溢出",
        ).to_dict())

    return vulns


def _check_dangerous_patterns(ctx: PwnContext) -> list[dict]:
    """检测其他危险模式。"""
    vulns = []

    # system() 调用（可能可以控制参数）
    for func_info in ctx.dangerous_funcs:
        name = func_info.get("name", "")
        if name == "system":
            vulns.append(Vulnerability(
                vuln_type="command_injection",
                confidence="suspected",
                description="system() 调用（需要检查参数是否可控）",
            ).to_dict())

    return vulns
