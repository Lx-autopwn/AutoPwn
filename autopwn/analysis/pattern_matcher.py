from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pwn import log

from autopwn.config import (
    INPUT_FUNC_NAMES, FORMAT_FUNCS, HEAP_ALLOC_FUNCS, HEAP_FREE_FUNCS,
)

if TYPE_CHECKING:
    from autopwn.context import PwnContext
    from autopwn.analysis.decompiler import DecompiledFunction


@dataclass
class PatternMatch:
    pattern: str = ""
    function: str = ""
    address: int = 0
    description: str = ""
    confidence: str = "suspected"
    details: dict[str, Any] = field(default_factory=dict)


def match_patterns(ctx: PwnContext) -> list[PatternMatch]:
    """在反编译代码上匹配漏洞模式。"""
    matches = []

    for func_name, dec in ctx.decompiled.items():
        matches.extend(_match_gets_pattern(func_name, dec))
        matches.extend(_match_read_overflow(func_name, dec))
        matches.extend(_match_fmt_vuln(func_name, dec))
        matches.extend(_match_free_no_null(func_name, dec))
        matches.extend(_match_double_free(func_name, dec))
        matches.extend(_match_off_by_one(func_name, dec))
        matches.extend(_match_menu_switch(func_name, dec))

    if matches:
        log.info(f"模式匹配: {len(matches)} 个匹配")

    return matches


def _match_gets_pattern(func_name: str, dec) -> list[PatternMatch]:
    """匹配 gets() 调用。"""
    matches = []
    for call in dec.calls:
        if call.target == "gets":
            matches.append(PatternMatch(
                pattern="gets_call",
                function=func_name,
                address=call.addr,
                description="gets() 无限制读取 → 确定性栈溢出",
                confidence="confirmed_static",
            ))
    return matches


def _match_read_overflow(func_name: str, dec) -> list[PatternMatch]:
    """匹配 read(fd, buf, size) 中 size > buffer_size。"""
    matches = []
    for call in dec.calls:
        if call.target in ("read", "fgets", "fread", "recv"):
            for buf in dec.buffer_vars:
                if buf.actual_max_write > buf.size > 0:
                    matches.append(PatternMatch(
                        pattern="read_overflow",
                        function=func_name,
                        address=call.addr,
                        description=f"读取{buf.actual_max_write}字节到{buf.size}字节缓冲区",
                        confidence="confirmed_static",
                        details={"overflow": buf.actual_max_write - buf.size},
                    ))
    return matches


def _match_fmt_vuln(func_name: str, dec) -> list[PatternMatch]:
    """匹配 printf(user_input) 格式化字符串漏洞。"""
    matches = []

    has_input = False
    input_calls = []
    fmt_calls = []

    for call in dec.calls:
        if call.target in INPUT_FUNC_NAMES:
            has_input = True
            input_calls.append(call)
        if call.target in FORMAT_FUNCS:
            fmt_calls.append(call)

    if has_input and fmt_calls:
        for fc in fmt_calls:
            for ic in input_calls:
                if ic.addr < fc.addr:
                    matches.append(PatternMatch(
                        pattern="fmt_string",
                        function=func_name,
                        address=fc.addr,
                        description=f"输入→{fc.target}()，可能的格式化字符串漏洞",
                        confidence="suspected",
                    ))
                    break

    return matches


def _match_free_no_null(func_name: str, dec) -> list[PatternMatch]:
    """匹配 free(ptr) 后 ptr 未清零。"""
    matches = []
    for i, call in enumerate(dec.calls):
        if call.target in HEAP_FREE_FUNCS:
            # 检查后续是否有对同一变量的NULL赋值
            has_null = False
            for j in range(i + 1, min(i + 5, len(dec.calls))):
                pass  # 简化：需要更细致的数据流分析

            if not has_null:
                matches.append(PatternMatch(
                    pattern="free_no_null",
                    function=func_name,
                    address=call.addr,
                    description="free() 后指针可能未清零 → 潜在UAF",
                    confidence="suspected",
                ))
    return matches


def _match_double_free(func_name: str, dec) -> list[PatternMatch]:
    """匹配同一函数内的double free。"""
    matches = []
    free_calls = [c for c in dec.calls if c.target in HEAP_FREE_FUNCS]

    if len(free_calls) >= 2:
        matches.append(PatternMatch(
            pattern="potential_double_free",
            function=func_name,
            address=free_calls[0].addr,
            description=f"函数内有{len(free_calls)}次free调用",
            confidence="suspected",
        ))

    return matches


def _match_off_by_one(func_name: str, dec) -> list[PatternMatch]:
    """匹配 off-by-one 模式。"""
    matches = []

    if dec.pseudo_code:
        code = dec.pseudo_code.lower()

        # for(i=0; i<=n; i++) 模式
        if "<=" in code and ("for" in code or "while" in code):
            if "buf" in code or "[" in code:
                matches.append(PatternMatch(
                    pattern="off_by_one_loop",
                    function=func_name,
                    description="循环中使用 <= 比较，可能off-by-one",
                    confidence="suspected",
                ))

        # buf[strlen(input)] = '\0' 模式
        if "strlen" in code and "= 0" in code:
            matches.append(PatternMatch(
                pattern="off_by_null",
                function=func_name,
                description="strlen+null终止可能导致off-by-null",
                confidence="suspected",
            ))

    return matches


def _match_menu_switch(func_name: str, dec) -> list[PatternMatch]:
    """匹配菜单switch-case结构。"""
    matches = []

    alloc_count = sum(1 for c in dec.calls if c.target in HEAP_ALLOC_FUNCS)
    free_count = sum(1 for c in dec.calls if c.target in HEAP_FREE_FUNCS)
    input_count = sum(1 for c in dec.calls if c.target in INPUT_FUNC_NAMES)

    if alloc_count > 0 and free_count > 0 and input_count > 0:
        matches.append(PatternMatch(
            pattern="heap_menu",
            function=func_name,
            description=f"菜单堆题模式: {alloc_count}次alloc, {free_count}次free",
            confidence="suspected",
            details={
                "alloc_count": alloc_count,
                "free_count": free_count,
                "input_count": input_count,
            },
        ))

    return matches
