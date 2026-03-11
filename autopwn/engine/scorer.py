"""Strategy scoring and ranking.

Ranks exploit strategy instances based on contextual fitness:
higher score = tried first.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from pwn import log

if TYPE_CHECKING:
    from autopwn.context import PwnContext
    from autopwn.exploit.base import BaseExploit


def rank_strategies(ctx: PwnContext, candidates: list[BaseExploit]) -> list[BaseExploit]:
    """Sort strategy instances by contextual score (descending)."""
    scored: list[tuple[float, BaseExploit]] = []

    for s in candidates:
        score = _score_strategy(ctx, s)
        scored.append((score, s))

    scored.sort(key=lambda t: -t[0])

    # Log ranking
    log.info("策略排名:")
    for score, s in scored:
        name = getattr(s, "name", type(s).__name__)
        log.info(f"  [{score:5.1f}] {name}")

    return [s for _, s in scored]


def _score_strategy(ctx: PwnContext, strategy: BaseExploit) -> float:
    """Compute a fitness score for a strategy given the current context."""
    name = getattr(strategy, "name", "")
    base = 100.0 - getattr(strategy, "priority", 50)

    # Bonus: win functions make ret2win very attractive
    if name == "ret2win" and ctx.win_funcs:
        base += 10

    # Bonus: canary_bypass when we have canary + win
    if name == "canary_bypass" and ctx.canary and ctx.win_funcs:
        base += 5

    # Bonus: fmt_string when format vuln is confirmed
    if name == "fmt_string":
        fmt_confirmed = any(
            isinstance(v, dict) and v.get("type") == "fmt_string"
            and v.get("confidence") in ("confirmed", "confirmed_dynamic")
            for v in ctx.vulnerabilities
        )
        if fmt_confirmed:
            base += 10

    # Bonus: ret2libc when we have overflow + PLT
    if name == "ret2libc":
        if ctx.overflow_offset >= 0 and ctx.plt_table:
            base += 5

    # Penalty: complex strategies when simpler ones exist
    if name in ("srop", "ret2dlresolve", "stack_pivot", "ret2csu"):
        if ctx.win_funcs:
            base -= 15

    # Penalty: shellcode when NX is on
    if name == "ret2shellcode" and ctx.nx:
        base -= 20

    # Bonus: overflow-based strategies when overflow detected
    if ctx.overflow_offset >= 0:
        if name in ("ret2win", "ret2libc", "ret2shellcode", "canary_bypass"):
            base += 5

    return max(0, base)
