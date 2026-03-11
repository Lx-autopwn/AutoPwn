"""Agent state and attempt record data structures."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AttemptRecord:
    """Record of a single exploit attempt."""
    strategy: str = ""
    payload: bytes = b""
    interaction: list[tuple[str, bytes]] = field(default_factory=list)

    # outcome
    success: bool = False
    crash_signal: int = 0
    exit_code: int = -1
    output: bytes = b""
    error_msg: str = ""
    duration: float = 0.0

    # agent interpretation
    diagnosis: str = ""


@dataclass
class ActionResult:
    """Result returned by a rule action."""
    success: bool = False
    terminal: bool = False  # True = don't retry this rule
    record: AttemptRecord = field(default_factory=AttemptRecord)


@dataclass
class AgentState:
    """All knowledge the agent accumulates during its run."""
    ctx: Any = None  # PwnContext

    attempts: list[AttemptRecord] = field(default_factory=list)
    blocked_rules: set[str] = field(default_factory=set)
    discovered_facts: dict[str, Any] = field(default_factory=dict)

    round: int = 0
    max_rounds: int = 15

    # phase5 failure info (populated from engine's failed strategies)
    phase5_strategies_tried: list[str] = field(default_factory=list)
    phase5_had_leak: bool = False
    phase5_leak_value: int = 0
