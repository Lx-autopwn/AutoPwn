"""Multi-step interaction prober.

Instead of classifying programs into rigid categories (direct/menu/read),
this module **explores** the program's interaction model by running it
and systematically probing:

  1. What does the program print first?
  2. What kind of input does it expect? (string, number, choice)
  3. After sending input, what happens? (more prompts, crash, same menu)
  4. Which input step triggers the overflow?

The output is an InteractionSequence -- a list of steps describing
how to reach the vulnerable input point:

  [
    Step(action="recv", pattern=b"length:"),
    Step(action="sendline", data=b"-1"),
    Step(action="recv", pattern=b"data:"),
    Step(action="overflow"),   # <-- this is where we send the payload
  ]

This replaces hardcoded overflow_prefix logic with a general-purpose
interaction discovery engine.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pwn import log, process

from autopwn.config import RECV_TIMEOUT

if TYPE_CHECKING:
    from autopwn.context import PwnContext


@dataclass
class InteractionStep:
    """One step in the interaction sequence."""
    action: str  # "recv", "send", "sendline", "overflow"
    data: bytes = b""
    pattern: bytes = b""  # expected output pattern before this step
    description: str = ""


@dataclass
class InteractionModel:
    """Describes how to interact with the binary to reach the overflow."""
    steps: list[InteractionStep] = field(default_factory=list)
    overflow_step_index: int = -1  # which step is the overflow
    confidence: float = 0.0

    @property
    def prefix_steps(self) -> list[InteractionStep]:
        """Steps before the overflow."""
        if self.overflow_step_index < 0:
            return []
        return self.steps[:self.overflow_step_index]


def probe_interaction(ctx: PwnContext) -> InteractionModel:
    """Probe the binary to discover its interaction model.

    Strategy:
    1. Run the binary, collect initial output
    2. If it waits for input, try different inputs and observe responses
    3. Check if input triggers a crash (potential overflow point)
    4. If multi-step, probe each step to find the overflow
    """
    model = InteractionModel()

    try:
        result = _probe_session(ctx)
        if result:
            model = result
    except Exception as exc:
        log.debug(f"interaction prober: {exc}")

    if model.overflow_step_index >= 0:
        log.info(f"交互模型: {len(model.steps)} 步, "
                 f"溢出在第 {model.overflow_step_index + 1} 步, "
                 f"置信度 {model.confidence:.0%}")
        # Save to context for exploit strategies to use
        ctx.interaction_model = model
    else:
        # Single-step model (default behavior)
        model.steps = [InteractionStep(action="overflow")]
        model.overflow_step_index = 0
        model.confidence = 0.5

    return model


def _probe_session(ctx: PwnContext) -> InteractionModel | None:
    """Run one probe session."""
    p = process(ctx.binary_path, level="error")
    try:
        return _explore(ctx, p)
    finally:
        try:
            p.close()
        except Exception:
            pass


def _explore(ctx: PwnContext, p) -> InteractionModel | None:
    """Explore the binary's interaction model."""

    # Step 1: Get initial output
    try:
        initial = p.recv(timeout=RECV_TIMEOUT)
    except Exception:
        initial = b""

    if not initial:
        # Binary produces no output — just expects raw input.
        # This is likely a simple overflow target.
        return _make_simple_model()

    # Step 2: Analyze what the binary expects
    # Look for numeric prompts (e.g., "Input size:", "length:", "How many")
    numeric_prompt = _detect_numeric_prompt(initial)
    if numeric_prompt:
        # Program wants a number first — this is multi-step
        return _probe_numeric_prefix(ctx, p, initial, numeric_prompt)

    # Step 3: Check if this is a menu
    if _count_numbered_options(initial) >= 3:
        return None  # Let the menu handler deal with this

    # Step 4: Simple single-input model
    return _make_simple_model()


def _detect_numeric_prompt(data: bytes) -> dict | None:
    """Detect if the output is asking for a numeric input.

    Returns a dict with 'type' and 'match' if numeric prompt detected.
    """
    text = data.decode("utf-8", errors="replace").lower()

    # Patterns that suggest a numeric input is expected
    numeric_patterns = [
        # "Input the length:", "Enter size:", etc.
        (r'(?:input|enter|give|type|specify|set)\s*(?:the\s+)?'
         r'(?:length|size|number|count|amount|n|num)\s*[:>?]?\s*$',
         "length_prompt"),
        # "How many bytes?", "How long?"
        (r'how\s+(?:many|long|much)\s*[?:>]?\s*$', "how_many"),
        # "n = ", "size: ", "len: "
        (r'(?:^|\n)\s*(?:n|size|len|length|count|num)\s*[:=]\s*$',
         "var_prompt"),
        # "Please input N", Chinese prompts
        (r'(?:请输入|输入)\s*(?:长度|大小|数字|个数)', "chinese_prompt"),
        # Just ":" or ">" at end after short text
        (r'.{3,30}[:>]\s*$', "generic_prompt"),
    ]

    for pat, ptype in numeric_patterns:
        m = re.search(pat, text, re.MULTILINE)
        if m:
            return {"type": ptype, "match": m.group()}

    return None


def _probe_numeric_prefix(
    ctx: PwnContext, p, initial: bytes, prompt_info: dict
) -> InteractionModel | None:
    """When a numeric prompt is detected, probe with different values.

    Strategy:
    1. Send a small number (e.g., 5) — see if it then asks for more input
    2. Send a negative number (-1) — see if signed/unsigned confusion exists
    3. Send a large number — see if it creates a larger buffer
    """
    steps: list[InteractionStep] = []
    steps.append(InteractionStep(
        action="recv",
        pattern=initial[-40:] if len(initial) > 40 else initial,
        description=f"Initial prompt ({prompt_info['type']})",
    ))

    # Try negative number first (common CTF bypass for length check)
    for test_val in [b"-1", b"999", b"5"]:
        try:
            p2 = process(ctx.binary_path, level="error")
        except Exception:
            continue

        try:
            try:
                p2.recv(timeout=RECV_TIMEOUT)
            except Exception:
                pass

            p2.sendline(test_val)
            time.sleep(0.2)

            try:
                resp = p2.recv(timeout=1.0)
            except Exception:
                resp = b""

            if not resp:
                # No response after number — maybe it's now reading raw data.
                # Send a large payload and check for crash.
                crash_test = b"A" * 200
                try:
                    p2.send(crash_test)
                    time.sleep(0.3)
                    alive = p2.proc and p2.proc.poll() is None
                    if not alive:
                        # Crashed! This is a multi-step overflow.
                        model = InteractionModel()
                        model.steps = [
                            InteractionStep(
                                action="recv",
                                pattern=initial[-40:] if len(initial) > 40 else initial,
                                description="Initial prompt",
                            ),
                            InteractionStep(
                                action="sendline",
                                data=test_val,
                                description=f"Send numeric bypass ({test_val.decode()})",
                            ),
                            InteractionStep(
                                action="overflow",
                                description="Overflow after numeric input",
                            ),
                        ]
                        model.overflow_step_index = 2
                        model.confidence = 0.8
                        log.info(
                            f"交互探测: 发现多步交互 (数字输入={test_val.decode()}, "
                            f"然后溢出)"
                        )
                        return model
                except Exception:
                    pass

            elif resp:
                # Got a response — check if it's asking for more input
                numeric2 = _detect_numeric_prompt(resp)
                if not numeric2:
                    # It printed something else — might be asking for string data
                    # Send overflow test
                    crash_test = b"A" * 200
                    try:
                        p2.sendline(crash_test)
                        time.sleep(0.3)
                        alive = p2.proc and p2.proc.poll() is None
                        if not alive:
                            model = InteractionModel()
                            model.steps = [
                                InteractionStep(
                                    action="recv",
                                    pattern=initial[-40:] if len(initial) > 40 else initial,
                                    description="Initial prompt",
                                ),
                                InteractionStep(
                                    action="sendline",
                                    data=test_val,
                                    description=f"Send numeric input ({test_val.decode()})",
                                ),
                                InteractionStep(
                                    action="recv",
                                    pattern=resp[-40:] if len(resp) > 40 else resp,
                                    description="Second prompt",
                                ),
                                InteractionStep(
                                    action="overflow",
                                    description="Overflow at second input",
                                ),
                            ]
                            model.overflow_step_index = 3
                            model.confidence = 0.7
                            return model
                    except Exception:
                        pass
        finally:
            try:
                p2.close()
            except Exception:
                pass

    return None


def _count_numbered_options(data: bytes) -> int:
    """Count how many numbered menu options appear in the output."""
    text = data.decode("utf-8", errors="replace")
    return len(re.findall(r"\d+\s*[.):]\s*\w+", text))


def _make_simple_model() -> InteractionModel:
    """Create a simple single-step overflow model."""
    model = InteractionModel()
    model.steps = [InteractionStep(action="overflow")]
    model.overflow_step_index = 0
    model.confidence = 0.5
    return model


def execute_prefix(io, model: InteractionModel) -> bool:
    """Execute all interaction steps before the overflow.

    Returns True if all prefix steps completed successfully.
    """
    for step in model.prefix_steps:
        try:
            if step.action == "recv":
                io.recv(timeout=RECV_TIMEOUT)
            elif step.action == "sendline":
                io.sendline(step.data)
                time.sleep(0.15)
            elif step.action == "send":
                io.send(step.data)
                time.sleep(0.15)
        except Exception as exc:
            log.debug(f"interaction prefix step failed: {step.action} — {exc}")
            return False
    return True
