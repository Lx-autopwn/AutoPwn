"""PwnAgent — rule-based feedback loop that wraps the autopwn engine."""
from __future__ import annotations

import time
from typing import Any

from pwn import log

from autopwn.agent.state import AgentState
from autopwn.agent.observer import observe_all
from autopwn.agent.rules import ALL_RULES


class PwnAgent:
    """Wraps the Engine: runs Phase 0-5, then Agent loop on failure."""

    def __init__(self, binary_path: str, libc_path: str | None = None,
                 remote: str | None = None, analyze_only: bool = False,
                 glibc_version: str | None = None, forced_strategy: str | None = None,
                 gen_script: bool = False, blackbox: bool = False,
                 batch: bool = False, max_rounds: int = 15):
        from autopwn.engine.engine import Engine

        self.engine = Engine(
            binary_path=binary_path,
            libc_path=libc_path,
            remote=remote,
            analyze_only=analyze_only,
            glibc_version=glibc_version,
            forced_strategy=forced_strategy,
            gen_script=gen_script,
            blackbox=blackbox,
            batch=batch,
        )
        self.remote = remote
        self.max_rounds = max_rounds
        self.analyze_only = analyze_only

        # Parse rules from tuples into usable form
        self.rules = []
        for r in ALL_RULES:
            name, priority, description, condition, action = r
            self.rules.append({
                "name": name,
                "priority": priority,
                "description": description,
                "condition": condition,
                "action": action,
            })
        # Sort by priority descending (highest first)
        self.rules.sort(key=lambda r: r["priority"], reverse=True)

    def run(self) -> int:
        """Execute full pipeline + agent loop."""
        start = time.time()

        try:
            # ---- Phase 0-4: analysis (same as Engine) ----
            self.engine._phase0_load()
            self.engine._phase1_recon()
            if not self.engine.blackbox:
                self.engine._phase2_whitebox()
            self.engine._phase3_dynamic()
            self.engine._phase4_synthesize()

            # Print report
            from autopwn.output.report import print_full_report
            print_full_report(self.engine.ctx)

            if self.analyze_only:
                elapsed = time.time() - start
                log.info(f"分析完成 ({elapsed:.1f}s)")
                return 0

            # ---- Phase 5: standard exploit (same as Engine) ----
            result = self.engine._phase5_exploit()
            if result:
                elapsed = time.time() - start
                log.success(f"利用成功！({elapsed:.1f}s)")
                return 0

            # Collect which strategies were tried in Phase 5
            strategies_tried = self._collect_phase5_strategies()

            # ---- Phase 6: Agent loop ----
            log.info("Phase 6: Agent 反馈循环")

            state = AgentState(
                ctx=self.engine.ctx,
                max_rounds=self.max_rounds,
                phase5_strategies_tried=strategies_tried,
            )

            agent_result = self._agent_loop(state)

            elapsed = time.time() - start
            if agent_result:
                log.success(f"Agent 利用成功！({elapsed:.1f}s)")
                return 0
            else:
                log.failure(f"所有策略均失败 ({elapsed:.1f}s)")
                return 1

        except KeyboardInterrupt:
            log.warning("用户中断")
            return 130
        except Exception as e:
            log.failure(f"引擎错误: {e}")
            import traceback
            traceback.print_exc()
            return 1

    def _agent_loop(self, state: AgentState) -> bool:
        """Run the observe → decide → act → verify loop."""

        # Run observers once before the loop (analyze static info)
        observe_all(state)

        while state.round < state.max_rounds:
            state.round += 1

            # Decide: find the highest-priority triggerable rule
            rule = self._decide(state)
            if rule is None:
                log.info("Agent: 无可用规则，结束")
                break

            log.info(f"Agent [{state.round}/{state.max_rounds}]: "
                     f"规则 [{rule['name']}] - {rule['description']}")

            # Act
            try:
                result = rule["action"](state)
            except Exception as exc:
                log.warning(f"Agent: 规则 [{rule['name']}] 异常: {exc}")
                state.blocked_rules.add(rule["name"])
                continue

            # Record attempt
            state.attempts.append(result.record)

            # Verify
            if result.success:
                return True

            # Mark terminal rules as blocked
            if result.terminal:
                state.blocked_rules.add(rule["name"])

            # Re-observe after each attempt (may discover new facts)
            observe_all(state)

        return False

    def _decide(self, state: AgentState) -> dict | None:
        """Find the highest-priority rule whose condition is met."""
        for rule in self.rules:
            if rule["name"] in state.blocked_rules:
                continue
            try:
                if rule["condition"](state):
                    return rule
            except Exception:
                continue
        return None

    def _collect_phase5_strategies(self) -> list[str]:
        """Collect names of strategies that were attempted in Phase 5."""
        # We can infer this from the engine's context and registered strategies
        from autopwn.exploit.base import get_strategies
        tried = []
        for strategy_cls in get_strategies():
            try:
                instance = strategy_cls(self.engine.ctx)
                if instance.check():
                    tried.append(instance.name)
            except Exception:
                pass
        return tried
