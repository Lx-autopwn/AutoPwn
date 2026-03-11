from __future__ import annotations

import re
import subprocess
import sys
import time
from typing import Any

from pwn import ELF, context as pwn_context, log

from autopwn.config import RECV_TIMEOUT
from autopwn.context import PwnContext


def _check_free_null_pattern(lines: list[str], bits: int = 64) -> tuple[int, int]:
    """Check if free() calls in a function are followed by NULL assignment.

    On 64-bit, only movq $0x0 counts as pointer null (movl $0x0 is likely
    a flag clear, not pointer null).  On 32-bit, movl $0x0 counts.

    Returns (free_without_null, free_with_null) counts.
    """
    free_without_null = 0
    free_with_null = 0

    # On 64-bit: only 64-bit stores (movq) count as pointer null.
    # movl $0x0 on 64-bit typically zeros a flag/int, not a pointer.
    if bits == 64:
        null_pattern = re.compile(r"movq\s+\$0x0,")
    else:
        null_pattern = re.compile(r"mov[ql]?\s+\$0x0,")

    for i, line in enumerate(lines):
        if "call" in line and ("free@plt" in line or "<free>" in line):
            # Check next 5 instructions for null pointer assignment
            has_null = False
            for j in range(i + 1, min(i + 6, len(lines))):
                if null_pattern.search(lines[j]):
                    has_null = True
                    break
                # Another function call means we've left the free handler
                if "call" in lines[j]:
                    break
            if has_null:
                free_with_null += 1
            else:
                free_without_null += 1

    return free_without_null, free_with_null


def _check_heap_overflow_pattern(disasm: str, ctx: Any) -> bool:
    """Detect heap overflow by checking if non-alloc handlers have user-controlled write size.

    Pattern: a function that does NOT call malloc/calloc but DOES call:
    - atoi/strtol/scanf 2+ times (once for index, once for user-controlled size)
    - read/fgets (to write data into the chunk)

    This distinguishes normal edit (uses stored size) from overflow-prone edit
    (lets user specify how much to write).
    """
    # Parse functions from disasm
    functions: list[tuple[str, list[str]]] = []
    current_name = ""
    current_lines: list[str] = []
    for line in disasm.splitlines():
        m = re.match(r"[0-9a-f]+ <(\w+)>:", line)
        if m:
            if current_name:
                functions.append((current_name, current_lines))
            current_name = m.group(1)
            current_lines = []
            continue
        current_lines.append(line)
    if current_name:
        functions.append((current_name, current_lines))

    # Analyze each function
    for func_name, lines in functions:
        plt_calls: dict[str, int] = {}
        for line in lines:
            m = re.search(r"call\s+[0-9a-f]+\s+<(\w+)@plt>", line)
            if m:
                name = m.group(1)
                plt_calls[name] = plt_calls.get(name, 0) + 1

        # Skip alloc handlers (have malloc/calloc)
        if "malloc" in plt_calls or "calloc" in plt_calls:
            continue

        # Skip functions without read/write capability
        has_write = "read" in plt_calls or "fgets" in plt_calls
        if not has_write:
            continue

        # Count number-input calls (atoi, strtol, strtoul, scanf variants)
        num_input_count = sum(
            plt_calls.get(fn, 0) for fn in ("atoi", "strtol", "strtoul", "atol",
                                              "__isoc99_scanf", "__isoc23_scanf",
                                              "scanf", "sscanf")
        )

        # If 2+ number inputs + write → user controls both index and size
        if num_input_count >= 2:
            return True

    return False


class Engine:
    """AutoPwn v2 主编排引擎。

    6阶段流程:
    Phase 0: 加载目标
    Phase 1: 快速侦察
    Phase 2: 白盒分析
    Phase 3: 动态验证
    Phase 4: 利用路径合成
    Phase 5: 逐路径执行
    """

    def __init__(self, binary_path: str, libc_path: str | None = None,
                 remote: str | None = None, analyze_only: bool = False,
                 glibc_version: str | None = None, forced_strategy: str | None = None,
                 gen_script: bool = False, blackbox: bool = False,
                 batch: bool = False):
        self.binary_path = binary_path
        self.libc_path = libc_path
        self.remote = remote
        self.analyze_only = analyze_only
        self.forced_strategy = forced_strategy
        self.gen_script = gen_script
        self.blackbox = blackbox
        self.batch = batch

        self.ctx = PwnContext(binary_path=binary_path)
        self.ctx._gen_script = gen_script
        if glibc_version:
            self.ctx.glibc_version = glibc_version

    def run(self) -> int:
        """执行完整的分析和利用流程。"""
        start = time.time()

        try:
            self._phase0_load()
            self._phase1_recon()

            if not self.blackbox:
                self._phase2_whitebox()

            self._phase3_dynamic()
            self._phase4_synthesize()

            # 打印报告
            from autopwn.output.report import print_full_report
            print_full_report(self.ctx)

            if self.analyze_only:
                elapsed = time.time() - start
                log.info(f"分析完成 ({elapsed:.1f}s)")
                return 0

            # Phase 5: 执行利用
            result = self._phase5_exploit()

            elapsed = time.time() - start
            if result:
                log.success(f"利用成功！({elapsed:.1f}s)")
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

    def _phase0_load(self) -> None:
        """Phase 0: 加载目标二进制。"""
        log.info("Phase 0: 加载目标")

        elf = ELF(self.binary_path, checksec=False)
        self.ctx.elf = elf
        self.ctx.arch = elf.arch
        self.ctx.bits = elf.bits
        self.ctx.endian = elf.endian

        pwn_context.binary = elf
        pwn_context.arch = elf.arch
        pwn_context.bits = elf.bits

        if self.libc_path:
            try:
                self.ctx.libc = ELF(self.libc_path, checksec=False)
                log.info(f"Libc: {self.libc_path}")
            except Exception as e:
                log.warning(f"加载libc失败: {e}")

        # Detect if binary requires files to function.  Run it briefly
        # and check if it exits immediately with an error about missing files.
        self._ensure_required_files(elf)

    @staticmethod
    def _ensure_required_files(elf: ELF) -> None:
        """Detect and create files the binary needs to reach its vulnerable code.

        Approach: run the binary briefly.  If it exits immediately (< 1s)
        without waiting for input, inspect its output for file-related error
        messages.  Parse the filename and create a dummy.

        This is more principled than blind string matching: we let the binary
        itself tell us what file it needs, based on its actual runtime behavior.
        """
        import re
        import subprocess
        from pathlib import Path

        binary_dir = Path(elf.path).parent
        try:
            result = subprocess.run(
                [elf.path],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=2,
            )
        except (subprocess.TimeoutExpired, PermissionError, FileNotFoundError):
            return  # binary is waiting for input or can't run → no missing file issue

        # Binary exited quickly — check if output mentions a missing file
        output = (result.stdout + result.stderr).decode("utf-8", errors="replace")

        # Look for common CTF error patterns about missing files
        # e.g. "Loading 'flag.txt' failed", "Cannot open flag.txt",
        #      "No such file: key.txt", "fopen: flag.txt"
        file_patterns = re.findall(
            r"""(?:load|open|read|fopen|access|找不到|failed|error|cannot|no such)[^"']*['"]([^"']+\.(?:txt|dat|key|flag|bin|conf))['"]"""
            r"""|['"]([^"']+\.(?:txt|dat|key|flag|bin|conf))['"][^"']*(?:fail|not found|missing|error|无法)""",
            output, re.IGNORECASE,
        )

        for groups in file_patterns:
            filename = groups[0] or groups[1]
            if not filename:
                continue
            fpath = binary_dir / filename
            if not fpath.exists():
                fpath.write_text("flag{PLACEHOLDER_FOR_TESTING}\n")
                log.info(f"Binary needs \"{filename}\" (detected from error output); "
                         f"created dummy: {fpath}")
                return  # usually only one file needed

    def _phase1_recon(self) -> None:
        """Phase 1: 快速静态侦察。"""
        log.info("Phase 1: 快速侦察")

        from autopwn.recon.checksec import run_checksec
        from autopwn.recon.functions import identify_functions
        from autopwn.recon.strings import extract_strings
        from autopwn.recon.gadgets import search_gadgets
        from autopwn.recon.got_plt import analyze_got_plt
        from autopwn.recon.seccomp import analyze_seccomp

        run_checksec(self.ctx)
        identify_functions(self.ctx)
        extract_strings(self.ctx)
        analyze_got_plt(self.ctx)
        search_gadgets(self.ctx)
        analyze_seccomp(self.ctx)

        # r2 function-level analysis (input sizes, transforms, call sequences)
        try:
            from autopwn.recon.r2_analyzer import R2Analyzer
            r2a = R2Analyzer(self.ctx.binary_path)
            self.ctx.r2_profile = r2a.analyze()
            # Propagate r2's input_max_size to ctx.input_limit if not yet set
            r2p = self.ctx.r2_profile
            if r2p and r2p.input_max_size > 0 and not self.ctx.input_limit:
                effective = r2p.input_max_size
                if r2p.has_data_transform and r2p.transform_expansion > 1:
                    effective *= r2p.transform_expansion
                self.ctx.input_limit = effective
                log.info(f"r2 → input_limit={effective}")
        except Exception as e:
            log.debug(f"r2 analysis skipped: {e}")

    def _phase2_whitebox(self) -> None:
        """Phase 2: 白盒程序分析。"""
        log.info("Phase 2: 白盒分析")

        try:
            import angr  # noqa: F401
        except ImportError:
            log.warning("angr未安装，跳过白盒分析")
            return

        # Skip heavy angr analysis for static binaries (too many functions,
        # angr takes 10+ minutes).  Recon gadgets already cover what we need.
        if self.ctx.elf and self.ctx.elf.statically_linked:
            log.info("静态链接binary，跳过angr白盒分析（gadgets已在Phase 1提取）")
            # Still run lightweight pattern matching and vuln detection
            try:
                from autopwn.analysis.vuln_finder import find_vulnerabilities
                find_vulnerabilities(self.ctx)
            except Exception:
                pass
            try:
                from autopwn.analysis.exploit_primitive import extract_primitives
                extract_primitives(self.ctx)
            except Exception:
                pass
            return

        # 2a. 反编译
        from autopwn.analysis.decompiler import decompile_all
        decompile_all(self.ctx)

        # 2b. 控制流图 + 调用图
        from autopwn.analysis.cfg_builder import build_cfg, build_callgraph
        build_cfg(self.ctx)
        build_callgraph(self.ctx)

        # 2c-2d. 污点分析
        from autopwn.analysis.taint import TaintEngine
        taint = TaintEngine(self.ctx)
        taint.run()

        # 2e. 数据流分析
        from autopwn.analysis.dataflow import analyze_dataflow, detect_uaf_pattern
        analyze_dataflow(self.ctx)
        detect_uaf_pattern(self.ctx)

        # 2f. 模式匹配 + 漏洞发现
        from autopwn.analysis.pattern_matcher import match_patterns
        match_patterns(self.ctx)

        from autopwn.analysis.vuln_finder import find_vulnerabilities
        find_vulnerabilities(self.ctx)

        # 2g. 利用原语提取
        from autopwn.analysis.exploit_primitive import extract_primitives
        extract_primitives(self.ctx)

    def _phase3_dynamic(self) -> None:
        """Phase 3: 动态验证。"""
        log.info("Phase 3: 动态验证")

        # 3a0. 程序行为分类（shellcode_runner / menu_program / simple_io）
        from autopwn.analysis.behavior import classify_behavior
        classify_behavior(self.ctx)

        # 3a. 交互协议探测
        from autopwn.dynamic.interaction import detect_interaction
        detect_interaction(self.ctx)

        # 3b. 溢出偏移探测（如果白盒分析没有确定）
        if self.ctx.overflow_offset < 0:
            # 检查是否有栈溢出漏洞
            has_bof = any(
                isinstance(v, dict) and v.get("type") == "stack_bof"
                for v in self.ctx.vulnerabilities
            )
            has_dangerous = bool(self.ctx.dangerous_funcs)
            # Skip overflow probing for menu programs (they need menu-aware interaction)
            is_menu = self.ctx.behavior == "menu_program" or self.ctx.input_type == "menu"
            # Skip overflow probing ONLY for looping format-string binaries
            # that have NO dangerous functions (read/gets/scanf etc.)
            # If dangerous funcs exist, there may be a stack overflow too
            fmt_loop_skip = (
                self.ctx.has_loop
                and self.ctx.vulnerabilities
                and all(
                    isinstance(v, dict) and v.get("type", "").startswith("fmt")
                    for v in self.ctx.vulnerabilities
                )
                and not has_bof
                and not has_dangerous
            )
            if not is_menu and (has_bof or has_dangerous or not self.ctx.vulnerabilities) and not fmt_loop_skip:
                from autopwn.dynamic.offset import find_overflow_offset
                find_overflow_offset(self.ctx)

        # Fallback: if overflow offset still not found, try static analysis
        if self.ctx.overflow_offset < 0:
            r2p = getattr(self.ctx, "r2_profile", None)
            if r2p and r2p.buf_stack_offset > 0:
                word = self.ctx.bits // 8
                static_off = r2p.buf_stack_offset + word
                log.info(f"溢出偏移 (r2 fallback): {static_off}")
                self.ctx.overflow_offset = static_off
            else:
                from autopwn.dynamic.offset import _static_offset_from_disasm
                static_off = _static_offset_from_disasm(self.ctx)
                if static_off >= 0:
                    log.info(f"溢出偏移 (static fallback): {static_off}")
                    self.ctx.overflow_offset = static_off

        # 3b2. Canary offset detection — always run when binary has canary
        if self.ctx.canary:
            from autopwn.dynamic.offset import find_canary_offset
            find_canary_offset(self.ctx)

        # 3c. 堆追踪（菜单程序）
        if self.ctx.input_type == "menu":
            from autopwn.dynamic.heap_tracer import trace_heap_ops
            try:
                trace_heap_ops(self.ctx, timeout=5)
            except Exception:
                pass

        # 3d. forking检测
        from autopwn.dynamic.constraint_prober import probe_forking
        probe_forking(self.ctx)

        # 3d1. strcmp gate detection — find strcmp(input, "constant") patterns
        # and set payload_prefix so exploit strategies include the bypass.
        self._detect_strcmp_gate()

        # 3d2. 多步交互探测
        # When the binary might have multi-step input (numeric prefix, etc.)
        # probe to discover the interaction model.
        if self.ctx.overflow_offset >= 0 and self.ctx.input_type != "menu":
            try:
                from autopwn.dynamic.interaction_prober import probe_interaction
                probe_interaction(self.ctx)
            except Exception as exc:
                log.debug(f"交互探测失败: {exc}")

        # 3e. 如果白盒没找到漏洞，尝试黑盒检测
        if not self.ctx.vulnerabilities:
            self._fallback_vuln_detect()

        # 3f. 堆漏洞轻量检测（即使白盒找到了其他漏洞，也检查堆）
        if not (self.ctx.has_uaf or self.ctx.has_double_free):
            self._detect_heap_vulns_lightweight()

        # 3g. 菜单映射转换和探测 (only for heap programs)
        has_heap = self.ctx.has_uaf or self.ctx.has_double_free or self.ctx.has_heap_overflow
        if self.ctx.input_type == "menu" and not self.ctx.menu_to_heap_map and has_heap:
            # First try converting already-parsed menu_map to heap_map format
            if self.ctx.menu_map:
                from autopwn.exploit.heap.menu_driver import _convert_raw_menu
                converted = _convert_raw_menu(self.ctx.menu_map)
                if converted:
                    self.ctx.menu_to_heap_map = converted
                    log.info(f"菜单映射转换: {list(converted.keys())}")

            # If still empty, run dynamic probe
            if not self.ctx.menu_to_heap_map:
                self._probe_menu_structure()

    def _detect_strcmp_gate(self) -> None:
        """Detect strcmp(input, "constant") gates and set payload_prefix.

        When a binary does: gets(buf) → strcmp(buf, "key") → if equal proceed
        the overflow payload must start with "key\\x00" for the function to
        return normally (instead of calling exit).  Generalizable to any
        binary with a strcmp/strncmp validation before a vulnerable return.
        """
        ctx = self.ctx
        if ctx.payload_prefix:
            return  # already set
        if not ctx.elf:
            return

        try:
            result = subprocess.run(
                ["objdump", "-d", ctx.binary_path],
                capture_output=True, text=True, timeout=10,
            )
            disasm = result.stdout
        except Exception:
            return

        for line_idx, line in enumerate(disasm.splitlines()):
            if 'call' not in line or 'strcmp' not in line:
                continue
            lines = disasm.splitlines()
            # Look backward for string address arguments
            for j in range(max(0, line_idx - 5), line_idx):
                prev = lines[j]
                addrs_to_try = []

                # objdump comment with computed RIP-relative address
                if '%rip' in prev or '%eip' in prev:
                    m_comment = re.search(r'#\s*([0-9a-f]+)\b', prev)
                    if m_comment:
                        addrs_to_try.append(int(m_comment.group(1), 16))

                # Absolute address / push immediate
                m = re.search(r'(?:lea|mov).*?(0x[0-9a-f]+).*%[re][ds]i', prev, re.I)
                if not m:
                    m = re.search(r'push\s+\$(0x[0-9a-f]+)', prev, re.I)
                if m:
                    addrs_to_try.append(int(m.group(1), 16))

                for str_addr in addrs_to_try:
                    try:
                        s = ctx.elf.string(str_addr)
                        if s and 1 < len(s) < 64 and s.isascii():
                            ctx.payload_prefix = s + b"\x00"
                            log.info(f"strcmp gate: payload_prefix = {s!r}")
                            return
                    except Exception:
                        pass

    def _fallback_vuln_detect(self) -> None:
        """降级漏洞检测（无白盒时）。"""
        vulns = []

        # 根据危险函数推断
        for func in self.ctx.dangerous_funcs:
            name = func.get("name", "")
            if name == "gets":
                vulns.append({"type": "stack_bof", "confidence": "confirmed_static",
                              "function": "(unknown)", "description": "gets()无限制读取"})
            elif name in ("strcpy", "strcat", "sprintf"):
                vulns.append({"type": "stack_bof", "confidence": "suspected",
                              "function": "(unknown)", "description": f"{name}()可能溢出"})

        # 如果有溢出偏移则确认栈溢出
        if self.ctx.overflow_offset >= 0:
            already_has_bof = any(v.get("type") == "stack_bof" for v in vulns)
            if not already_has_bof:
                vulns.append({"type": "stack_bof", "confidence": "confirmed_dynamic",
                              "function": "(unknown)",
                              "description": f"动态验证溢出偏移={self.ctx.overflow_offset}"})

        self.ctx.vulnerabilities.extend(vulns)

        # 重新提取原语
        if vulns:
            from autopwn.analysis.exploit_primitive import extract_primitives
            extract_primitives(self.ctx)

    def _detect_heap_vulns_lightweight(self) -> None:
        """Detect heap vulnerabilities from disassembly when angr fails.

        Heuristics:
        - If binary has free@plt and is a menu program → likely UAF or double-free
        - If binary has malloc+free but the free handler doesn't null the pointer
          (detected from disassembly: no mov $0x0 after free call) → has_uaf
        - If the binary name or strings suggest specific heap attacks → set flags
        """
        ctx = self.ctx
        if ctx.has_uaf or ctx.has_double_free or ctx.has_heap_overflow:
            return  # Already detected by angr

        if ctx.behavior != "menu_program" and ctx.input_type != "menu":
            return  # Only relevant for menu programs

        elf = ctx.elf
        if not elf:
            return

        has_free = "free" in (elf.plt or {})
        has_alloc = "malloc" in (elf.plt or {}) or "calloc" in (elf.plt or {})
        if not (has_free and has_alloc):
            return

        log.info("轻量堆漏洞检测: 二进制有malloc+free，检查UAF/double-free模式...")

        try:
            result = subprocess.run(
                ["objdump", "-d", ctx.binary_path],
                capture_output=True, timeout=10,
            )
            disasm = result.stdout.decode("utf-8", errors="replace")
        except Exception:
            return

        # Check for UAF pattern: free() call without NULL assignment after
        bits = ctx.bits or 64
        free_without_null = 0
        free_with_null = 0

        func_lines: list[str] = []
        for line in disasm.splitlines():
            m = re.match(r"[0-9a-f]+ <(\w+)>:", line)
            if m:
                if func_lines:
                    f_no_null, f_null = _check_free_null_pattern(func_lines, bits)
                    free_without_null += f_no_null
                    free_with_null += f_null
                func_lines = []
                continue
            func_lines.append(line)
        if func_lines:
            f_no_null, f_null = _check_free_null_pattern(func_lines, bits)
            free_without_null += f_no_null
            free_with_null += f_null

        if free_without_null > 0:
            ctx.has_uaf = True
            log.info(f"轻量检测: {free_without_null} 个free()调用后未清零指针 → UAF")
            ctx.vulnerabilities.append({
                "type": "heap_uaf",
                "confidence": "suspected_static",
                "function": "(unknown)",
                "description": f"free()后指针未清零 ({free_without_null}处)",
            })

        # Check for heap overflow: edit handler has user-controlled write size
        # Pattern: a non-alloc handler function calls atoi/scanf 2+ times
        # (once for index, once for size) AND read/fgets (to write data)
        if not ctx.has_heap_overflow:
            ctx.has_heap_overflow = _check_heap_overflow_pattern(disasm, ctx)
            if ctx.has_heap_overflow:
                log.info("轻量检测: edit handler接受用户输入的写入长度 → 堆溢出")
                ctx.vulnerabilities.append({
                    "type": "heap_overflow",
                    "confidence": "suspected_static",
                    "function": "(unknown)",
                    "description": "edit操作允许用户控制写入长度",
                })

        # Also set has_double_free if free is called and name/strings suggest it
        binary_name = ctx.binary_path.lower()
        if any(kw in binary_name for kw in ["fast", "double", "tcache"]):
            ctx.has_double_free = True
            log.info("轻量检测: 二进制名称暗示double-free")

        # If binary has free but no null after, also suspect double-free
        if free_without_null > 0 and not ctx.has_double_free:
            ctx.has_double_free = True

    def _probe_menu_structure(self) -> None:
        """Probe menu binary to determine operation mapping dynamically."""
        from autopwn.dynamic.menu_probe import probe_menu
        try:
            heap_map = probe_menu(self.ctx)
            if heap_map:
                self.ctx.menu_to_heap_map = heap_map
        except Exception as e:
            log.debug(f"菜单探测异常: {e}")

    def _phase4_synthesize(self) -> None:
        """Phase 4: 利用路径合成。"""
        log.info("Phase 4: 利用路径合成")

        from autopwn.engine.path_synthesizer import synthesize_paths
        from autopwn.engine.planner import generate_plans

        synthesize_paths(self.ctx)
        generate_plans(self.ctx)

    def _phase5_exploit(self) -> bool:
        """Phase 5: 逐策略执行利用。"""
        log.info("Phase 5: 执行利用")

        from autopwn.exploit.base import get_strategies
        from autopwn.engine.scorer import rank_strategies

        strategies = get_strategies()

        if self.forced_strategy:
            strategies = [s for s in strategies
                          if s.name == self.forced_strategy or
                          type(s).__name__.lower().replace("exploit", "") == self.forced_strategy]
            if not strategies:
                log.failure(f"策略 {self.forced_strategy} 未找到")
                return False

        # 实例化并过滤
        candidates = []
        for strategy_cls in strategies:
            try:
                instance = strategy_cls(self.ctx)
                result = instance.check()
                if result:
                    candidates.append(instance)
            except Exception as exc:
                log.debug(f"策略 {getattr(strategy_cls, 'name', '?')} check 异常: {exc}")

        if not candidates:
            log.failure("没有可用的利用策略")
            return False

        # 按评分排序
        ranked = rank_strategies(self.ctx, candidates)

        # 逐个执行
        for i, strategy in enumerate(ranked):
            name = getattr(strategy, "name", type(strategy).__name__)
            log.info(f"尝试策略 [{i + 1}/{len(ranked)}]: {name}")

            try:
                success = strategy.exploit(target=self.remote)
                if success:
                    self._last_strategy = strategy
                    return True
            except KeyboardInterrupt:
                raise
            except Exception as e:
                log.warning(f"策略 {name} 异常: {e}")

            log.info(f"策略 {name} 失败，尝试下一个")

        return False

    def _generate_script(self, strategy) -> None:
        """生成独立的exploit脚本。"""
        from autopwn.output.script_gen import save_exploit_script

        steps = []
        if hasattr(strategy, "get_exploit_steps"):
            steps = strategy.get_exploit_steps()

        save_exploit_script(self.ctx, exploit_steps=steps)

    def _generate_script_from_last(self) -> None:
        """生成上次成功策略的exploit脚本（供Agent调用）。"""
        strategy = getattr(self, "_last_strategy", None)
        if strategy:
            self._generate_script(strategy)
        else:
            from autopwn.output.script_gen import save_exploit_script
            save_exploit_script(self.ctx, exploit_steps=[])
