from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pwn import log

from autopwn.config import INPUT_FUNC_NAMES, FORMAT_FUNCS, HEAP_FREE_FUNCS

if TYPE_CHECKING:
    from autopwn.context import PwnContext


@dataclass
class TaintSource:
    func: str = ""
    addr: int = 0
    buffer_var: str = ""
    max_size: int = 0
    in_function: str = ""


@dataclass
class TaintSink:
    sink_type: str = ""  # ret_addr / fmt_arg / free_arg / memcpy_size / array_index
    func: str = ""
    addr: int = 0
    in_function: str = ""


@dataclass
class TaintFlow:
    source: TaintSource = field(default_factory=TaintSource)
    sink: TaintSink = field(default_factory=TaintSink)
    path: list[int] = field(default_factory=list)
    transforms: list[str] = field(default_factory=list)
    constraints: list[Any] = field(default_factory=list)
    confidence: str = "suspected"


class TaintEngine:
    """基于angr的污点分析引擎。"""

    def __init__(self, ctx: PwnContext):
        self.ctx = ctx
        self.sources: list[TaintSource] = []
        self.sinks: list[TaintSink] = []
        self.flows: list[TaintFlow] = []
        self.proj = None
        self.cfg = None

    def run(self) -> list[TaintFlow]:
        """执行完整的污点分析流程。"""
        try:
            import angr
            self.proj = angr.Project(self.ctx.binary_path, auto_load_libs=False)
            self.cfg = self.ctx.cfg
            if self.cfg is None:
                self.cfg = self.proj.analyses.CFGFast()
        except ImportError:
            log.warning("angr未安装，跳过污点分析")
            return []
        except Exception as e:
            log.warning(f"加载失败: {e}")
            return []

        self.identify_sources()
        self.identify_sinks()
        self.analyze_flows()

        self.ctx.taint_flows = self.flows
        log.info(f"污点分析: {len(self.sources)} 源, {len(self.sinks)} 汇, {len(self.flows)} 流")
        return self.flows

    def identify_sources(self) -> None:
        """识别所有输入源。"""
        if not self.cfg:
            return

        for func_addr, func in self.cfg.functions.items():
            if func.is_plt or func.is_simprocedure:
                continue

            for block in func.blocks:
                try:
                    vex = self.proj.factory.block(block.addr)
                    for insn in vex.capstone.insns:
                        if insn.mnemonic == "call":
                            target_name = self._resolve_call_name(insn.address)
                            if target_name in INPUT_FUNC_NAMES:
                                source = TaintSource(
                                    func=target_name,
                                    addr=insn.address,
                                    in_function=func.name,
                                )

                                if target_name in ("read", "fread", "recv"):
                                    source.max_size = self._extract_read_size(func, insn.address)
                                elif target_name == "gets":
                                    source.max_size = 0xffffffff  # 无限制
                                elif target_name in ("fgets", "scanf"):
                                    source.max_size = self._extract_read_size(func, insn.address)

                                self.sources.append(source)
                except Exception:
                    pass

    def identify_sinks(self) -> None:
        """识别所有危险汇点。"""
        if not self.cfg:
            return

        for func_addr, func in self.cfg.functions.items():
            if func.is_plt or func.is_simprocedure:
                continue

            # 每个函数的返回地址都是potential sink
            sink = TaintSink(
                sink_type="ret_addr",
                func="return",
                addr=func_addr,
                in_function=func.name,
            )
            self.sinks.append(sink)

            for block in func.blocks:
                try:
                    vex = self.proj.factory.block(block.addr)
                    for insn in vex.capstone.insns:
                        if insn.mnemonic == "call":
                            target_name = self._resolve_call_name(insn.address)

                            if target_name in FORMAT_FUNCS:
                                self.sinks.append(TaintSink(
                                    sink_type="fmt_arg",
                                    func=target_name,
                                    addr=insn.address,
                                    in_function=func.name,
                                ))

                            if target_name in HEAP_FREE_FUNCS:
                                self.sinks.append(TaintSink(
                                    sink_type="free_arg",
                                    func=target_name,
                                    addr=insn.address,
                                    in_function=func.name,
                                ))

                            if target_name == "system":
                                self.sinks.append(TaintSink(
                                    sink_type="system_arg",
                                    func=target_name,
                                    addr=insn.address,
                                    in_function=func.name,
                                ))
                except Exception:
                    pass

    def analyze_flows(self) -> None:
        """分析source到sink的数据流（简化版）。

        通过函数内的调用关系和栈布局推导。
        """
        for source in self.sources:
            for sink in self.sinks:
                if source.in_function == sink.in_function:
                    flow = self._check_intra_flow(source, sink)
                    if flow:
                        self.flows.append(flow)
                else:
                    flow = self._check_inter_flow(source, sink)
                    if flow:
                        self.flows.append(flow)

    def _check_intra_flow(self, source: TaintSource, sink: TaintSink) -> TaintFlow | None:
        """检查同一函数内的污点流。"""
        # source在sink之前 → 数据可能流向sink
        if source.addr >= sink.addr and sink.sink_type != "ret_addr":
            return None

        # 最常见的情况: read/gets → 栈溢出到返回地址
        if sink.sink_type == "ret_addr" and source.func in ("gets", "read", "scanf", "fgets"):
            # 需要检查缓冲区是否在栈上且可以溢出到ret addr
            flow = TaintFlow(
                source=source,
                sink=sink,
                confidence="suspected",
            )

            if source.func == "gets":
                flow.confidence = "confirmed_static"
                flow.transforms.append("gets: 无长度限制")
            elif source.max_size > 0:
                # 需要比较缓冲区大小和读取大小
                flow.transforms.append(f"max_read={source.max_size}")

            return flow

        # 格式化字符串: 用户输入作为printf的格式参数
        if sink.sink_type == "fmt_arg":
            flow = TaintFlow(
                source=source,
                sink=sink,
                confidence="suspected",
            )
            return flow

        return None

    def _check_inter_flow(self, source: TaintSource, sink: TaintSink) -> TaintFlow | None:
        """检查跨函数的污点流（通过调用图）。"""
        if not self.ctx.callgraph:
            return None

        callgraph = self.ctx.callgraph
        from autopwn.analysis.cfg_builder import find_path_to_function

        path = find_path_to_function(callgraph, source.in_function, sink.in_function)
        if path:
            return TaintFlow(
                source=source,
                sink=sink,
                confidence="suspected",
                transforms=[f"跨函数: {' → '.join(path)}"],
            )
        return None

    def _resolve_call_name(self, addr: int) -> str:
        """解析调用指令的目标函数名。"""
        if not self.cfg:
            return ""
        try:
            node = self.cfg.get_any_node(addr)
            if node:
                for succ in node.successors:
                    func = self.proj.kb.functions.get(succ.addr)
                    if func:
                        return func.demangled_name or func.name
        except Exception:
            pass

        # 从反汇编中解析
        try:
            block = self.proj.factory.block(addr)
            for insn in block.capstone.insns:
                if insn.address == addr and insn.mnemonic == "call":
                    op = insn.op_str
                    if "<" in op and ">" in op:
                        return op.split("<")[1].split(">")[0].strip()
        except Exception:
            pass

        return ""

    def _extract_read_size(self, func, call_addr: int) -> int:
        """尝试提取read调用的size参数。"""
        try:
            block = self.proj.factory.block(call_addr)
            for insn in block.capstone.insns:
                if insn.address < call_addr:
                    # 查找 mov rdx, IMM (read的第三个参数)
                    if "rdx" in insn.op_str or "edx" in insn.op_str:
                        parts = insn.op_str.split(",")
                        if len(parts) == 2:
                            try:
                                return int(parts[1].strip(), 0)
                            except ValueError:
                                pass
        except Exception:
            pass
        return 0
