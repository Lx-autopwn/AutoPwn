from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from pwn import log

from autopwn.config import GDB_TIMEOUT

if TYPE_CHECKING:
    from autopwn.context import PwnContext


@dataclass
class CrashInfo:
    signal: str = ""
    signal_num: int = 0
    fault_addr: int = 0
    rip: int = 0
    rsp: int = 0
    rbp: int = 0
    registers: dict[str, int] = None
    crash_type: str = "unknown"
    description: str = ""

    def __post_init__(self):
        if self.registers is None:
            self.registers = {}


def triage_crash(ctx: PwnContext, payload: bytes) -> CrashInfo:
    """发送payload到程序，用GDB分析crash类型。"""
    info = CrashInfo()

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as pf:
        pf.write(payload)
        payload_file = pf.name

    gdb_script = """
set pagination off
set confirm off
set disable-randomization on
run < {payload_file}
if $_siginfo
  printf "SIGNAL:%d\\n", $_siginfo.si_signo
  printf "ADDR:0x%lx\\n", $_siginfo.si_addr
  info registers
end
quit
""".format(payload_file=payload_file)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as sf:
        sf.write(gdb_script)
        script_file = sf.name

    try:
        result = subprocess.run(
            ["gdb", "-batch", "-nx", "-x", script_file, ctx.binary_path],
            capture_output=True, text=True, timeout=GDB_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
        output = result.stdout + result.stderr
        info = _parse_gdb_output(output, ctx)
    except subprocess.TimeoutExpired:
        info.crash_type = "timeout"
        info.description = "程序超时（可能等待输入或死循环）"
    except FileNotFoundError:
        log.warning("GDB未安装")
    finally:
        Path(payload_file).unlink(missing_ok=True)
        Path(script_file).unlink(missing_ok=True)

    return info


def _parse_gdb_output(output: str, ctx: PwnContext) -> CrashInfo:
    """解析GDB输出。"""
    info = CrashInfo()

    for line in output.splitlines():
        line = line.strip()

        if line.startswith("SIGNAL:"):
            try:
                info.signal_num = int(line.split(":")[1])
                _signum_to_name = {4: "SIGILL", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 11: "SIGSEGV"}
                info.signal = _signum_to_name.get(info.signal_num, f"SIG{info.signal_num}")
            except ValueError:
                pass

        elif line.startswith("ADDR:"):
            try:
                info.fault_addr = int(line.split(":")[1], 16)
            except ValueError:
                pass

        elif any(line.startswith(r) for r in ["rip", "eip", "rsp", "esp", "rbp", "ebp",
                                                "rax", "rbx", "rcx", "rdx", "rsi", "rdi"]):
            parts = line.split()
            if len(parts) >= 2:
                reg_name = parts[0]
                for part in parts[1:]:
                    if part.startswith("0x"):
                        try:
                            val = int(part, 16)
                            info.registers[reg_name] = val
                            if reg_name in ("rip", "eip"):
                                info.rip = val
                            elif reg_name in ("rsp", "esp"):
                                info.rsp = val
                            elif reg_name in ("rbp", "ebp"):
                                info.rbp = val
                        except ValueError:
                            pass
                        break

        if "stack smashing" in line.lower():
            info.crash_type = "canary"
            info.description = "Stack canary被破坏"

        if "Program received signal" in line:
            if "SIGABRT" in line:
                info.signal = "SIGABRT"
            elif "SIGSEGV" in line:
                info.signal = "SIGSEGV"
            elif "SIGBUS" in line:
                info.signal = "SIGBUS"

    if info.crash_type == "unknown":
        info.crash_type, info.description = _classify_crash(info, ctx)

    return info


def _classify_crash(info: CrashInfo, ctx: PwnContext) -> tuple[str, str]:
    """分类crash类型。"""
    if info.signal == "SIGABRT":
        return "canary", "Stack canary检测到溢出（或abort调用）"

    if info.signal == "SIGSEGV":
        if info.fault_addr == 0:
            return "null_deref", "空指针解引用"

        rip = info.rip
        if rip and _is_pattern_value(rip):
            return "rip_control", f"RIP已被控制为 {rip:#x}（来自输入pattern）"

        if info.fault_addr and _is_pattern_value(info.fault_addr):
            return "mem_access", f"内存访问被控制 {info.fault_addr:#x}"

        rsp = info.rsp
        if rsp and (rsp & 0xf) != 0 and ctx.bits == 64:
            return "stack_misalign", "栈未对齐（x86_64要求16字节对齐，加ret gadget）"

        return "sigsegv", f"段错误 @ {info.fault_addr:#x}"

    if info.signal == "SIGBUS":
        return "sigbus", "总线错误（非法内存对齐）"

    if info.signal == "SIGILL":
        return "sigill", f"非法指令 @ {info.rip:#x}"

    return "unknown", f"未知crash: signal={info.signal}"


def _is_pattern_value(val: int) -> bool:
    """检查值是否可能来自cyclic pattern。"""
    byte_val = val & 0xff
    if 0x61 <= byte_val <= 0x7a:
        return True
    if val == 0x41414141 or val == 0x4141414141414141:
        return True
    return False


def diagnose_and_suggest(info: CrashInfo, ctx: PwnContext) -> list[str]:
    """基于crash信息给出修复建议。"""
    suggestions = []

    if info.crash_type == "canary":
        if ctx.is_forking:
            suggestions.append("forking server: 可以逐字节爆破canary")
        suggestions.append("需要先泄露canary值（格式化字符串或信息泄露）")

    elif info.crash_type == "stack_misalign":
        suggestions.append("在ROP链开头添加一个 ret gadget 进行栈对齐")

    elif info.crash_type == "rip_control":
        suggestions.append("RIP已被控制，确认覆盖地址是否正确")
        if ctx.pie:
            suggestions.append("PIE启用，需要泄露程序基址")

    elif info.crash_type == "null_deref":
        suggestions.append("空指针解引用，检查参数设置是否正确")

    return suggestions
