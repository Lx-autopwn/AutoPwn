"""Lightweight radare2-based function-level analysis.

Extracts input call parameters (fgets size, read size), buffer stack offsets,
call sequences, and data-transform hints to inform exploit construction.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from pwn import log


@dataclass
class FuncCallInfo:
    """A single function call site with inferred arguments."""
    name: str          # "fgets", "read", "gets", etc.
    addr: int = 0      # call-site address
    args: list[Any] = field(default_factory=list)  # inferred argument values


@dataclass
class R2Profile:
    """Function-level analysis results from r2."""
    vuln_func: str = ""                           # most likely vulnerable function name
    input_calls: list[FuncCallInfo] = field(default_factory=list)
    input_max_size: int = 0                       # max single-input byte count (from fgets/read size)
    buf_stack_offset: int = 0                     # buffer offset relative to rbp (positive = below rbp)
    call_sequence: list[str] = field(default_factory=list)  # ordered call list in main
    has_data_transform: bool = False              # strcpy/strcat/replace detected
    transform_expansion: int = 1                  # max expansion multiplier (default 1x)
    num_input_calls: int = 0                      # total distinct input call sites


# Input functions whose size parameter we want to extract
_INPUT_FUNCS = {
    "read":            {"size_arg_idx": 2, "buf_arg_idx": 1},  # read(fd, buf, size)
    "fgets":           {"size_arg_idx": 1, "buf_arg_idx": 0},  # fgets(buf, size, stream)
    "fread":           {"size_arg_idx": 1, "buf_arg_idx": 0},  # fread(buf, size, nmemb, stream)
    "recv":            {"size_arg_idx": 2, "buf_arg_idx": 1},  # recv(fd, buf, size, flags)
}

# Functions that transform/expand data in buffers
_TRANSFORM_FUNCS = {
    "strcpy", "strncpy", "strcat", "strncat", "sprintf", "snprintf",
    "memcpy", "memmove",
}

# C++ string operations that may cause expansion (replace 1-char with multi-char)
_CPP_EXPAND_FUNCS = {
    "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7replaceEmmPKcm",
    "_ZNSs7replaceEmmPKcm",
    "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7replaceEmmPKc",
}

# Simpler pattern match for C++ replace in symbol names
_CPP_REPLACE_RE = re.compile(r"replace|append|insert|concat", re.IGNORECASE)


class R2Analyzer:
    """Use r2pipe for lightweight binary analysis."""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self._r2 = None

    def analyze(self) -> R2Profile:
        """Run analysis and return an R2Profile."""
        try:
            import r2pipe
        except ImportError:
            log.debug("r2pipe not available, skipping r2 analysis")
            return R2Profile()

        profile = R2Profile()
        try:
            self._r2 = r2pipe.open(self.binary_path, flags=["-2"])
            self._r2.cmd("aaa")  # full analysis
            self._r2.cmd("e asm.var = false")  # show raw offsets, not symbolic names

            self._extract_call_sequence(profile)
            self._extract_input_calls(profile)
            self._detect_transforms(profile)
            self._extract_buf_offset(profile)
            self._infer_vuln_func(profile)

        except Exception as e:
            log.debug(f"r2 analysis error: {e}")
        finally:
            if self._r2:
                try:
                    self._r2.quit()
                except Exception:
                    pass
                self._r2 = None

        if profile.input_max_size > 0:
            log.info(f"r2: input_max_size={profile.input_max_size}, "
                     f"buf_offset={profile.buf_stack_offset:#x}, "
                     f"transform={'yes' if profile.has_data_transform else 'no'}"
                     f"(x{profile.transform_expansion})")
        return profile

    def _extract_call_sequence(self, profile: R2Profile) -> None:
        """Extract the ordered list of function calls in main."""
        r2 = self._r2
        # Get main's disassembly as JSON
        try:
            main_info = r2.cmd("s main; pdf")
        except Exception:
            return

        calls = []
        for line in main_info.splitlines():
            # Match call instructions: "call sym.func" or "call sym.imp.func"
            m = re.search(r"call\s+(?:sym\.imp\.|sym\.|reloc\.)(\w+)", line)
            if m:
                calls.append(m.group(1))
                continue
            # Also match "call 0xaddr" with comment showing function name
            m2 = re.search(r"call.*;\s*(\w+)", line)
            if m2:
                name = m2.group(1)
                if name not in ("invalid", "section"):
                    calls.append(name)

        profile.call_sequence = calls

    def _extract_input_calls(self, profile: R2Profile) -> None:
        """Find all input function calls and infer their size arguments."""
        r2 = self._r2

        # Collect all functions to analyze: main + functions called by main
        funcs_to_check = self._get_analysis_funcs()

        all_input_calls = []
        for func_name in funcs_to_check:
            calls = self._analyze_func_inputs(func_name)
            all_input_calls.extend(calls)

        profile.input_calls = all_input_calls
        profile.num_input_calls = len(all_input_calls)

        # Determine max input size from collected calls
        max_size = 0
        for call in all_input_calls:
            if call.name in _INPUT_FUNCS:
                size_idx = _INPUT_FUNCS[call.name]["size_arg_idx"]
                if len(call.args) > size_idx and isinstance(call.args[size_idx], int):
                    sz = call.args[size_idx]
                    if 0 < sz < 0x10000:  # reasonable range
                        max_size = max(max_size, sz)
            elif call.name == "gets":
                # gets() has no size limit
                max_size = max(max_size, 0x10000)
            elif call.name in ("scanf", "__isoc99_scanf"):
                # scanf %s has no limit, %Ns has limit N
                for arg in call.args:
                    if isinstance(arg, str):
                        m = re.search(r"%(\d+)s", arg)
                        if m:
                            max_size = max(max_size, int(m.group(1)))

        profile.input_max_size = max_size

    def _get_analysis_funcs(self) -> list[str]:
        """Get list of functions to analyze (main + called functions)."""
        r2 = self._r2
        funcs = ["main"]

        try:
            # Get functions called by main using r2's cross-references
            refs_json = r2.cmd("s main; afij")
            if refs_json:
                info = json.loads(refs_json)
                if info and isinstance(info, list):
                    # Get callrefs from main
                    for fi in info:
                        callrefs = fi.get("callrefs", [])
                        for ref in callrefs:
                            if ref.get("type") == "CALL":
                                # Resolve the target function name
                                addr = ref.get("addr", 0)
                                name = r2.cmd(f"fd {addr}").strip()
                                if name:
                                    # Clean up: "sym.func" -> "func"
                                    clean = re.sub(r"^(sym\.imp\.|sym\.|reloc\.)", "", name)
                                    if clean and clean not in funcs:
                                        funcs.append(clean)
        except Exception:
            pass

        # Also try the simpler approach: parse pdf for call targets
        try:
            main_pdf = r2.cmd("s main; pdf")
            for line in main_pdf.splitlines():
                m = re.search(r"call\s+(?:sym\.imp\.|sym\.|reloc\.)(\w+)", line)
                if m:
                    name = m.group(1)
                    if name not in funcs:
                        funcs.append(name)
        except Exception:
            pass

        return funcs

    def _analyze_func_inputs(self, func_name: str) -> list[FuncCallInfo]:
        """Analyze a single function for input calls and their arguments."""
        r2 = self._r2
        results = []

        try:
            # Seek to function and get disassembly as JSON
            # asm.var=false ensures raw offsets (e.g. [esp + 4]) instead of
            # symbolic names (e.g. [size]) which break our regex matching
            r2.cmd(f"s sym.{func_name} 2>/dev/null || s sym.imp.{func_name} 2>/dev/null || s {func_name} 2>/dev/null")
            r2.cmd("e asm.var = false")
            ops_raw = r2.cmd("pdfj")
            if not ops_raw:
                return results
            ops_data = json.loads(ops_raw)
        except Exception:
            return results

        ops = ops_data.get("ops", [])
        if not ops:
            return results

        # Track register values set before calls (mov esi, N / mov edx, N etc.)
        reg_values: dict[str, int] = {}
        # Track stack pushes for 32-bit calling convention (right-to-left push order)
        stack_pushes: list[int | None] = []
        # Track mov dword [esp+offset], imm for 32-bit sub esp style
        stack_slots: dict[int, int] = {}  # offset -> value

        for i, op in enumerate(ops):
            optype = op.get("type", "")
            # Use 'opcode' for raw instruction (unaffected by r2 variable renaming),
            # fall back to 'disasm' for call resolution (has symbol names)
            raw_asm = op.get("opcode", "") or op.get("disasm", "")
            disasm = op.get("disasm", "")
            addr = op.get("offset", op.get("addr", 0))

            # Track mov reg, immediate (use raw_asm for reliable offset parsing)
            if optype == "mov" or ("mov" in raw_asm and "push" not in raw_asm):
                # Match: mov esi, 0x20 / mov edx, 0x100 / mov edi, 0
                m = re.match(r"mov\s+(e?[a-z]{2,3}|r[a-z0-9]{1,3}),\s*(0x[0-9a-f]+|\d+)", raw_asm)
                if m:
                    reg = m.group(1).lower()
                    try:
                        val = int(m.group(2), 0)
                        reg_values[reg] = val
                        # Map 32-bit regs to 64-bit equivalents
                        reg_map = {"edi": "rdi", "esi": "rsi", "edx": "rdx", "ecx": "rcx"}
                        if reg in reg_map:
                            reg_values[reg_map[reg]] = val
                    except ValueError:
                        pass

                # 32-bit: mov dword [esp + N], immediate
                # Maps to argument index = N / 4
                m2 = re.match(r"mov\s+dword\s+\[esp\s*(?:\+\s*(0x[0-9a-f]+|\d+))?\],\s*(0x[0-9a-f]+|\d+)", raw_asm)
                if m2:
                    try:
                        slot_off = int(m2.group(1), 0) if m2.group(1) else 0
                        val = int(m2.group(2), 0)
                        arg_idx = slot_off // 4  # cdecl: arg N at [esp + N*4]
                        stack_slots[arg_idx] = val
                    except ValueError:
                        pass

            # Track push instructions (32-bit calling convention)
            if optype == "push" or raw_asm.startswith("push "):
                m = re.match(r"push\s+(0x[0-9a-f]+|\d+)", raw_asm)
                if m:
                    try:
                        stack_pushes.append(int(m.group(1), 0))
                    except ValueError:
                        stack_pushes.append(None)
                else:
                    stack_pushes.append(None)  # register push, value unknown

            # Also track lea reg, [rbp - offset] for buffer addresses
            if "lea" in raw_asm:
                m = re.match(r"lea\s+(e?[a-z]{2,3}|r[a-z0-9]{1,3}),\s*\[(?:rbp|ebp)\s*-\s*(0x[0-9a-f]+|\d+)\]", raw_asm)
                if m:
                    reg = m.group(1).lower()
                    try:
                        offset = int(m.group(2), 0)
                        reg_values[reg] = -offset  # negative = below rbp
                        reg_map = {"edi": "rdi", "esi": "rsi", "edx": "rdx",
                                   "ecx": "rcx", "eax": "rax"}
                        if reg in reg_map:
                            reg_values[reg_map[reg]] = -offset
                    except ValueError:
                        pass

            # Detect calls to input functions
            if optype == "call" or "call" in disasm:
                called = op.get("jump", 0)
                # Get called function name
                call_name = ""
                m = re.search(r"call\s+(?:sym\.imp\.|sym\.|reloc\.)(\w+)", disasm)
                if m:
                    call_name = m.group(1)
                else:
                    # Try to resolve from address
                    if called:
                        resolved = r2.cmd(f"fd {called}").strip()
                        call_name = re.sub(r"^(sym\.imp\.|sym\.|reloc\.)", "", resolved)

                if not call_name:
                    reg_values.clear()
                    stack_pushes.clear()
                    stack_slots.clear()
                    continue

                # Check if this is an input function
                is_input = call_name in _INPUT_FUNCS or call_name in ("gets", "scanf", "__isoc99_scanf")
                if is_input:
                    args = self._infer_call_args(call_name, reg_values,
                                                 stack_pushes, stack_slots)
                    info = FuncCallInfo(name=call_name, addr=addr, args=args)
                    results.append(info)

                if is_input:
                    reg_values.clear()
                stack_pushes.clear()
                stack_slots.clear()

        return results

    def _infer_call_args(self, func_name: str, reg_values: dict[str, int],
                         stack_pushes: list[int | None] | None = None,
                         stack_slots: dict[int, int] | None = None) -> list[Any]:
        """Infer function call arguments from tracked register/stack values.

        64-bit: uses SysV ABI (rdi, rsi, rdx, rcx, r8, r9).
        32-bit: uses stack pushes (right-to-left) or mov [esp+N], val.
        """
        if func_name in _INPUT_FUNCS:
            info = _INPUT_FUNCS[func_name]
            max_arg = max(info["size_arg_idx"], info["buf_arg_idx"]) + 1
        elif func_name == "gets":
            max_arg = 1
        elif func_name in ("scanf", "__isoc99_scanf"):
            max_arg = 2
        else:
            max_arg = 3

        # Try 64-bit register-based args first
        arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        args = []
        has_reg_args = False

        for i in range(min(max_arg, len(arg_regs))):
            reg = arg_regs[i]
            if reg in reg_values:
                args.append(reg_values[reg])
                has_reg_args = True
            else:
                r32 = {"rdi": "edi", "rsi": "esi", "rdx": "edx", "rcx": "ecx"}.get(reg)
                if r32 and r32 in reg_values:
                    args.append(reg_values[r32])
                    has_reg_args = True
                else:
                    args.append(None)

        if has_reg_args:
            return args

        # 32-bit: try stack_slots (mov dword [esp+N], val)
        # Keys are argument indices (offset // 4)
        if stack_slots:
            args = [None] * max_arg
            for idx, val in stack_slots.items():
                if 0 <= idx < max_arg:
                    args[idx] = val
            return args

        # 32-bit: try push-based args (reversed, since pushes are right-to-left)
        if stack_pushes:
            reversed_pushes = list(reversed(stack_pushes))
            args = reversed_pushes[:max_arg]
            while len(args) < max_arg:
                args.append(None)
            return args

        return [None] * max_arg

    def _detect_transforms(self, profile: R2Profile) -> None:
        """Detect data-transforming functions (strcpy, strcat, C++ replace)."""
        r2 = self._r2

        try:
            # Get all imports/symbols
            imports_raw = r2.cmd("iij")
            if not imports_raw:
                imports_raw = "[]"
            imports = json.loads(imports_raw)
        except Exception:
            imports = []

        import_names = set()
        for imp in imports:
            name = imp.get("name", "")
            import_names.add(name)

        # Check for standard transform functions
        for tf in _TRANSFORM_FUNCS:
            if tf in import_names:
                profile.has_data_transform = True
                break

        # Check for C++ string replace (causes 'I' -> 'you' style expansion)
        for name in import_names:
            if any(cpp in name for cpp in _CPP_EXPAND_FUNCS):
                profile.has_data_transform = True
                profile.transform_expansion = 3  # common: 1 char -> 3 chars
                break
            if _CPP_REPLACE_RE.search(name):
                profile.has_data_transform = True
                if profile.transform_expansion < 2:
                    profile.transform_expansion = 2
                break

        # Scan disassembly for replace patterns and infer expansion ratio
        try:
            funcs = self._get_analysis_funcs()
            for fn in funcs:
                pdf = r2.cmd(f"s sym.{fn} 2>/dev/null; pdf 2>/dev/null")
                if not pdf:
                    continue
                if _CPP_REPLACE_RE.search(pdf):
                    profile.has_data_transform = True
                    # Try to infer expansion from string references
                    # Look for pairs of short strings near replace calls
                    # (needle, replacement) — e.g. "I" and "you"
                    strings_in_func = re.findall(r'; "([^"]{1,10})"', pdf)
                    if len(strings_in_func) >= 2:
                        # Check adjacent pairs of short strings (replace targets)
                        for j in range(len(strings_in_func) - 1):
                            s1 = strings_in_func[j]
                            s2 = strings_in_func[j + 1]
                            # Both must be short — replace("I", "you") style
                            if 0 < len(s1) <= 5 and 0 < len(s2) <= 5 and len(s1) != len(s2):
                                shorter = min(len(s1), len(s2))
                                longer = max(len(s1), len(s2))
                                ratio = longer // shorter
                                if 2 <= ratio <= 5 and ratio > profile.transform_expansion:
                                    profile.transform_expansion = ratio
                    if profile.transform_expansion < 2:
                        profile.transform_expansion = 2
                    break
        except Exception:
            pass

    def _extract_buf_offset(self, profile: R2Profile) -> None:
        """Extract the vulnerable buffer's stack offset from local variables."""
        r2 = self._r2

        # Determine which function to analyze
        target_func = "main"
        funcs = self._get_analysis_funcs()
        # Prefer non-main functions that have input calls
        for fn in funcs:
            if fn != "main" and fn not in ("__libc_start_main", "setvbuf",
                                            "printf", "puts", "exit"):
                target_func = fn
                break

        try:
            r2.cmd(f"s sym.{target_func} 2>/dev/null || s {target_func} 2>/dev/null")
            vars_raw = r2.cmd("afvj")
            if not vars_raw:
                return
            variables = json.loads(vars_raw)
        except Exception:
            return

        if not variables:
            return

        # Find the largest stack buffer (likely the overflow target)
        # Handle both list format and dict format from afvj
        var_list = variables
        if isinstance(variables, dict):
            # r2 returns {"bp": [...], "sp": [...], "reg": [...]}
            var_list = []
            for key in ("bp", "sp", "reg"):
                if key in variables:
                    var_list.extend(variables[key])

        best_offset = 0
        best_size = 0
        for var in var_list:
            if not isinstance(var, dict):
                continue
            # ref can be an int or a dict {"base": "rbp", "offset": -64}
            ref_raw = var.get("ref", 0)
            if isinstance(ref_raw, dict):
                ref = ref_raw.get("offset", 0)
            elif isinstance(ref_raw, (int, float)):
                ref = int(ref_raw)
            else:
                continue

            vtype = var.get("type", "")

            # Estimate size from type
            size = 0
            # Match array types like "char [32]" or "int [10]"
            arr_m = re.search(r"\[(\d+)\]", vtype)
            if arr_m:
                elem_count = int(arr_m.group(1))
                if "char" in vtype or "int8" in vtype:
                    size = elem_count
                elif "int" in vtype or "int32" in vtype:
                    size = elem_count * 4
                else:
                    size = elem_count

            # If no array type, use absolute offset as rough size
            if size == 0 and abs(ref) > 0:
                size = abs(ref)

            if size > best_size and abs(ref) > 0:
                best_size = size
                best_offset = abs(ref)

        if best_offset > 0:
            profile.buf_stack_offset = best_offset

    def _infer_vuln_func(self, profile: R2Profile) -> None:
        """Infer the most likely vulnerable function."""
        skip = {"setvbuf", "setbuf", "puts", "printf", "exit", "alarm",
                "signal", "setreuid", "setregid", "setuid", "setgid",
                "__stack_chk_fail", "write", "read", "gets", "fgets",
                "scanf", "__isoc99_scanf", "atoi", "strtol", "strlen",
                "memset", "memcpy", "strcpy", "sprintf", "snprintf",
                "fopen", "fclose", "fread", "recv", "send"}

        # Try to find which function contains input calls (via afi.)
        func_names = set()
        for call in profile.input_calls:
            if call.addr:
                try:
                    result = self._r2.cmd(f"afi. @ {call.addr}")
                    if result:
                        name = result.strip().split()[0] if result.strip() else ""
                        name = re.sub(r"^(sym\.imp\.|sym\.|reloc\.)", "", name)
                        if name and name != "main" and name not in skip:
                            func_names.add(name)
                except Exception:
                    pass

        if func_names:
            # Prefer function names that suggest vulnerability
            for name in func_names:
                if any(kw in name.lower() for kw in ("vuln", "overflow", "pwn",
                                                       "hack", "input", "get")):
                    profile.vuln_func = name
                    return
            profile.vuln_func = next(iter(func_names))
            return

        # Fallback: use call_sequence from main
        if profile.call_sequence:
            for fn in reversed(profile.call_sequence):
                if fn not in skip:
                    profile.vuln_func = fn
                    return
