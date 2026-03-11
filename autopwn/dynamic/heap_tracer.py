from __future__ import annotations

import subprocess
import tempfile
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pwn import log

from autopwn.config import GDB_TIMEOUT

if TYPE_CHECKING:
    from autopwn.context import PwnContext


@dataclass
class ChunkInfo:
    addr: int = 0
    size: int = 0
    state: str = "allocated"  # allocated / freed
    bin_type: str = ""  # tcache / fast / unsorted / small / large
    alloc_site: int = 0
    free_site: int = 0
    data: bytes = b""


@dataclass
class HeapOp:
    op: str = ""  # malloc / free / realloc / calloc
    addr: int = 0
    size: int = 0
    callsite: int = 0
    index: int = 0


@dataclass
class HeapState:
    chunks: list[ChunkInfo] = field(default_factory=list)
    freed_chunks: list[ChunkInfo] = field(default_factory=list)
    tcache_bins: dict[int, list[int]] = field(default_factory=dict)
    fastbins: dict[int, list[int]] = field(default_factory=dict)
    unsorted_bin: list[int] = field(default_factory=list)
    top_chunk: int = 0
    heap_base: int = 0
    ops_log: list[HeapOp] = field(default_factory=list)

    def get_chunk(self, addr: int) -> ChunkInfo | None:
        for c in self.chunks:
            if c.addr == addr:
                return c
        for c in self.freed_chunks:
            if c.addr == addr:
                return c
        return None

    def detect_uaf(self) -> list[dict[str, Any]]:
        """检测UAF：freed但之后仍被访问的chunk。"""
        uaf_list = []
        freed_addrs = {c.addr for c in self.freed_chunks}
        for op in self.ops_log:
            if op.op in ("read", "write", "show", "edit") and op.addr in freed_addrs:
                uaf_list.append({
                    "addr": op.addr,
                    "op": op.op,
                    "callsite": op.callsite,
                })
        return uaf_list

    def detect_double_free(self) -> list[dict[str, Any]]:
        """检测double free。"""
        freed_log = [(i, op) for i, op in enumerate(self.ops_log) if op.op == "free"]
        seen: dict[int, int] = {}
        doubles = []
        for idx, op in freed_log:
            if op.addr in seen:
                doubles.append({
                    "addr": op.addr,
                    "first_free_idx": seen[op.addr],
                    "second_free_idx": idx,
                })
            seen[op.addr] = idx
        return doubles


# LD_PRELOAD tracer source
_TRACER_C = r"""
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>

static void *(*real_malloc)(size_t) = NULL;
static void (*real_free)(void *) = NULL;
static void *(*real_calloc)(size_t, size_t) = NULL;
static void *(*real_realloc)(void *, size_t) = NULL;

static FILE *logfile = NULL;
static int init_done = 0;

static void init_tracer(void) {
    if (init_done) return;
    init_done = 1;
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_free = dlsym(RTLD_NEXT, "free");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    char *path = getenv("HEAP_TRACE_LOG");
    if (path) {
        logfile = fopen(path, "w");
    }
}

void *malloc(size_t size) {
    init_tracer();
    void *ptr = real_malloc(size);
    if (logfile) {
        fprintf(logfile, "MALLOC %p %zu\n", ptr, size);
        fflush(logfile);
    }
    return ptr;
}

void free(void *ptr) {
    init_tracer();
    if (logfile && ptr) {
        fprintf(logfile, "FREE %p\n", ptr);
        fflush(logfile);
    }
    real_free(ptr);
}

void *calloc(size_t nmemb, size_t size) {
    init_tracer();
    void *ptr = real_calloc(nmemb, size);
    if (logfile) {
        fprintf(logfile, "CALLOC %p %zu\n", ptr, nmemb * size);
        fflush(logfile);
    }
    return ptr;
}

void *realloc(void *ptr, size_t size) {
    init_tracer();
    void *new_ptr = real_realloc(ptr, size);
    if (logfile) {
        fprintf(logfile, "REALLOC %p %p %zu\n", ptr, new_ptr, size);
        fflush(logfile);
    }
    return new_ptr;
}
"""


def build_tracer_lib() -> str | None:
    """编译LD_PRELOAD tracer库。"""
    from autopwn.config import CACHE_DIR
    lib_path = CACHE_DIR / "heap_tracer.so"
    if lib_path.exists():
        return str(lib_path)

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    src_path = CACHE_DIR / "heap_tracer.c"
    src_path.write_text(_TRACER_C)

    try:
        result = subprocess.run(
            ["gcc", "-shared", "-fPIC", "-o", str(lib_path), str(src_path), "-ldl"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            log.info(f"堆追踪器编译成功: {lib_path}")
            return str(lib_path)
        log.warning(f"堆追踪器编译失败: {result.stderr}")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        log.warning("无法编译堆追踪器（需要gcc）")
    return None


def trace_heap_ops(ctx: PwnContext, stdin_data: bytes = b"", timeout: int = 10) -> HeapState:
    """用LD_PRELOAD追踪程序的堆操作。"""
    state = HeapState()

    tracer_lib = build_tracer_lib()
    if not tracer_lib:
        return state

    log_file = tempfile.mktemp(suffix=".log")

    env = {
        "LD_PRELOAD": tracer_lib,
        "HEAP_TRACE_LOG": log_file,
    }

    try:
        proc = subprocess.run(
            [ctx.binary_path],
            input=stdin_data,
            capture_output=True,
            timeout=timeout,
            env=env,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        pass

    log_path = Path(log_file)
    if log_path.exists():
        state = _parse_trace_log(log_path.read_text())
        log_path.unlink(missing_ok=True)

    ctx.heap_state = state
    ctx.heap_ops_log = state.ops_log
    return state


def _parse_trace_log(log_text: str) -> HeapState:
    """解析追踪日志。"""
    state = HeapState()
    chunk_map: dict[int, ChunkInfo] = {}
    op_idx = 0

    for line in log_text.splitlines():
        parts = line.strip().split()
        if not parts:
            continue

        op_type = parts[0]

        if op_type == "MALLOC" and len(parts) >= 3:
            addr = int(parts[1], 16)
            size = int(parts[2])
            chunk = ChunkInfo(addr=addr, size=size, state="allocated")
            chunk_map[addr] = chunk
            state.chunks.append(chunk)
            state.ops_log.append(HeapOp(op="malloc", addr=addr, size=size, index=op_idx))
            if state.heap_base == 0 or addr < state.heap_base:
                state.heap_base = addr & ~0xfff

        elif op_type == "FREE" and len(parts) >= 2:
            addr = int(parts[1], 16)
            if addr in chunk_map:
                chunk_map[addr].state = "freed"
                state.freed_chunks.append(chunk_map[addr])
            state.ops_log.append(HeapOp(op="free", addr=addr, index=op_idx))

        elif op_type == "CALLOC" and len(parts) >= 3:
            addr = int(parts[1], 16)
            size = int(parts[2])
            chunk = ChunkInfo(addr=addr, size=size, state="allocated")
            chunk_map[addr] = chunk
            state.chunks.append(chunk)
            state.ops_log.append(HeapOp(op="calloc", addr=addr, size=size, index=op_idx))

        elif op_type == "REALLOC" and len(parts) >= 4:
            old_addr = int(parts[1], 16)
            new_addr = int(parts[2], 16)
            size = int(parts[3])
            if old_addr in chunk_map:
                chunk_map[old_addr].state = "freed"
            chunk = ChunkInfo(addr=new_addr, size=size, state="allocated")
            chunk_map[new_addr] = chunk
            state.chunks.append(chunk)
            state.ops_log.append(HeapOp(op="realloc", addr=new_addr, size=size, index=op_idx))

        op_idx += 1

    return state


def trace_with_gdb(ctx: PwnContext, commands: list[str] = None) -> HeapState:
    """使用GDB断点追踪堆操作（备选方法）。"""
    state = HeapState()

    gdb_script = """
set pagination off
set confirm off
set disable-randomization on

break malloc
commands
  silent
  printf "MALLOC_CALL size=%d\\n", (long)$rdi
  continue
end

break *malloc+0
commands
  silent
  finish
  printf "MALLOC_RET addr=%p\\n", (void*)$rax
  continue
end

break free
commands
  silent
  printf "FREE addr=%p\\n", (void*)$rdi
  continue
end

run
quit
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as sf:
        sf.write(gdb_script)
        script_file = sf.name

    stdin_data = b"\n".join(c.encode() for c in commands) + b"\n" if commands else b""

    try:
        result = subprocess.run(
            ["gdb", "-batch", "-nx", "-x", script_file, ctx.binary_path],
            input=stdin_data,
            capture_output=True, text=True,
            timeout=GDB_TIMEOUT * 3,
        )

        for line in result.stdout.splitlines():
            if "MALLOC_RET" in line:
                m = re.search(r"addr=(0x[0-9a-f]+)", line)
                if m:
                    addr = int(m.group(1), 16)
                    state.ops_log.append(HeapOp(op="malloc", addr=addr))
            elif "FREE" in line:
                m = re.search(r"addr=(0x[0-9a-f]+)", line)
                if m:
                    addr = int(m.group(1), 16)
                    state.ops_log.append(HeapOp(op="free", addr=addr))

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    finally:
        Path(script_file).unlink(missing_ok=True)

    return state
