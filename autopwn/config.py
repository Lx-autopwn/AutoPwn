from __future__ import annotations

from pathlib import Path

GDB_TIMEOUT: int = 15
RECV_TIMEOUT: int = 3
SHELL_VERIFY_TIMEOUT: int = 3
MAX_PATTERN_LEN: int = 512

CACHE_DIR: Path = Path.home() / ".cache" / "autopwn"

SHELL_MARKER: bytes = b"P_W_N_E_D"

ANGR_TIMEOUT: int = 120
SYMEX_TIMEOUT: int = 60

LIBC_RIP_URL: str = "https://libc.rip/api/find"

WIN_FUNC_NAMES: list[str] = [
    "win", "flag", "shell", "backdoor", "get_flag", "print_flag",
    "read_flag", "cat_flag", "give_shell", "spawn_shell", "getshell",
    "get_shell", "secret", "callme", "ret2win", "system_call",
    "easy", "vuln_backdoor", "magic",
    # CamelCase variants (matched case-insensitively via _match)
    "printflag", "getflag", "readflag", "spawnshell",
    "good_game", "callsystem",
]

DANGEROUS_FUNCS: list[str] = [
    "gets", "scanf", "vscanf", "sprintf", "vsprintf",
    "strcpy", "strcat", "strncpy", "strncat",
    "read", "fgets", "fread", "recv", "recvfrom",
    "memcpy", "memmove", "bcopy",
    "printf", "fprintf", "snprintf", "vprintf", "vfprintf",
    "free", "realloc",
]

SYSTEM_CALLS: list[str] = [
    "system", "execve", "execl", "execlp", "execle",
    "execv", "execvp", "execvpe", "popen", "dlopen",
]

SKIP_FUNCS: list[str] = [
    "_start", "__libc_start_main", "__libc_csu_init", "__libc_csu_fini",
    "_init", "_fini", "__do_global_dtors_aux", "frame_dummy",
    "register_tm_clones", "deregister_tm_clones",
    "__x86.get_pc_thunk.bx", "__x86.get_pc_thunk.ax",
    "_dl_relocate_static_pie",
]

INPUT_FUNC_NAMES: list[str] = [
    "read", "gets", "fgets", "scanf", "fscanf", "sscanf",
    "recv", "recvfrom", "fread", "__isoc99_scanf",
]

OUTPUT_FUNC_NAMES: list[str] = [
    "puts", "printf", "fprintf", "write", "send", "sendto",
    "fputs", "fwrite", "putchar", "putc",
]

HEAP_ALLOC_FUNCS: list[str] = [
    "malloc", "calloc", "realloc", "memalign",
    "aligned_alloc", "pvalloc", "valloc",
]

HEAP_FREE_FUNCS: list[str] = [
    "free", "cfree",
]

FORMAT_FUNCS: list[str] = [
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "dprintf", "syslog",
]
