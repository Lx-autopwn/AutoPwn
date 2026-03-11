```
     _         _        ____
    / \  _   _| |_ ___ |  _ \__      ___ __
   / _ \| | | | __/ _ \| |_) \ \ /\ / / '_ \
  / ___ \ |_| | || (_) |  __/ \ V  V /| | | |
 /_/   \_\__,_|\__\___/|_|     \_/\_/ |_| |_|
              Autonomous CTF Pwn Solver
```

**AutoPwn** is a fully autonomous binary exploitation engine for CTF pwn challenges. Give it an ELF binary, and it will analyze vulnerabilities, craft exploits, and pop a shell -- no human interaction required.

> 66 / 112 challenges solved (58.9%) across mixed CTF datasets, fully automated.

---

## Features

- **Zero-click exploitation** -- point it at a binary, get a shell
- **6-phase analysis pipeline** -- static recon, white-box analysis, dynamic probing, path synthesis, exploit execution, and agent-guided retry
- **30+ exploit strategies** -- stack, heap, format string, shellcode, ROP, SROP, ret2libc, ret2csu, ret2dlresolve, and more
- **Adaptive agent loop** -- 11 observer-rule pairs detect patterns and retry with refined strategies when initial attempts fail
- **Bundled libc-database** -- automatic libc identification and offset resolution
- **Local and remote targets** -- works on local binaries and remote `host:port` services

## Quick Start

```bash
# Clone
git clone https://github.com/Lx-autopwn/AutoPwn.git
cd AutoPwn

# Install everything (Kali / Debian / Ubuntu)
chmod +x setup.sh && ./setup.sh

# Pwn
autopwn ./challenge
```

Or install manually:

```bash
pip install -e .            # core (pwntools + ROPgadget)
pip install -e '.[full]'    # + angr white-box engine
```

## Pipeline

AutoPwn processes each binary through six phases:

| Phase | Name | What it does |
|-------|------|--------------|
| 0 | **Load** | Parse ELF, resolve libc |
| 1 | **Recon** | checksec, strings, gadgets, GOT/PLT, seccomp rules |
| 2 | **White-box** | Decompile, CFG, taint analysis, vulnerability detection (requires angr) |
| 3 | **Dynamic** | Interaction probing, overflow offset, canary detection, heap tracing |
| 4 | **Synthesize** | Rank candidate exploit paths, build execution plan |
| 5 | **Exploit** | Execute strategies in priority order until shell is obtained |
| 6 | **Agent** | Observer-rule feedback loop retries with refined strategies |

## Exploit Strategies

<details>
<summary>Stack (9)</summary>

| Strategy | Description |
|----------|-------------|
| Ret2Win | Jump to win/flag function |
| Ret2Libc | Leak libc + system("/bin/sh") |
| Ret2Shellcode | Jump to injected shellcode |
| Ret2Syscall | execve via syscall gadgets |
| Ret2CSU | Universal ROP via __libc_csu_init |
| Ret2DlResolve | Forge relocation entries |
| SROP | Sigreturn-oriented programming |
| StackPivot | Migrate stack to controlled buffer |
| PartialOverwrite | Overwrite partial return address |

</details>

<details>
<summary>Heap (11)</summary>

| Strategy | Description |
|----------|-------------|
| TcachePoison | Tcache fd poisoning |
| TcacheSafe | Safe-linking bypass |
| FastbinDup | Fastbin double-free |
| HouseOfForce | Top chunk size overwrite |
| HouseOfSpirit | Fake chunk on stack |
| HouseOfEinherjar | Null byte off-by-one |
| HouseOfOrange | Unsorted bin attack |
| HouseOfApple | Wide data vtable hijack |
| UnsortedBin | Unsorted bin link corruption |
| LargeBin | Large bin attack |
| HeapBackdoor | Direct backdoor via heap menu |

</details>

<details>
<summary>Format String (1)</summary>

| Strategy | Description |
|----------|-------------|
| FmtString | Arbitrary read/write via format string |

</details>

<details>
<summary>Shellcode & Sandbox (5)</summary>

| Strategy | Description |
|----------|-------------|
| ShellcodeInject | Direct shellcode injection |
| MprotectShellcode | mprotect + shellcode |
| ORW | Open-Read-Write chain |
| ORWSendfile | sendfile-based exfiltration |
| SideChannel | Bit-by-bit flag leak |

</details>

<details>
<summary>Advanced (5)</summary>

| Strategy | Description |
|----------|-------------|
| CanaryBypass | Canary leak + overflow |
| GOTHijack | GOT overwrite to win |
| WriteWhatWhereGOT | Arbitrary write targeting GOT |
| FSOP | File stream oriented programming |
| CmdInject | Command injection in input handlers |

</details>

## Usage

```
autopwn <binary> [options]

positional arguments:
  binary                  Path to target ELF binary

options:
  -l, --libc LIBC         Path to libc.so.6
  -r, --remote HOST:PORT  Remote target
  -a, --analyze-only      Analyze only, do not exploit
  --glibc VERSION         Specify glibc version (e.g., 2.31)
  --strategy NAME         Force a specific exploit strategy
  --gen-script            Generate standalone exploit script
  --blackbox              Skip white-box analysis
  --no-agent              Disable agent feedback loop
  --max-rounds N          Max agent retry rounds (default: 15)
  --batch                 Non-interactive batch mode
  -v, -vv                 Verbosity (info / debug)
  --version               Show version
```

### Examples

```bash
# Basic local exploit
autopwn ./vuln_binary

# Specify libc
autopwn ./vuln_binary -l ./libc.so.6

# Remote target
autopwn ./vuln_binary -r pwn.ctf.example:9999

# Analysis only (no exploit attempt)
autopwn ./vuln_binary -a

# Force specific strategy
autopwn ./vuln_binary --strategy ret2libc

# Fast mode (no angr, no agent)
autopwn ./vuln_binary --blackbox --no-agent
```

## Architecture

```
autopwn/
  cli.py              # CLI entry point
  context.py          # Shared analysis context
  engine/
    engine.py         # 6-phase pipeline orchestrator
  analysis/           # Static + dynamic analysis modules
  exploit/
    stack/            # 9 stack strategies
    heap/             # 11 heap strategies
    fmt/              # Format string exploits
    shellcode/        # Shellcode + sandbox bypass
    advanced/         # GOT hijack, FSOP, canary bypass
  agent/
    agent.py          # PwnAgent retry loop
    observer.py       # 11 pattern observers
    rules/            # 11 corrective rules
  dynamic/            # Runtime interaction, menu detection
  gadget/             # ROP gadget management
  libc/               # libc resolution + one_gadget
libc-database/        # Bundled libc offset database
```

## Benchmark

Tested on 112 mixed CTF pwn challenges (beginner to intermediate):

| Metric | Value |
|--------|-------|
| Total solved | 66 / 112 (58.9%) |
| Stack exploits | Ret2Win, Ret2Libc, Ret2Shellcode, Ret2Syscall, ... |
| Heap exploits | Tcache, Fastbin, House-of-* family |
| Format string | Arbitrary read/write |
| Agent recoveries | +5 challenges rescued by observer-rule feedback |

### What it handles well

- Standard stack buffer overflows (with and without canary/PIE/NX)
- ret2libc with automatic libc leak + identification
- Format string read/write primitives
- Basic shellcode injection
- Simple menu-driven heap challenges

### Current limitations

- Complex heap exploitation (multi-step house-of-* techniques)
- Heavy reverse engineering requirements (encrypted input, custom encodings)
- C++ vtable exploitation
- Multi-stage interactions requiring domain-specific logic
- Challenges requiring brute force or timing attacks

## Requirements

- **OS**: Linux (Kali / Debian / Ubuntu recommended)
- **Python**: >= 3.11
- **Core**: pwntools, ROPgadget, GDB
- **Recommended**: angr (white-box analysis), one_gadget, seccomp-tools, radare2

## License

[MIT](LICENSE)
