from __future__ import annotations

import argparse
import os
import signal
import sys
from pathlib import Path

from autopwn import __version__
from autopwn.output.logger import banner, setup_logger


def _kill_group(signum, frame) -> None:
    try:
        os.killpg(os.getpgid(os.getpid()), signal.SIGTERM)
    except ProcessLookupError:
        pass
    sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autopwn",
        description=f"AutoPwn v{__version__} - Automated CTF PWN Framework",
    )
    parser.add_argument(
        "binary",
        help="path to target ELF binary",
    )
    parser.add_argument(
        "-l", "--libc",
        metavar="LIBC",
        help="path to libc.so.6",
    )
    parser.add_argument(
        "-r", "--remote",
        metavar="HOST:PORT",
        help="remote target (host:port)",
    )
    parser.add_argument(
        "-a", "--analyze-only",
        action="store_true",
        help="analyze only, do not exploit",
    )
    parser.add_argument(
        "--glibc",
        metavar="VERSION",
        help="specify glibc version (e.g. 2.31)",
    )
    parser.add_argument(
        "--strategy",
        metavar="NAME",
        help="force a specific exploit strategy",
    )
    parser.add_argument(
        "--gen-script",
        action="store_true",
        help="generate standalone exploit script",
    )
    parser.add_argument(
        "--blackbox",
        action="store_true",
        help="skip white-box analysis (v1 mode)",
    )
    parser.add_argument(
        "-v",
        action="count",
        default=0,
        dest="verbosity",
        help="increase verbosity (-v info, -vv debug)",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="non-interactive batch mode",
    )
    parser.add_argument(
        "--no-agent",
        action="store_true",
        help="disable agent feedback loop (use engine only)",
    )
    parser.add_argument(
        "--max-rounds",
        type=int,
        default=15,
        metavar="N",
        help="max agent loop rounds (default: 15)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    signal.signal(signal.SIGINT, _kill_group)
    # Only create a separate process group in non-interactive (batch/pipe)
    # mode.  When stdin is a tty, os.setpgrp() moves us to a background
    # group, which blocks terminal reads (SIGTTIN) and prevents Ctrl-C
    # from reaching us — breaking pwntools interactive().
    if not sys.stdin.isatty():
        try:
            os.setpgrp()
        except OSError:
            pass

    parser = build_parser()

    # Show banner + usage when called with no arguments
    if argv is None and len(sys.argv) < 2:
        banner()
        parser.print_help()
        return 0

    args = parser.parse_args(argv)

    setup_logger(args.verbosity)
    banner()

    binary = Path(args.binary).resolve()
    if not binary.exists():
        from pwn import log
        log.failure(f"Binary not found: {binary}")
        return 1
    if not binary.is_file():
        from pwn import log
        log.failure(f"Not a file: {binary}")
        return 1

    binary.chmod(binary.stat().st_mode | 0o111)

    from pwn import log
    log.info(f"Target: {binary}")
    if args.libc:
        log.info(f"Libc: {args.libc}")
    if args.remote:
        log.info(f"Remote: {args.remote}")
    if args.glibc:
        log.info(f"Glibc version: {args.glibc}")
    if args.strategy:
        log.info(f"Forced strategy: {args.strategy}")
    if args.blackbox:
        log.info("Black-box mode (no white-box analysis)")

    try:
        if args.no_agent:
            from autopwn.engine.engine import Engine
            runner = Engine(
                binary_path=str(binary),
                libc_path=args.libc,
                remote=args.remote,
                analyze_only=args.analyze_only,
                glibc_version=args.glibc,
                forced_strategy=args.strategy,
                gen_script=args.gen_script,
                blackbox=args.blackbox,
                batch=args.batch,
            )
        else:
            from autopwn.agent import PwnAgent
            runner = PwnAgent(
                binary_path=str(binary),
                libc_path=args.libc,
                remote=args.remote,
                analyze_only=args.analyze_only,
                glibc_version=args.glibc,
                forced_strategy=args.strategy,
                gen_script=args.gen_script,
                blackbox=args.blackbox,
                batch=args.batch,
                max_rounds=args.max_rounds,
            )
        return runner.run()
    except ImportError:
        log.warning("Engine module not yet available; running in analysis-only stub mode")
        _stub_analyze(str(binary), args)
        return 0


def _stub_analyze(binary_path: str, args: argparse.Namespace) -> None:
    from pwn import ELF, log
    from autopwn.context import PwnContext
    from autopwn.output.report import print_full_report

    elf = ELF(binary_path, checksec=False)
    ctx = PwnContext(
        binary_path=binary_path,
        elf=elf,
        arch=elf.arch,
        bits=elf.bits,
        endian=elf.endian,
        nx=bool(elf.execstack is False),
        pie=bool(elf.pie),
        canary="__stack_chk_fail" in elf.symbols or "__stack_chk_fail" in (elf.got or {}),
        relro=elf.relro or "no",
    )
    if args.glibc:
        ctx.glibc_version = args.glibc

    from autopwn.config import WIN_FUNC_NAMES, DANGEROUS_FUNCS
    for name, addr in elf.symbols.items():
        if name in WIN_FUNC_NAMES:
            ctx.win_funcs.append({"name": name, "addr": addr})
    for name in DANGEROUS_FUNCS:
        if name in elf.plt:
            ctx.dangerous_funcs.append({"name": name, "addr": elf.plt[name]})
        elif name in elf.symbols:
            ctx.dangerous_funcs.append({"name": name, "addr": elf.symbols[name]})

    ctx.got_table = dict(elf.got) if elf.got else {}
    ctx.plt_table = dict(elf.plt) if elf.plt else {}

    print_full_report(ctx)
    log.info("Stub analysis complete (engine not loaded)")
