from __future__ import annotations

import logging

from pwn import context as pwn_context, log


def setup_logger(verbosity: int = 0) -> None:
    if verbosity >= 2:
        pwn_context.log_level = "debug"
    else:
        # Default to info — users need to see analysis progress and results
        pwn_context.log_level = "info"

    # Stop pwnlib log propagation to root logger (prevents duplicate output
    # when other libraries like angr add handlers to the root logger)
    logging.getLogger("pwnlib").propagate = False


BANNER_TEXT = r"""
 █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ██╗    ██╗███╗   ██╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██║    ██║████╗  ██║
███████║██║   ██║   ██║   ██║   ██║██████╔╝██║ █╗ ██║██╔██╗ ██║
██╔══██║██║   ██║   ██║   ██║   ██║██╔═══╝ ██║███╗██║██║╚██╗██║
██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║     ╚███╔███╔╝██║ ╚████║
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
"""


def banner() -> None:
    from autopwn import __version__
    cyan = "\033[0;36m"
    green = "\033[0;32m"
    reset = "\033[0m"
    print(f"{cyan}{BANNER_TEXT}{reset}")
    print(f"  {green}AutoPwn v{__version__} - Automated CTF PWN Framework{reset}")
    print(f"  {green}White-box analysis driven exploit engine{reset}")
    print()
