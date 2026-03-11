from __future__ import annotations

import logging
import sys

# Suppress verbose third-party logs before any imports trigger them
for _name in ("angr", "cle", "claripy", "archinfo", "pyvex", "ailment"):
    logging.getLogger(_name).setLevel(logging.CRITICAL)

from autopwn.cli import main

sys.exit(main())
