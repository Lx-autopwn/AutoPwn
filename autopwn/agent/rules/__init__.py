"""Auto-load all rules from this package."""
from __future__ import annotations

from autopwn.agent.rules.sleep_bypass import RULES as _r1
from autopwn.agent.rules.restart_fix import RULES as _r2
from autopwn.agent.rules.system_bss import RULES as _r3
from autopwn.agent.rules.cmp_win import RULES as _r4
from autopwn.agent.rules.var_overwrite import RULES as _r5
from autopwn.agent.rules.fmt_combo import RULES as _r6
from autopwn.agent.rules.orw_chain import RULES as _r7
from autopwn.agent.rules.close_redirect import RULES as _r8
from autopwn.agent.rules.expanded_win import RULES as _r9
from autopwn.agent.rules.orw_shellcode import RULES as _r10
from autopwn.agent.rules.local_overwrite import RULES as _r11

ALL_RULES = _r1 + _r2 + _r3 + _r4 + _r5 + _r6 + _r7 + _r8 + _r9 + _r10 + _r11
