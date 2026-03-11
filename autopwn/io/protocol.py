from __future__ import annotations

import re
from typing import TYPE_CHECKING

from pwn import log, process

from autopwn.config import RECV_TIMEOUT

if TYPE_CHECKING:
    pass


def detect_protocol(binary_path: str, timeout: float = RECV_TIMEOUT) -> dict:
    """Probe the binary's interaction protocol.

    Runs the binary locally, reads its initial output, and classifies the
    interaction style.

    Returns::

        {
            "type": "direct" | "menu" | "multi_round",
            "prompts": [b"..."],
            "menu_items": {1: b"Add", 2: b"Delete", ...},
        }
    """
    result: dict = {
        "type": "direct",
        "prompts": [],
        "menu_items": {},
    }

    try:
        p = process(binary_path, timeout=timeout)
    except Exception as e:
        log.warning(f"protocol detect: failed to spawn process: {e}")
        return result

    try:
        # read initial output
        try:
            initial = p.recv(timeout=timeout)
        except Exception:
            initial = b""
        if not initial:
            p.close()
            return result

        lines = initial.split(b"\n")
        prompts = _extract_prompts(lines)
        menu = _extract_menu(lines)

        if menu:
            result["type"] = "menu"
            result["menu_items"] = menu
            result["prompts"] = prompts
        elif len(prompts) > 1:
            result["type"] = "multi_round"
            result["prompts"] = prompts
        elif prompts:
            result["type"] = "direct"
            result["prompts"] = prompts
        # else: no prompt at all -> "direct" (binary reads immediately)

    except Exception as e:
        log.debug(f"protocol detect error: {e}")
    finally:
        try:
            p.close()
        except Exception:
            pass

    return result


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

_PROMPT_RE = re.compile(rb"[:>?]\s*$")
_MENU_LINE_RE = re.compile(rb"^\s*(\d+)\s*[.):\-]\s*(.+)", re.IGNORECASE)


def _extract_prompts(lines: list[bytes]) -> list[bytes]:
    """Find lines that look like input prompts."""
    prompts: list[bytes] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if _PROMPT_RE.search(stripped):
            prompts.append(stripped)
    return prompts


def _extract_menu(lines: list[bytes]) -> dict[int, bytes]:
    """Try to parse numbered menu items from output lines."""
    items: dict[int, bytes] = {}
    for line in lines:
        m = _MENU_LINE_RE.match(line.strip())
        if m:
            try:
                num = int(m.group(1))
                label = m.group(2).strip()
                items[num] = label
            except ValueError:
                continue
    return items
