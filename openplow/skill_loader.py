"""Loads the vendored Cloudflare security-audit skill.

The skill's per-class prompt files drive the hunters: each OpenPlow attack class
maps to one class file, whose text is injected into the hunter prompt. The skill
is vendored under ``skills/security-audit/`` (see ``skills/README.md``). If it is
not present, hunters fall back to a generic prompt and a wishlist item is logged.
"""

from __future__ import annotations

from functools import cache, lru_cache
from pathlib import Path

# OpenPlow attack-class id -> vendored skill file.
CLASS_FILES = {
    "web-protocol-and-auth": "WEB-PROTOCOL-AND-AUTH.md",
    "memory-safety-and-binary": "MEMORY-SAFETY-AND-BINARY.md",
    "ai-and-llm": "AI-AND-LLM.md",
    "client-side": "CLIENT-SIDE.md",
    "supply-chain-and-release": "SUPPLY-CHAIN-AND-RELEASE.md",
    "cloud-and-deployment": "CLOUD-AND-DEPLOYMENT.md",
    "protocols-rpc-and-messaging": "PROTOCOLS-RPC-AND-MESSAGING.md",
    "resource-exhaustion-and-availability": "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md",
    "data-isolation-and-lifecycle": "DATA-ISOLATION-AND-LIFECYCLE.md",
    "desktop-mobile-and-local-ipc": "DESKTOP-MOBILE-AND-LOCAL-IPC.md",
}


def skill_dir() -> Path:
    """Path to the vendored skill, relative to the installed package."""
    return Path(__file__).resolve().parent.parent / "skills" / "security-audit"


def is_vendored() -> bool:
    d = skill_dir()
    return d.is_dir() and (d / "SKILL.md").exists()


@cache
def load_class_prompt(attack_class: str) -> str | None:
    """Return the text of the class file for an attack class, or None if absent."""
    fname = CLASS_FILES.get(attack_class)
    if not fname:
        return None
    path = skill_dir() / fname
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def load_core_methodology() -> str:
    """Shared hunting methodology (HUNTING.md), loaded once."""
    path = skill_dir() / "HUNTING.md"
    return path.read_text(encoding="utf-8") if path.exists() else ""
