"""Parsing and validating findings returned by a model.

A hunter returns free-form text; this module pulls structured findings out of it
and checks them against the finding schema before anything is persisted. A
finding that does not parse, or is missing required fields, is dropped (and the
caller can log it to the wishlist) rather than stored as a half-finding.

Schema validation uses ``jsonschema`` when it is installed; otherwise it falls
back to a minimal required-field check so the base install stays
dependency-free.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

_SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "finding.schema.json"

# Matches a ```json ... ``` fenced block or a bare top-level JSON array/object.
_FENCE = re.compile(r"```(?:json)?\s*(?P<body>[\[{].*?[\]}])\s*```", re.DOTALL)


@lru_cache(maxsize=1)
def _schema() -> dict[str, Any]:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def extract_json(text: str) -> list[dict[str, Any]]:
    """Pull a list of finding dicts out of a model response.

    Accepts a fenced ```json block, a bare array, or a bare object (wrapped into
    a one-element list). Returns [] when nothing parseable is present.
    """
    candidates: list[str] = []
    m = _FENCE.search(text)
    if m:
        candidates.append(m.group("body"))
    stripped = text.strip()
    if stripped[:1] in "[{":
        candidates.append(stripped)

    for body in candidates:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            continue
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        if isinstance(data, dict):
            # Allow {"findings": [...]} or a single finding object.
            if isinstance(data.get("findings"), list):
                return [d for d in data["findings"] if isinstance(d, dict)]
            return [data]
    return []


# Minimal required-field spec mirroring the schema's "required" lists, used when
# jsonschema is not installed.
_REQUIRED_TOP = ("id", "verdict", "title", "attack_class", "threat_model", "location")


def _minimal_check(finding: dict[str, Any]) -> list[str]:
    problems = [f"missing required field: {k}" for k in _REQUIRED_TOP if k not in finding]
    tm = finding.get("threat_model")
    if isinstance(tm, dict):
        if not tm.get("attacker"):
            problems.append("threat_model.attacker missing")
        if not tm.get("boundary"):
            problems.append("threat_model.boundary missing")
    elif "threat_model" in finding:
        problems.append("threat_model must be an object")
    loc = finding.get("location")
    if isinstance(loc, dict):
        if not loc.get("file"):
            problems.append("location.file missing")
    elif "location" in finding:
        problems.append("location must be an object")
    return problems


def validate_finding(finding: dict[str, Any]) -> list[str]:
    """Return a list of schema problems (empty = valid)."""
    try:
        import jsonschema
    except ImportError:
        return _minimal_check(finding)
    validator = jsonschema.Draft202012Validator(_schema())
    return [f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message}"
            for e in validator.iter_errors(finding)]
