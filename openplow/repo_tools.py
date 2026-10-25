"""Read-only repository tools a hunter model can call.

A hunter that only sees file *names* cannot find a bug in the file's body, so
the finder is given three tools over the target checkout: ``list_files``,
``read_file`` and ``grep``. They are provider-neutral (a name, a description and
a JSON-schema for the input); a model adapter that supports tool use turns them
into its own wire format and calls :meth:`RepoTools.call` for each request.

Every path is resolved against the repository root and refused if it escapes
it (``..``, absolute paths, symlinks pointing outside). Nothing here writes.
Outputs are capped by size so one call cannot flood the model's context; a
capped output says so, and ``read_file`` takes a line range so a large file can
be paged through.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_MAX_OUTPUT_BYTES = 200_000   # cap on any one tool result
_MAX_LIST_ENTRIES = 500
_MAX_GREP_MATCHES = 200
_MAX_GREP_LINE_CHARS = 500    # long (e.g. minified) matching lines are cut
_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}


class ToolError(Exception):
    """A tool call the model can correct (bad path, bad regex, ...)."""


class RepoTools:
    """Read-only, root-confined file access over one checkout."""

    def __init__(self, root: Path):
        self.root = Path(root).resolve()

    # ---- provider-neutral tool definitions --------------------------------

    def specs(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "list_files",
                "description": (
                    "List files under a directory of the target repository, recursively. "
                    "Paths are relative to the repository root; use '.' for the root."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string",
                                 "description": "Directory relative to the repo root."},
                    },
                    "required": ["path"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "read_file",
                "description": (
                    "Read a file of the target repository, returned with 1-based line "
                    "numbers. Optionally restrict to a line range."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string",
                                 "description": "File path relative to the repo root."},
                        "start_line": {"type": "integer", "minimum": 1},
                        "end_line": {"type": "integer", "minimum": 1},
                    },
                    "required": ["path"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "grep",
                "description": (
                    "Search file contents of the target repository with a Python regular "
                    "expression. Returns path:line: text for each match."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string"},
                        "path": {"type": "string",
                                 "description": "Directory or file to search; default '.'."},
                    },
                    "required": ["pattern"],
                    "additionalProperties": False,
                },
            },
        ]

    # ---- dispatch -----------------------------------------------------------

    def call(self, name: str, args: dict[str, Any]) -> str:
        """Run one tool call. Raises :class:`ToolError` for a correctable mistake."""
        if not isinstance(args, dict):
            raise ToolError("tool input must be an object")
        if name == "list_files":
            return self.list_files(_str_arg(args, "path", "."))
        if name == "read_file":
            return self.read_file(_str_arg(args, "path"),
                                  _int_arg(args, "start_line"), _int_arg(args, "end_line"))
        if name == "grep":
            return self.grep(_str_arg(args, "pattern"), _str_arg(args, "path", "."))
        raise ToolError(f"unknown tool: {name}")

    # ---- tools ----------------------------------------------------------------

    def list_files(self, path: str = ".") -> str:
        base = self._resolve(path)
        if not base.is_dir():
            raise ToolError(f"not a directory: {path}")
        out: list[str] = []
        for p in sorted(self._walk(base)):
            out.append(self._rel(p))
            if len(out) >= _MAX_LIST_ENTRIES:
                out.append(f"... (truncated at {_MAX_LIST_ENTRIES} entries)")
                break
        return "\n".join(out) if out else "(no files)"

    def read_file(self, path: str, start_line: int | None = None,
                  end_line: int | None = None) -> str:
        target = self._resolve(path)
        if not target.is_file():
            raise ToolError(f"not a file: {path}")
        lines = target.read_bytes().decode("utf-8", errors="replace").splitlines()
        first = max(start_line or 1, 1)
        last = min(end_line or len(lines), len(lines))
        # Select the range first, then cap the output, so any line is reachable.
        out: list[str] = []
        size = 0
        for i in range(first, last + 1):
            row = f"{i:>5}  {lines[i - 1]}"
            size += len(row.encode("utf-8")) + 1
            if size > _MAX_OUTPUT_BYTES and out:
                out.append(f"... (output truncated at {_MAX_OUTPUT_BYTES} bytes; "
                           f"call again with start_line={i} to continue; "
                           f"file has {len(lines)} lines)")
                break
            out.append(row)
        return "\n".join(out) or "(empty file)"

    def grep(self, pattern: str, path: str = ".") -> str:
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            raise ToolError(f"bad regex: {exc}") from exc
        base = self._resolve(path)
        files = [base] if base.is_file() else sorted(self._walk(base))
        out: list[str] = []
        size = 0
        for f in files:
            try:
                text = f.read_bytes().decode("utf-8", errors="replace")
            except OSError:
                continue
            for n, line in enumerate(text.splitlines(), 1):
                if not rx.search(line):
                    continue
                if len(line) > _MAX_GREP_LINE_CHARS:
                    line = line[:_MAX_GREP_LINE_CHARS] + " ...(line truncated)"
                row = f"{self._rel(f)}:{n}: {line}"
                size += len(row.encode("utf-8")) + 1
                if len(out) >= _MAX_GREP_MATCHES or size > _MAX_OUTPUT_BYTES:
                    out.append(f"... (truncated at {len(out)} matches; narrow the "
                               "pattern or path)")
                    return "\n".join(out)
                out.append(row)
        return "\n".join(out) if out else "(no matches)"

    # ---- helpers ------------------------------------------------------------

    def _resolve(self, path: str) -> Path:
        if Path(path).is_absolute():
            raise ToolError("paths must be relative to the repository root")
        resolved = (self.root / path).resolve()
        if not resolved.is_relative_to(self.root):
            raise ToolError(f"path escapes the repository: {path}")
        if not resolved.exists():
            raise ToolError(f"no such path: {path}")
        return resolved

    def _walk(self, base: Path):
        for p in base.rglob("*"):
            if any(part in _SKIP_DIRS for part in p.relative_to(base).parts):
                continue
            if p.is_file() and p.resolve().is_relative_to(self.root):
                yield p

    def _rel(self, p: Path) -> str:
        return str(p.resolve().relative_to(self.root))


def _str_arg(args: dict[str, Any], key: str, default: str | None = None) -> str:
    val = args.get(key, default)
    if not isinstance(val, str) or not val:
        raise ToolError(f"'{key}' must be a non-empty string")
    return val


def _int_arg(args: dict[str, Any], key: str) -> int | None:
    val = args.get(key)
    if val is None:
        return None
    if not isinstance(val, int) or isinstance(val, bool):
        raise ToolError(f"'{key}' must be an integer")
    return val
