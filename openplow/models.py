"""Model-adapter layer.

Models are interchangeable components; the harness is the durable part. Every
stage talks to a model only through :class:`ModelAdapter`, so the finder and the
validator can be *different* models that check each other's output.

Two rules from Cloudflare's write-up are baked into the contract:

* A response is classified explicitly as ok / retryable / fatal. Transient API
  errors can arrive as text inside a ``200 OK``, so a successful HTTP status is
  not enough.
* An adapter never decides policy (what counts as a finding). It only turns a
  prompt into text and reports how the call went.
"""

from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Outcome(str, Enum):
    OK = "ok"
    RETRYABLE = "retryable"
    FATAL = "fatal"


@dataclass
class ModelResponse:
    outcome: Outcome
    text: str = ""
    error: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.outcome is Outcome.OK


# Phrases that signal a transient failure delivered as a 200-OK body rather than
# an HTTP error. Checked before a response is treated as success.
_TRANSIENT_IN_BODY = re.compile(
    r"\b(overloaded|rate.?limit|try again|temporarily unavailable|"
    r"internal server error|upstream connect error|timeout)\b",
    re.IGNORECASE,
)


def classify_body(text: str) -> Outcome:
    """Classify a 200-OK body. A short body that is *only* a transient error
    message is retryable; anything substantive is OK."""
    stripped = text.strip()
    if stripped and len(stripped) < 400 and _TRANSIENT_IN_BODY.search(stripped):
        return Outcome.RETRYABLE
    return Outcome.OK


class ModelAdapter(ABC):
    """Provider-agnostic interface. One concrete adapter per backend."""

    #: Human-readable name recorded in finding provenance.
    name: str = "abstract"

    @abstractmethod
    def complete(self, system: str, prompt: str, *, max_tokens: int = 4096) -> ModelResponse:
        """Turn a prompt into text, classifying how the call went."""
        raise NotImplementedError


class StubAdapter(ModelAdapter):
    """Deterministic, no-network adapter for exercising the pipeline.

    It never calls a model. It echoes a tiny, schema-shaped response so the
    orchestrator, store, and reporter can be run and tested end-to-end without
    an API key.
    """

    name = "stub"

    def complete(self, system: str, prompt: str, *, max_tokens: int = 4096) -> ModelResponse:
        return ModelResponse(outcome=Outcome.OK, text="STUB_OK", raw={"system_len": len(system)})


class AnthropicAdapter(ModelAdapter):
    """Real adapter backed by the Anthropic API.

    Lazily imports ``anthropic`` so the base install stays dependency-free.
    Install with ``pip install 'openplow[anthropic]'``.
    """

    def __init__(self, model: str, api_key: str | None = None, *, name: str | None = None,
                 effort: str | None = "high"):
        self.model = model
        self.name = name or f"anthropic:{model}"
        self.effort = effort  # output_config effort; "high" is good for audit work
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client: Any = None

    def _ensure_client(self) -> Any:
        if self._client is None:
            try:
                import anthropic
            except ImportError as exc:  # pragma: no cover - import guard
                raise RuntimeError(
                    "AnthropicAdapter needs the 'anthropic' package: pip install 'openplow[anthropic]'"
                ) from exc
            if not self._api_key:
                raise RuntimeError("ANTHROPIC_API_KEY is not set")
            self._client = anthropic.Anthropic(api_key=self._api_key)
        return self._client

    def complete(self, system: str, prompt: str, *, max_tokens: int = 4096) -> ModelResponse:
        # Note: temperature/top_p are intentionally not sent — current models
        # reject non-default sampling. Thinking is adaptive by default (omitted).
        try:
            client = self._ensure_client()
            kwargs: dict[str, Any] = {
                "model": self.model,
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": prompt}],
            }
            if self.effort:
                kwargs["output_config"] = {"effort": self.effort}
            msg = client.messages.create(**kwargs)
            text = "".join(
                block.text for block in msg.content if getattr(block, "type", None) == "text"
            )
            outcome = classify_body(text)
            return ModelResponse(outcome=outcome, text=text, raw={
                "stop_reason": getattr(msg, "stop_reason", None),
                "model": self.model,
                "usage": _extract_usage(msg),
            })
        except Exception as exc:  # noqa: BLE001 - adapter boundary
            return ModelResponse(outcome=_classify_exception(exc), text="", error=str(exc))


def _extract_usage(msg: Any) -> dict[str, int]:
    u = getattr(msg, "usage", None)
    if u is None:
        return {}
    return {
        "input_tokens": getattr(u, "input_tokens", 0) or 0,
        "output_tokens": getattr(u, "output_tokens", 0) or 0,
        "cache_read_tokens": getattr(u, "cache_read_input_tokens", 0) or 0,
        "cache_creation_tokens": getattr(u, "cache_creation_input_tokens", 0) or 0,
    }


class FixtureAdapter(ModelAdapter):
    """Deterministic adapter that replays canned findings from a fixture file.

    Lets the benchmark harness (and tests) run the whole pipeline — including
    scoring — without a network or an API key. The fixture is::

        {
          "hunts": {"<area>/<attack_class>": [ <finding>, ... ], ...},
          "validator_verdict": "confirmed"      # applied to every validation
        }

    The adapter tells a hunt call from a validation call by the prompt: a
    validation prompt starts with "Finding to disprove".
    """

    name = "fixture"

    def __init__(self, fixture: dict[str, Any], *, name: str = "fixture"):
        self.name = name
        self._hunts: dict[str, list] = fixture.get("hunts", {})
        self._verdict: str = fixture.get("validator_verdict", "confirmed")

    @classmethod
    def from_path(cls, path: str, **kw: Any) -> FixtureAdapter:
        import json
        from pathlib import Path
        return cls(json.loads(Path(path).read_text(encoding="utf-8")), **kw)

    def complete(self, system: str, prompt: str, *, max_tokens: int = 4096) -> ModelResponse:
        if prompt.lstrip().startswith("Finding to disprove"):
            return ModelResponse(outcome=Outcome.OK, text=f"VERDICT: {self._verdict}")
        area = _grep(prompt, "Area:")
        attack_class = _grep(prompt, "Attack class:")
        findings = self._hunts.get(f"{area}/{attack_class}", [])
        import json
        return ModelResponse(outcome=Outcome.OK,
                             text="```json\n" + json.dumps(findings) + "\n```")


def _grep(text: str, label: str) -> str:
    for line in text.splitlines():
        if line.strip().startswith(label):
            return line.split(label, 1)[1].strip()
    return ""


def _classify_exception(exc: Exception) -> Outcome:
    name = type(exc).__name__.lower()
    msg = str(exc).lower()
    retryable = ("overloaded", "ratelimit", "rate_limit", "timeout", "apiconnection",
                 "503", "502", "429", "500")
    if any(tok in name or tok in msg for tok in retryable):
        return Outcome.RETRYABLE
    return Outcome.FATAL


class MeteredAdapter(ModelAdapter):
    """Wraps an adapter and records each call's token usage to the store, so the
    report can estimate what a run cost. Transparent otherwise."""

    def __init__(self, inner: ModelAdapter, store: Any, run_id: str, repo: str, role: str):
        self.inner = inner
        self.name = inner.name
        self._store = store
        self._run_id = run_id
        self._repo = repo
        self._role = role

    @property
    def model(self) -> str:
        return getattr(self.inner, "model", self.inner.name)

    def complete(self, system: str, prompt: str, *, max_tokens: int = 4096) -> ModelResponse:
        resp = self.inner.complete(system, prompt, max_tokens=max_tokens)
        usage = (resp.raw or {}).get("usage") or {}
        if usage:
            self._store.add_usage(
                self._run_id, self._repo, self._role,
                (resp.raw or {}).get("model", self.model),
                int(usage.get("input_tokens", 0)),
                int(usage.get("output_tokens", 0)),
                int(usage.get("cache_read_tokens", 0)),
                int(usage.get("cache_creation_tokens", 0)),
            )
        return resp


# Registry so the CLI can select an adapter by a short name.
_BUILTIN = {"stub": lambda **kw: StubAdapter()}


def build_adapter(spec: str, *, effort: str | None = None) -> ModelAdapter:
    """Build an adapter from a short spec.

    ``stub``                 -> StubAdapter
    ``fixture:<path>``       -> FixtureAdapter replaying that fixture
    ``anthropic:<model-id>`` -> AnthropicAdapter(model=<model-id>)
    """
    if spec in _BUILTIN:
        return _BUILTIN[spec]()
    if spec.startswith("anthropic:"):
        kw = {"effort": effort} if effort else {}
        return AnthropicAdapter(model=spec.split(":", 1)[1], **kw)
    if spec.startswith("fixture:"):
        return FixtureAdapter.from_path(spec.split(":", 1)[1])
    raise ValueError(f"unknown adapter spec: {spec!r}")
