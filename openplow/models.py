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

    def __init__(self, model: str, api_key: str | None = None, *, name: str | None = None):
        self.model = model
        self.name = name or f"anthropic:{model}"
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
        try:
            client = self._ensure_client()
            msg = client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(
                block.text for block in msg.content if getattr(block, "type", None) == "text"
            )
            outcome = classify_body(text)
            return ModelResponse(outcome=outcome, text=text,
                                 raw={"stop_reason": getattr(msg, "stop_reason", None)})
        except Exception as exc:  # noqa: BLE001 - adapter boundary
            return ModelResponse(outcome=_classify_exception(exc), text="", error=str(exc))


def _classify_exception(exc: Exception) -> Outcome:
    name = type(exc).__name__.lower()
    msg = str(exc).lower()
    retryable = ("overloaded", "ratelimit", "rate_limit", "timeout", "apiconnection",
                 "503", "502", "429", "500")
    if any(tok in name or tok in msg for tok in retryable):
        return Outcome.RETRYABLE
    return Outcome.FATAL


# Registry so the CLI can select an adapter by a short name.
_BUILTIN = {"stub": lambda **kw: StubAdapter()}


def build_adapter(spec: str, **kwargs: Any) -> ModelAdapter:
    """Build an adapter from a short spec.

    ``stub``                 -> StubAdapter
    ``anthropic:<model-id>`` -> AnthropicAdapter(model=<model-id>)
    """
    if spec in _BUILTIN:
        return _BUILTIN[spec](**kwargs)
    if spec.startswith("anthropic:"):
        return AnthropicAdapter(model=spec.split(":", 1)[1], **kwargs)
    raise ValueError(f"unknown adapter spec: {spec!r}")
