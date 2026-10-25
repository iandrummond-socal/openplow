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

    #: Whether :meth:`complete_with_tools` actually lets the model call tools.
    supports_tools: bool = False

    @abstractmethod
    def complete(self, system: str, prompt: str, *, max_tokens: int = 4096) -> ModelResponse:
        """Turn a prompt into text, classifying how the call went."""
        raise NotImplementedError

    def complete_with_tools(self, system: str, prompt: str, tools: Any, *,
                            max_tokens: int = 4096, max_rounds: int = 30) -> ModelResponse:
        """Like :meth:`complete`, but the model may call ``tools`` (an object with
        ``specs()`` and ``call(name, args)``, e.g. :class:`~openplow.repo_tools.RepoTools`)
        before answering. Adapters without tool support ignore the tools."""
        return self.complete(system, prompt, max_tokens=max_tokens)


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

    Prompt caching: the system prompt (which, with the tool definitions ahead
    of it, is shared by every call of the same kind) carries a cache breakpoint,
    and the tool loop also sets top-level automatic caching so each turn reads
    the conversation so far from cache instead of paying for it again.

    An optional :class:`~openplow.pricing.Budget` is checked before every API
    call and charged after it, so a spending cap holds even mid tool loop.

    Server-side refusal fallback is on by default (``fallbacks="default"``): when
    a safety classifier declines a request, the API re-runs it on Anthropic's
    recommended model for that refusal category within the same call. Pass
    ``fallbacks=None`` to turn it off. Haiku models have no server-side fallback,
    so it is never sent for them.
    """

    supports_tools = True

    def __init__(self, model: str, api_key: str | None = None, *, name: str | None = None,
                 effort: str | None = "high", fallbacks: str | None = "default",
                 budget: Any = None):
        self.model = model
        self.name = name or f"anthropic:{model}"
        self.effort = effort  # output_config effort; "high" is good for audit work
        self.fallbacks = fallbacks if fallbacks and "haiku" not in model else None
        self.budget = budget
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

    def _create(self, client: Any, kwargs: dict[str, Any]) -> Any:
        if self.budget is not None:
            self.budget.check(self.model, kwargs["max_tokens"])
        if self.fallbacks:
            msg = client.beta.messages.create(betas=[_FALLBACK_BETA],
                                              fallbacks=self.fallbacks, **kwargs)
        else:
            msg = client.messages.create(**kwargs)
        if self.budget is not None:
            usage = _extract_usage(msg)
            self.budget.charge(usage.get("model") or self.model, usage)
        return msg

    def complete(self, system: str, prompt: str, *, max_tokens: int = 4096) -> ModelResponse:
        # Note: temperature/top_p are intentionally not sent — current models
        # reject non-default sampling. Thinking is adaptive by default (omitted).
        try:
            client = self._ensure_client()
            kwargs: dict[str, Any] = {
                "model": self.model,
                "max_tokens": max_tokens,
                "system": _cached_system(system),
                "messages": [{"role": "user", "content": prompt}],
            }
            if self.effort:
                kwargs["output_config"] = {"effort": self.effort}
            msg = self._create(client, kwargs)
            text = "".join(
                block.text for block in msg.content if getattr(block, "type", None) == "text"
            )
            outcome = classify_body(text)
            return ModelResponse(outcome=outcome, text=text, raw={
                "stop_reason": getattr(msg, "stop_reason", None),
                "model": self.model,
                "usage": _extract_usage(msg),
                **_refusal_info(msg, self.model),
            })
        except Exception as exc:  # noqa: BLE001 - adapter boundary
            return ModelResponse(outcome=_classify_exception(exc), text="", error=str(exc))

    def complete_with_tools(self, system: str, prompt: str, tools: Any, *,
                            max_tokens: int = 4096, max_rounds: int = 30) -> ModelResponse:
        """Manual tool-use loop: run each requested tool locally and feed the
        results back until the model answers. After ``max_rounds`` tool rounds
        the model is told to answer and tools are switched off for the last call.

        ``raw`` carries a per-turn ``transcript`` (text, tool calls, truncated
        tool results, stop reason) so a miss can be diagnosed afterwards, plus
        summed ``usage`` and the per-call ``turn_usages`` for metering.
        """
        specs = tools.specs()
        messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
        transcript: list[dict[str, Any]] = []
        turn_usages: list[dict[str, int]] = []
        tool_rounds = 0
        final_call = False
        served_by: set[str] = set()
        fallbacks: list[dict[str, Any]] = []
        try:
            client = self._ensure_client()
            while True:
                kwargs: dict[str, Any] = {
                    "model": self.model,
                    "max_tokens": max_tokens,
                    "system": _cached_system(system),
                    "messages": messages,
                    "tools": specs,
                    # Automatic caching of the growing conversation tail.
                    "cache_control": {"type": "ephemeral"},
                }
                if final_call:
                    kwargs["tool_choice"] = {"type": "none"}
                if self.effort:
                    kwargs["output_config"] = {"effort": self.effort}
                msg = self._create(client, kwargs)
                turn_usages.append(_extract_usage(msg))
                info = _refusal_info(msg, self.model)
                stop = getattr(msg, "stop_reason", None)
                text = "".join(b.text for b in msg.content
                               if getattr(b, "type", None) == "text")
                calls = [b for b in msg.content if getattr(b, "type", None) == "tool_use"]
                turn: dict[str, Any] = {"stop_reason": stop, "text": text,
                                        "tool_calls": [{"name": c.name, "input": c.input}
                                                       for c in calls], **info}
                served_by.add(info["served_by"])
                fallbacks.extend(info["fallbacks"])
                transcript.append(turn)
                # Pass the assistant content back unchanged (thinking blocks included).
                messages.append({"role": "assistant", "content": msg.content})

                if stop == "pause_turn":
                    continue
                if stop != "tool_use" or not calls:
                    break

                results: list[dict[str, Any]] = []
                turn["tool_results"] = []
                for c in calls:
                    try:
                        out, is_error = tools.call(c.name, c.input), False
                    except Exception as exc:  # noqa: BLE001 - reported to the model
                        out, is_error = f"error: {exc}", True
                    results.append({"type": "tool_result", "tool_use_id": c.id,
                                    "content": out, "is_error": is_error})
                    turn["tool_results"].append(
                        {"name": c.name, "is_error": is_error,
                         "content": out if len(out) <= 2000 else out[:2000] + "...(truncated)"})
                tool_rounds += 1
                if tool_rounds >= max_rounds:
                    final_call = True
                    results.append({"type": "text", "text": (
                        "Tool budget exhausted. Give your final answer now, in the "
                        "required format, from what you have read.")})
                messages.append({"role": "user", "content": results})

            return ModelResponse(outcome=classify_body(text), text=text, raw={
                "stop_reason": stop,
                "model": self.model,
                "usage": _sum_usage(turn_usages),
                "turn_usages": turn_usages,
                "tool_rounds": tool_rounds,
                "transcript": transcript,
                "served_by": sorted(served_by),
                "fallbacks": fallbacks,
                "stop_details": info.get("stop_details"),
            })
        except Exception as exc:  # noqa: BLE001 - adapter boundary
            return ModelResponse(outcome=_classify_exception(exc), text="", error=str(exc),
                                 raw={"model": self.model, "usage": _sum_usage(turn_usages),
                                      "turn_usages": turn_usages, "transcript": transcript})


_FALLBACK_BETA = "server-side-fallback-2026-07-01"


def _cached_system(system: str) -> list[dict[str, Any]]:
    """System prompt as one text block with a cache breakpoint. Tools render
    before system, so this caches the tool definitions too."""
    return [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]


def served_model(resp: ModelResponse) -> str | None:
    """The model that wrote a response's final answer, when the adapter reports
    it — the fallback model if a refusal was re-run, else the requested one."""
    raw = resp.raw or {}
    turns = raw.get("transcript") or []
    if turns and isinstance(turns[-1], dict) and turns[-1].get("served_by"):
        return turns[-1]["served_by"]
    served = raw.get("served_by")
    return served if isinstance(served, str) else None


def _refusal_info(msg: Any, requested: str) -> dict[str, Any]:
    """Which model served a response, any fallback hops, and refusal details."""
    hops = [{"from": getattr(getattr(b, "from_", None), "model", None),
             "to": getattr(getattr(b, "to", None), "model", None)}
            for b in msg.content if getattr(b, "type", None) == "fallback"]
    details = getattr(msg, "stop_details", None)
    stop_details = None
    if details is not None:
        stop_details = {"category": getattr(details, "category", None),
                        "explanation": getattr(details, "explanation", None)}
    served = getattr(msg, "model", None)
    return {"served_by": served if isinstance(served, str) else requested,
            "fallbacks": hops, "stop_details": stop_details}


def _sum_usage(usages: list[dict[str, Any]]) -> dict[str, int]:
    total: dict[str, int] = {}
    for u in usages:
        for k, v in u.items():
            if isinstance(v, int):
                total[k] = total.get(k, 0) + v
    return total


def _extract_usage(msg: Any) -> dict[str, Any]:
    u = getattr(msg, "usage", None)
    if u is None:
        return {}
    served = getattr(msg, "model", None)
    return {
        **({"model": served} if isinstance(served, str) else {}),
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
    from .pricing import BudgetExceeded
    if isinstance(exc, BudgetExceeded):
        return Outcome.FATAL  # retrying cannot help; its message may contain "500"
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

    @property
    def supports_tools(self) -> bool:  # type: ignore[override]
        return self.inner.supports_tools

    def complete(self, system: str, prompt: str, *, max_tokens: int = 4096) -> ModelResponse:
        resp = self.inner.complete(system, prompt, max_tokens=max_tokens)
        self._record(resp)
        return resp

    def complete_with_tools(self, system: str, prompt: str, tools: Any, *,
                            max_tokens: int = 4096, max_rounds: int = 30) -> ModelResponse:
        resp = self.inner.complete_with_tools(system, prompt, tools, max_tokens=max_tokens,
                                              max_rounds=max_rounds)
        self._record(resp)
        return resp

    def _record(self, resp: ModelResponse) -> None:
        raw = resp.raw or {}
        # A tool loop makes several API calls; record each so "calls" stays honest.
        usages = raw.get("turn_usages") or ([raw["usage"]] if raw.get("usage") else [])
        for usage in usages:
            if not usage:
                continue
            # Bill each call to the model that served it (a fallback may differ).
            self._store.add_usage(
                self._run_id, self._repo, self._role,
                usage.get("model") or raw.get("model", self.model),
                int(usage.get("input_tokens", 0)),
                int(usage.get("output_tokens", 0)),
                int(usage.get("cache_read_tokens", 0)),
                int(usage.get("cache_creation_tokens", 0)),
            )


# Registry so the CLI can select an adapter by a short name.
_BUILTIN = {"stub": lambda **kw: StubAdapter()}


def build_adapter(spec: str, *, effort: str | None = None, budget: Any = None) -> ModelAdapter:
    """Build an adapter from a short spec.

    ``stub``                 -> StubAdapter
    ``fixture:<path>``       -> FixtureAdapter replaying that fixture
    ``anthropic:<model-id>`` -> AnthropicAdapter(model=<model-id>)
    """
    if spec in _BUILTIN:
        return _BUILTIN[spec]()
    if spec.startswith("anthropic:"):
        kw: dict[str, Any] = {"effort": effort} if effort else {}
        return AnthropicAdapter(model=spec.split(":", 1)[1], budget=budget, **kw)
    if spec.startswith("fixture:"):
        return FixtureAdapter.from_path(spec.split(":", 1)[1])
    raise ValueError(f"unknown adapter spec: {spec!r}")
