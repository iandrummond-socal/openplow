"""Tests for usage metering, pricing, and the Anthropic adapter call path."""

from __future__ import annotations

from pathlib import Path

from openplow import pricing
from openplow.db import Store
from openplow.models import AnthropicAdapter, MeteredAdapter, ModelAdapter, ModelResponse, Outcome

# ---- pricing ------------------------------------------------------------

def test_estimate_cost_known_model():
    u = pricing.Usage(input_tokens=1_000_000, output_tokens=1_000_000)
    # opus-5-5 is $4 in / $20 out per MTok
    assert pricing.estimate_cost("claude-opus-5-5", u) == 24.0


def test_estimate_cost_cache_read():
    u = pricing.Usage(cache_read_tokens=1_000_000)
    assert pricing.estimate_cost("claude-opus-5-5", u) == 0.20


def test_estimate_cost_unknown_model_is_none():
    assert pricing.estimate_cost("some-future-model", pricing.Usage(input_tokens=10)) is None


def test_model_from_adapter_name():
    assert pricing.model_from_adapter_name("anthropic:claude-opus-5-5") == "claude-opus-5-5"
    assert pricing.model_from_adapter_name("stub") is None


# ---- metered adapter ----------------------------------------------------

class _FakeModel(ModelAdapter):
    name = "anthropic:claude-haiku-5-5"
    model = "claude-haiku-5-5"

    def complete(self, system, prompt, *, max_tokens=4096):
        return ModelResponse(outcome=Outcome.OK, text="STUB_OK", raw={
            "model": "claude-haiku-5-5",
            "usage": {"input_tokens": 1000, "output_tokens": 200,
                      "cache_read_tokens": 0, "cache_creation_tokens": 0},
        })


def test_metered_adapter_records_usage(tmp_path: Path):
    store = Store(tmp_path / "db.sqlite")
    store.create_run("run-x", "repo", "fake")
    metered = MeteredAdapter(_FakeModel(), store, "run-x", "repo", "finder")
    metered.complete("sys", "prompt")
    metered.complete("sys", "prompt")

    rows = store.usage_by_model("run-x")
    assert len(rows) == 1
    assert rows[0]["calls"] == 2
    assert rows[0]["input_tokens"] == 2000
    assert rows[0]["output_tokens"] == 400
    cost = pricing.estimate_cost(rows[0]["model"],
                                 pricing.Usage(rows[0]["input_tokens"], rows[0]["output_tokens"]))
    assert cost is not None and cost > 0


# ---- Anthropic adapter call path (fake client, no network) --------------

class _FakeBlock:
    type = "text"
    text = "```json\n[]\n```"


class _FakeUsage:
    input_tokens = 123
    output_tokens = 45
    cache_read_input_tokens = 0
    cache_creation_input_tokens = 0


class _FakeMsg:
    stop_reason = "end_turn"

    def __init__(self):
        self.content = [_FakeBlock()]
        self.usage = _FakeUsage()


class _FakeClient:
    def __init__(self):
        self.last_kwargs = None
        self.messages = self
        self.beta = self

    def create(self, **kwargs):
        self.last_kwargs = kwargs
        return _FakeMsg()


def test_anthropic_adapter_builds_request_and_extracts_usage():
    adapter = AnthropicAdapter(model="claude-opus-5-5", api_key="x", effort="high")
    fake = _FakeClient()
    adapter._client = fake  # inject, bypassing real SDK/network

    resp = adapter.complete("system prompt", "user prompt", max_tokens=8192)
    assert resp.ok
    # effort routed into output_config; no temperature/top_p sent
    assert fake.last_kwargs["output_config"] == {"effort": "high"}
    assert "temperature" not in fake.last_kwargs and "top_p" not in fake.last_kwargs
    assert fake.last_kwargs["model"] == "claude-opus-5-5"
    assert resp.raw["usage"]["input_tokens"] == 123
    assert resp.raw["model"] == "claude-opus-5-5"


def test_anthropic_adapter_no_effort_omits_output_config():
    adapter = AnthropicAdapter(model="claude-opus-5-5", api_key="x", effort=None)
    fake = _FakeClient()
    adapter._client = fake
    adapter.complete("s", "p")
    assert "output_config" not in fake.last_kwargs
