"""Tests for the spending cap and prompt-caching request shape. No network."""

from __future__ import annotations

from pathlib import Path

import pytest

from openplow import benchmark as bm
from openplow.models import AnthropicAdapter, Outcome
from openplow.pricing import Budget, BudgetExceeded
from openplow.repo_tools import RepoTools

SAMPLE = Path(__file__).resolve().parent.parent / "benchmarks" / "sample" / "benchmark.json"
FIXTURE = Path(__file__).resolve().parent.parent / "benchmarks" / "sample" / "fixture.json"


class _Usage:
    input_tokens, output_tokens = 100_000, 10_000
    cache_read_input_tokens = cache_creation_input_tokens = 0


class _Block:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _Msg:
    stop_reason = "end_turn"
    model = "claude-opus-5-5"

    def __init__(self, content=None):
        self.content = content or [_Block(type="text", text="[]")]
        self.usage = _Usage()


class _Client:
    def __init__(self, script=None):
        self.requests: list[dict] = []
        self._script = list(script or [])
        self.messages = self
        self.beta = self

    def create(self, **kwargs):
        self.requests.append(kwargs)
        return self._script.pop(0) if self._script else _Msg()


# ---- Budget -------------------------------------------------------------

def test_budget_reserves_worst_case_output():
    b = Budget(1.00)
    b.check("claude-opus-5-5", 8192)          # $0.16 reserve fits
    b.spent = 0.90
    with pytest.raises(BudgetExceeded):
        b.check("claude-opus-5-5", 8192)      # 0.90 + 0.16 > 1.00
    assert b.exhausted and b.refused == 1


def test_budget_charges_served_model_rates():
    b = Budget(10)
    b.charge("claude-opus-4-8", {"input_tokens": 1_000_000})
    assert b.spent == pytest.approx(5.0)


# ---- adapter ---------------------------------------------------------------

def test_adapter_charges_budget_and_refuses_when_full(tmp_path):
    budget = Budget(0.70)
    client = _Client()
    a = AnthropicAdapter(model="claude-opus-5-5", api_key="x", budget=budget)
    a._client = client
    assert a.complete("s", "p", max_tokens=1000).ok       # costs $0.60
    assert budget.spent == pytest.approx(0.60)
    resp = a.complete("s", "p", max_tokens=8192)           # 0.60 + 0.16 > 0.70
    assert resp.outcome is Outcome.FATAL and "spending cap" in (resp.error or "")
    assert len(client.requests) == 1                       # never sent


def test_tool_loop_stops_mid_loop_at_cap(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    call = _Msg([_Block(type="tool_use", id="t", name="list_files", input={"path": "."})])
    call.stop_reason = "tool_use"
    client = _Client([call, call, call])
    budget = Budget(1.21)                                  # room for two $0.60 turns
    a = AnthropicAdapter(model="claude-opus-5-5", api_key="x", budget=budget)
    a._client = client
    resp = a.complete_with_tools("s", "p", RepoTools(tmp_path), max_tokens=1000)
    assert resp.outcome is Outcome.FATAL and len(client.requests) == 2
    assert budget.spent <= 1.21


def test_requests_carry_cache_breakpoints(tmp_path):
    client = _Client()
    a = AnthropicAdapter(model="claude-opus-5-5", api_key="x")
    a._client = client
    a.complete("system text", "p")
    a.complete_with_tools("system text", "p", RepoTools(tmp_path))
    single, loop = client.requests
    for req in (single, loop):
        assert req["system"] == [{"type": "text", "text": "system text",
                                  "cache_control": {"type": "ephemeral"}}]
    assert "cache_control" not in single           # nothing to reuse in one shot
    assert loop["cache_control"] == {"type": "ephemeral"}


# ---- benchmark ---------------------------------------------------------------

def test_benchmark_skips_targets_once_cap_reached(tmp_path):
    spec = bm.load_spec(SAMPLE)
    report = bm.run_benchmark(spec, finder_spec=f"fixture:{FIXTURE}", validator_spec=None,
                              sandbox_kind="stub", out_dir=tmp_path, max_cost=0.0)
    assert report.totals["cap_reached"] is True
    assert report.totals["skipped_targets"] == [t.name for t in spec.targets]
    assert "Spending cap reached" in (tmp_path / "benchmark-report.md").read_text()


def test_benchmark_without_cap_reports_no_cap(tmp_path):
    spec = bm.load_spec(SAMPLE)
    report = bm.run_benchmark(spec, finder_spec=f"fixture:{FIXTURE}", validator_spec=None,
                              sandbox_kind="stub", out_dir=tmp_path)
    assert report.totals["cap_reached"] is False and report.totals["skipped_targets"] == []
