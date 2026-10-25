"""Tests for the finder's read-only repo tools, the Anthropic tool-use loop, and
hunt transcripts. Fake clients only — no network, no API key."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openplow.context import RunContext
from openplow.db import Store
from openplow.models import AnthropicAdapter, MeteredAdapter, ModelAdapter, ModelResponse, Outcome
from openplow.repo_tools import RepoTools, ToolError
from openplow.sandbox import StubSandbox
from openplow.stages import hunt


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "target"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("import os\n\ndef run(cmd):\n    os.system(cmd)\n")
    (tmp_path / "secret.txt").write_text("outside")
    return root


# ---- RepoTools ------------------------------------------------------------

def test_read_file_numbers_lines(repo):
    out = RepoTools(repo).call("read_file", {"path": "src/app.py", "start_line": 3})
    assert out.splitlines()[0].strip() == "3  def run(cmd):"
    assert "import os" not in out


def test_list_and_grep(repo):
    tools = RepoTools(repo)
    assert tools.call("list_files", {"path": "."}) == "src/app.py"
    assert tools.call("grep", {"pattern": r"os\.system"}) == "src/app.py:4:     os.system(cmd)"


@pytest.mark.parametrize("path", ["../secret.txt", "/etc/passwd", "src/../../secret.txt"])
def test_paths_cannot_escape_root(repo, path):
    with pytest.raises(ToolError):
        RepoTools(repo).call("read_file", {"path": path})


def test_symlink_out_of_root_is_refused(repo):
    (repo / "link.txt").symlink_to(repo.parent / "secret.txt")
    with pytest.raises(ToolError):
        RepoTools(repo).call("read_file", {"path": "link.txt"})
    assert "link.txt" not in RepoTools(repo).call("list_files", {"path": "."})


def test_bad_inputs_are_tool_errors(repo):
    tools = RepoTools(repo)
    with pytest.raises(ToolError):
        tools.call("grep", {"pattern": "("})
    with pytest.raises(ToolError):
        tools.call("read_file", {"path": "src/app.py", "start_line": "1"})
    with pytest.raises(ToolError):
        tools.call("delete_file", {"path": "src/app.py"})


# ---- Anthropic tool-use loop (fake client) -------------------------------

class _Block:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _Usage:
    def __init__(self, i, o):
        self.input_tokens, self.output_tokens = i, o
        self.cache_read_input_tokens = self.cache_creation_input_tokens = 0


class _Msg:
    def __init__(self, stop, content, usage=(10, 5)):
        self.stop_reason, self.content, self.usage = stop, content, _Usage(*usage)


class _ScriptedClient:
    """Returns the scripted messages in order, recording each request."""

    def __init__(self, script):
        self._script = list(script)
        self.requests: list[dict] = []
        self.messages = self

    def create(self, **kwargs):
        self.requests.append({**kwargs, "messages": list(kwargs["messages"])})
        return self._script.pop(0)


def _tool_use(id_, name, args):
    return _Block(type="tool_use", id=id_, name=name, input=args)


def test_loop_runs_tools_and_returns_final_text(repo):
    client = _ScriptedClient([
        _Msg("tool_use", [_tool_use("t1", "read_file", {"path": "src/app.py"})], (100, 20)),
        _Msg("end_turn", [_Block(type="text", text="```json\n[]\n```")], (200, 30)),
    ])
    adapter = AnthropicAdapter(model="claude-opus-5-5", api_key="x")
    adapter._client = client
    resp = adapter.complete_with_tools("sys", "prompt", RepoTools(repo))

    assert resp.ok and resp.text == "```json\n[]\n```"
    assert [t["name"] for t in client.requests[0]["tools"]] == ["list_files", "read_file", "grep"]
    result = client.requests[1]["messages"][-1]["content"][0]
    assert result["type"] == "tool_result" and result["tool_use_id"] == "t1"
    assert "os.system(cmd)" in result["content"] and result["is_error"] is False
    assert resp.raw["usage"] == {"input_tokens": 300, "output_tokens": 50,
                                 "cache_read_tokens": 0, "cache_creation_tokens": 0}
    assert len(resp.raw["turn_usages"]) == 2
    assert resp.raw["transcript"][0]["tool_calls"] == [
        {"name": "read_file", "input": {"path": "src/app.py"}}]


def test_loop_reports_tool_errors_to_model(repo):
    client = _ScriptedClient([
        _Msg("tool_use", [_tool_use("t1", "read_file", {"path": "../secret.txt"})]),
        _Msg("end_turn", [_Block(type="text", text="[]")]),
    ])
    adapter = AnthropicAdapter(model="claude-opus-5-5", api_key="x")
    adapter._client = client
    adapter.complete_with_tools("sys", "prompt", RepoTools(repo))
    result = client.requests[1]["messages"][-1]["content"][0]
    assert result["is_error"] is True and "escapes" in result["content"]


def test_loop_forces_answer_after_round_budget(repo):
    call = _Msg("tool_use", [_tool_use("t", "list_files", {"path": "."})])
    client = _ScriptedClient([call, call, _Msg("end_turn", [_Block(type="text", text="[]")])])
    adapter = AnthropicAdapter(model="claude-opus-5-5", api_key="x")
    adapter._client = client
    resp = adapter.complete_with_tools("sys", "prompt", RepoTools(repo), max_rounds=2)
    assert resp.ok and resp.raw["tool_rounds"] == 2
    assert "tool_choice" not in client.requests[1]
    assert client.requests[2]["tool_choice"] == {"type": "none"}


def test_metered_records_each_turn(tmp_path, repo):
    client = _ScriptedClient([
        _Msg("tool_use", [_tool_use("t1", "list_files", {"path": "."})]),
        _Msg("end_turn", [_Block(type="text", text="[]")]),
    ])
    inner = AnthropicAdapter(model="claude-opus-5-5", api_key="x")
    inner._client = client
    store = Store(tmp_path / "db.sqlite")
    store.create_run("r", "repo", "x")
    metered = MeteredAdapter(inner, store, "r", "repo", "finder")
    assert metered.supports_tools
    metered.complete_with_tools("sys", "prompt", RepoTools(repo))
    assert store.usage_by_model("r")[0]["calls"] == 2


# ---- hunt stage: tools + transcripts --------------------------------------

class _ToolFinder(ModelAdapter):
    """Reads a file through the tools, then answers with fixed text."""

    name = "tool-finder"
    supports_tools = True

    def __init__(self, text):
        self._text = text
        self.read: str | None = None
        self.system: str | None = None

    def complete(self, system, prompt, *, max_tokens=4096):
        raise AssertionError("hunt should use complete_with_tools")

    def complete_with_tools(self, system, prompt, tools, *, max_tokens=4096, max_rounds=30):
        self.system = system
        self.read = tools.call("read_file", {"path": "src/app.py"})
        return ModelResponse(outcome=Outcome.OK, text=self._text,
                             raw={"stop_reason": "end_turn", "tool_rounds": 1,
                                  "transcript": [{"text": self._text}]})


def _ctx(tmp_path, repo, finder):
    out = tmp_path / "out"
    out.mkdir()
    store = Store(tmp_path / "db.sqlite")
    store.create_run("run-t", repo.name, finder.name)
    return RunContext(run_id="run-t", repo=repo, out_dir=out, store=store, finder=finder,
                      validator=finder, sandbox=StubSandbox(out / "scratch"))


def test_hunt_gives_finder_the_repo_and_saves_transcript(tmp_path, repo):
    finder = _ToolFinder('Nothing here.\n```json\n[{"id": "x", "title": "t"}]\n```')
    ctx = _ctx(tmp_path, repo, finder)
    result = hunt.run_task(ctx, {"area": "src", "attack_class": "cloud-and-deployment"})

    assert "os.system(cmd)" in (finder.read or "")
    assert "read_file" in (finder.system or "")
    assert result["dropped"] == 1
    record = json.loads((ctx.out_dir / "transcripts" / "hunt"
                         / "src__cloud-and-deployment__d1.json").read_text())
    assert record["text"].startswith("Nothing here.")
    assert record["tool_rounds"] == 1
    assert record["parsed"] == 1 and record["filed"] == 0
    assert record["drops"][0]["id"] == "x"


def test_hunt_flags_unparseable_output(tmp_path, repo):
    ctx = _ctx(tmp_path, repo, _ToolFinder("I could not decide."))
    hunt.run_task(ctx, {"area": "src", "attack_class": "cloud-and-deployment"})
    wishes = [w["item"] for w in ctx.store.wishes("run-t")]
    assert any("unparseable hunter output" in w for w in wishes)


def test_hunt_does_not_flag_explicit_empty_answer(tmp_path, repo):
    ctx = _ctx(tmp_path, repo, _ToolFinder("Nothing found.\n```json\n[]\n```"))
    hunt.run_task(ctx, {"area": "src", "attack_class": "cloud-and-deployment"})
    assert ctx.store.wishes("run-t") == []


# ---- poc.kind -------------------------------------------------------------

def _finding(kind: str) -> dict:
    return {"id": "cmd-1", "title": "shell injection", "attack_class": "cloud-and-deployment",
            "threat_model": {"attacker": "remote", "boundary": "input -> shell"},
            "location": {"file": "src/app.py", "line": 4},
            "description": "cmd reaches os.system",
            "poc": {"kind": kind, "content": "print('x')", "observed": "x"},
            "patch": None}


def test_python_poc_kind_is_filed_as_script(tmp_path, repo):
    ctx = _ctx(tmp_path, repo, _ToolFinder("```json\n" + json.dumps([_finding("Python")])
                                           + "\n```"))
    result = hunt.run_task(ctx, {"area": "src", "attack_class": "cloud-and-deployment"})
    assert result["findings"] == 1
    assert ctx.store.findings("run-t")[0]["poc"]["kind"] == "script"


def test_other_language_poc_kind_is_still_dropped(tmp_path, repo):
    ctx = _ctx(tmp_path, repo, _ToolFinder("```json\n" + json.dumps([_finding("bash")])
                                           + "\n```"))
    result = hunt.run_task(ctx, {"area": "src", "attack_class": "cloud-and-deployment"})
    assert result["findings"] == 0 and result["dropped"] == 1


def test_system_prompt_lists_poc_kinds(tmp_path, repo):
    finder = _ToolFinder("[]")
    hunt.run_task(_ctx(tmp_path, repo, finder),
                  {"area": "src", "attack_class": "cloud-and-deployment"})
    assert all(k in (finder.system or "") for k in ('"test"', '"script"', '"input"', '"trace"'))


def test_cell_class_wins_and_model_label_kept_as_weakness(tmp_path, repo):
    f = _finding("script")
    f["attack_class"] = "OS command injection (CWE-78)"
    ctx = _ctx(tmp_path, repo, _ToolFinder("```json\n" + json.dumps([f]) + "\n```"))
    hunt.run_task(ctx, {"area": "src", "attack_class": "client-side"})
    stored = ctx.store.findings("run-t")[0]
    assert stored["attack_class"] == "client-side"
    assert stored["weakness"] == "OS command injection (CWE-78)"


def test_system_prompt_states_observed_and_patch_rules(tmp_path, repo):
    finder = _ToolFinder("[]")
    hunt.run_task(_ctx(tmp_path, repo, finder),
                  {"area": "src", "attack_class": "cloud-and-deployment"})
    assert "exact substring" in finder.system and "@@ -start,count +start,count @@" in finder.system


# ---- patch gate: miscounted hunks ------------------------------------------

_MISCOUNTED = """--- a/src/app.py
+++ b/src/app.py
@@ -3,2 +3,9 @@
 def run(cmd):
-    os.system(cmd)
+    import subprocess
+    subprocess.run(["echo", cmd], check=False)
"""


def test_recount_hunks_fixes_line_counts():
    from openplow.poc import recount_hunks
    assert "@@ -3,2 +3,3 @@" in recount_hunks(_MISCOUNTED)


def test_apply_patch_recovers_from_miscounted_hunk(tmp_path, repo):
    from openplow.poc import apply_patch
    target = tmp_path / "copy"
    import shutil
    shutil.copytree(repo, target)
    ok, reason = apply_patch(target, {"patch": _MISCOUNTED})
    assert ok and "recomputed" in reason
    assert "subprocess.run" in (target / "src" / "app.py").read_text()


# ---- validator gets the tools ----------------------------------------------

def test_validator_reads_repo_and_saves_transcript(tmp_path, repo):
    from openplow.stages import validate

    class _Validator(_ToolFinder):
        name = "tool-validator"

    validator = _Validator("Read src/app.py; os.system(cmd) is reachable.\nVERDICT: confirmed")
    ctx = _ctx(tmp_path, repo, _ToolFinder("[]"))
    ctx.validator = validator
    f = _finding("input")
    f["verdict"] = "needs_validation"
    ctx.store.upsert_finding("run-t", repo.name, "hunt", f)
    result = validate.run_task(ctx, {"finding_id": "cmd-1"})
    assert result["verdict"] == "confirmed"
    assert "os.system(cmd)" in (validator.read or "")
    assert "read_file" in (validator.system or "")
    record = json.loads((ctx.out_dir / "transcripts" / "validate" / "cmd-1.json").read_text())
    assert record["text"].endswith("VERDICT: confirmed")
