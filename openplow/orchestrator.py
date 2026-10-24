"""The orchestrator.

Splits a run into narrow tasks and drains the queue, keeping each agent's job
small. The queued stages are the producers and consumers — recon enqueues
hunts, hunts enqueue validations — and they run through the SQLite-backed queue
so a crashed run resumes by requeuing whatever was mid-flight.

Three stages run as finalization, after the queue drains, so they always see the
complete set of findings (late finds are validated before the report is cut):

1. **Gapfill** (bounded rounds) re-queues hunts for thin ``(area x class)``
   cells; any new hunts and their validations drain before the next round.
2. **Dedup** consolidates findings that share a root cause.
3. **Report** writes the artifacts.

M1 ran tasks sequentially in one process. The queue lives in SQLite, so moving
to a worker pool (50-200 workers, per Cloudflare) is a matter of running several
drainers against the same store.
"""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass

from .context import RunContext
from .stages import HANDLERS, dedup, gapfill, report

MAX_ATTEMPTS = 3
BACKOFF_BASE = 2.0  # seconds; 2, 4, 8 ...
MAX_GAPFILL_ROUNDS = 1


@dataclass
class RunSummary:
    run_id: str
    processed: int
    failed: int
    final: dict | None


def _run_one(ctx: RunContext, task) -> None:
    handler = HANDLERS.get(task.stage)
    if handler is None:
        raise RuntimeError(f"no handler for stage {task.stage!r}")
    handler(ctx, task.payload)


def _drain(ctx: RunContext, *, sleep) -> tuple[int, int]:
    """Process queued tasks until the queue is empty. Returns (processed, failed)."""
    processed = 0
    failed = 0
    while True:
        task = ctx.store.next_pending(ctx.run_id)
        if task is None:
            break
        try:
            _run_one(ctx, task)
            ctx.store.finish_task(task.run_id, task.task_id, "done")
            processed += 1
        except Exception as exc:  # noqa: BLE001 - task boundary
            err = f"{exc}\n{traceback.format_exc()}"
            if task.attempts < MAX_ATTEMPTS:
                # Transient: back off and requeue by marking pending again.
                sleep(BACKOFF_BASE ** task.attempts)
                ctx.store.finish_task(task.run_id, task.task_id, "pending", error=str(exc))
            else:
                ctx.store.finish_task(task.run_id, task.task_id, "failed", error=err)
                failed += 1
    return processed, failed


def start_run(ctx: RunContext, *, resume: bool = False, sleep=time.sleep) -> RunSummary:
    """Seed a run with recon (or requeue a crashed one), drain it, then run the
    gapfill -> dedup -> report finalization."""
    ctx.store.create_run(ctx.run_id, ctx.repo_name, ctx.finder.name)
    if resume:
        if ctx.store.requeue_stale_running(ctx.run_id):
            ctx.store.set_run_status(ctx.run_id, "running")
    else:
        ctx.store.add_task("recon:initial", ctx.run_id, ctx.repo_name, "recon", payload={})

    processed, failed = _drain(ctx, sleep=sleep)

    # Gapfill: re-queue thin cells and drain the new hunts, up to a cap.
    for round_no in range(1, MAX_GAPFILL_ROUNDS + 1):
        result = gapfill.run_task(ctx, {"round": round_no})
        if not result.get("enqueued"):
            break
        p, f = _drain(ctx, sleep=sleep)
        processed += p
        failed += f

    # Dedup, then report — both see the full, validated finding set.
    dedup.run_task(ctx, {})
    final = report.run_task(ctx, {})

    ctx.store.set_run_status(ctx.run_id, "failed" if failed else "done")
    return RunSummary(run_id=ctx.run_id, processed=processed, failed=failed, final=final)
