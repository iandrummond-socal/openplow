"""The orchestrator.

Splits a run into narrow tasks and drains the queue, keeping each agent's job
small. Stages are producer/consumer: recon enqueues hunts, hunts enqueue
validations, and a report task closes the run. Everything is persisted, so a
crashed run resumes by requeuing whatever was mid-flight.

M1 runs tasks sequentially in one process. The queue lives in SQLite, so moving
to a worker pool (50-200 workers, per Cloudflare) is a matter of running several
drainers against the same store.
"""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass

from .context import RunContext
from .stages import HANDLERS

MAX_ATTEMPTS = 3
BACKOFF_BASE = 2.0  # seconds; 2, 4, 8 ...


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


def drain(ctx: RunContext, *, sleep=time.sleep) -> RunSummary:
    """Process tasks until the queue is empty. Returns a summary."""
    processed = 0
    failed = 0
    final: dict | None = None

    while True:
        task = ctx.store.next_pending(ctx.run_id)
        if task is None:
            break
        try:
            _run_one(ctx, task)
            ctx.store.finish_task(task.task_id, "done")
            processed += 1
            if task.stage == "report":
                final = {"ok": True}
        except Exception as exc:  # noqa: BLE001 - task boundary
            err = f"{exc}\n{traceback.format_exc()}"
            if task.attempts < MAX_ATTEMPTS:
                # Transient: back off and requeue by marking pending again.
                sleep(BACKOFF_BASE ** task.attempts)
                ctx.store.finish_task(task.task_id, "pending", error=str(exc))
            else:
                ctx.store.finish_task(task.task_id, "failed", error=err)
                failed += 1

    ctx.store.set_run_status(ctx.run_id, "failed" if failed else "done")
    return RunSummary(run_id=ctx.run_id, processed=processed, failed=failed, final=final)


def start_run(ctx: RunContext, *, resume: bool = False) -> RunSummary:
    """Seed a run with a recon task (or requeue a crashed one) and drain it."""
    ctx.store.create_run(ctx.run_id, ctx.repo_name, ctx.finder.name)
    if resume:
        requeued = ctx.store.requeue_stale_running(ctx.run_id)
        if requeued:
            ctx.store.set_run_status(ctx.run_id, "running")
    else:
        ctx.store.add_task("recon:initial", ctx.run_id, ctx.repo_name, "recon", payload={})
    return drain(ctx)
