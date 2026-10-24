"""Pipeline stages.

Queued stages (dispatched through ``HANDLERS`` by the orchestrator): recon,
hunt, validate. Finalization stages run directly after the queue drains:
gapfill (which enqueues more hunts), dedup, report. Each stage is a function
that takes a :class:`~openplow.context.RunContext` and a task payload and does
one narrow thing, keeping its own context use small.
"""

from . import dedup, gapfill, hunt, recon, report, validate

__all__ = ["dedup", "gapfill", "hunt", "recon", "report", "validate"]

# Stage name -> handler for queued tasks. Gapfill/dedup/report are invoked
# directly by the orchestrator as finalization, not pulled from the queue.
HANDLERS = {
    "recon": recon.run_task,
    "hunt": hunt.run_task,
    "validate": validate.run_task,
}
