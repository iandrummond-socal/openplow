"""Pipeline stages.

M1 ships the core four: recon, hunt, validate, report. Each stage is a function
that takes a :class:`~openplow.context.RunContext` and a task payload and does
one narrow thing, keeping its own context use small. Later waves (gapfill,
dedup, judgment, fixer) plug in the same way.
"""

from . import hunt, recon, report, validate

__all__ = ["hunt", "recon", "report", "validate"]

# Stage name -> handler. The orchestrator dispatches on this.
HANDLERS = {
    "recon": recon.run_task,
    "hunt": hunt.run_task,
    "validate": validate.run_task,
    "report": report.run_task,
}
