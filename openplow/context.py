"""Shared run context handed to every stage."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .db import Store
from .models import ModelAdapter
from .sandbox import Sandbox


@dataclass
class RunContext:
    run_id: str
    repo: Path                 # path to the target checkout
    out_dir: Path              # where human-readable artifacts land
    store: Store
    finder: ModelAdapter       # model that hunts
    validator: ModelAdapter    # a DIFFERENT model that tries to disprove
    sandbox: Sandbox

    @property
    def repo_name(self) -> str:
        return self.repo.name
