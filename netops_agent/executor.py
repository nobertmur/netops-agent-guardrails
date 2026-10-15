"""Executors turn an approved change into an effect.

No executor in this repository logs in to a device, on purpose. The two provided ones either
record what would happen or write a proposal file that a human (or a Git pull request, as in the
sibling network-automation-pipeline project) turns into a real change. A production executor
should open a pull request against the config repository so the usual review and rollout apply.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

import yaml

from .approval import verify_approval
from .models import Approval, ExecutionResult, ProposedChange


class Executor(Protocol):
    def execute(self, change: ProposedChange, approval: Approval) -> ExecutionResult: ...


class DryRunExecutor:
    """Records what would run. The default."""

    def __init__(self) -> None:
        self.calls: list[ProposedChange] = []

    def execute(self, change: ProposedChange, approval: Approval) -> ExecutionResult:
        verify_approval(change, approval)
        self.calls.append(change)
        return ExecutionResult("dry_run", f"would run {change.action} on {change.device} {change.params}")


class ProposalFileExecutor:
    """Writes each approved change to a YAML file for a human or a PR to pick up."""

    def __init__(self, directory: Path):
        self.directory = Path(directory)

    def execute(self, change: ProposedChange, approval: Approval) -> ExecutionResult:
        verify_approval(change, approval)
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"{change.digest()[:12]}-{change.action}-{change.device}.yml"
        body = {"change": change.to_dict(), "approval": approval.to_dict()}
        path.write_text(yaml.safe_dump(body, sort_keys=True))
        return ExecutionResult("proposed", f"wrote {path.name}")
