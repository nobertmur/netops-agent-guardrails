"""Detect, propose, judge, approve, execute, and audit every step."""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field

from .approval import ApprovalMismatch, Approver, verify_approval
from .audit import AuditLog
from .detect import DetectorConfig, detect_all
from .executor import Executor
from .models import Approval, Sample, Verdict
from .policy import Policy, PolicyContext
from .proposer import ProposalError, Proposer

HOUR_S = 3600


@dataclass
class RunSummary:
    findings: int = 0
    proposals: int = 0
    executed: int = 0
    denied: int = 0
    rejected_by_human: int = 0
    proposer_errors: int = 0
    outcomes: Counter = field(default_factory=Counter)


class Pipeline:
    def __init__(
        self,
        proposer: Proposer,
        policy: Policy,
        approver: Approver,
        executor: Executor,
        audit: AuditLog,
        detector_config: DetectorConfig | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.proposer = proposer
        self.policy = policy
        self.approver = approver
        self.executor = executor
        self.audit = audit
        self.detector_config = detector_config
        self.clock = clock

    def run(self, samples: list[Sample], rejected_rows: list[str] | None = None) -> RunSummary:
        now = self.clock()
        summary = RunSummary()
        self.audit.append("run_started", {"samples": len(samples)}, now)
        for reason in rejected_rows or []:
            self.audit.append("sample_rejected", {"reason": reason}, now)

        ctx = PolicyContext(now=now, recent_changes=self.audit.recent_executions(now - HOUR_S))
        findings = detect_all(samples, self.detector_config)
        summary.findings = len(findings)

        for finding in findings:
            self.audit.append("finding", finding.to_dict(), now)
            try:
                changes = self.proposer.propose(finding)
            except ProposalError as exc:
                summary.proposer_errors += 1
                self.audit.append("proposal_rejected", {"finding": finding.id, "reason": str(exc)}, now)
                continue

            for change in changes:
                summary.proposals += 1
                decision = self.policy.evaluate(change, ctx)
                self.audit.append("decision", {"change": change.to_dict(), "decision": decision.to_dict()}, now)

                if decision.verdict == Verdict.DENY:
                    summary.denied += 1
                    summary.outcomes["denied"] += 1
                    continue

                if decision.verdict == Verdict.ALLOW_AUTO:
                    approval = Approval(True, "policy:auto-low-risk", change.digest())
                else:
                    approval = self.approver.approve(change, decision)
                    self.audit.append("approval", {"change": change.to_dict(), "approval": approval.to_dict()}, now)
                    if not approval.approved:
                        summary.rejected_by_human += 1
                        summary.outcomes["not_approved"] += 1
                        continue

                try:
                    verify_approval(change, approval)
                    result = self.executor.execute(change, approval)
                except ApprovalMismatch as exc:
                    summary.denied += 1
                    summary.outcomes["approval_mismatch"] += 1
                    self.audit.append("execution_blocked", {"change": change.to_dict(), "reason": str(exc)}, now)
                    continue

                modifies = self.policy.modifies_device(change.action)
                self.audit.append(
                    "execution",
                    {"change": change.to_dict(), "result": result.to_dict(), "modifies_device": modifies},
                    now,
                )
                if modifies:
                    ctx.record(change.device)
                summary.executed += 1
                summary.outcomes[result.status] += 1

        self.audit.append("run_finished", {"findings": summary.findings, "executed": summary.executed}, now)
        return summary
