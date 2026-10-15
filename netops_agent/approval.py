"""Human approval, bound to the exact change that was shown to the human."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from .models import Approval, Decision, ProposedChange, clean_text


class Approver(Protocol):
    def approve(self, change: ProposedChange, decision: Decision) -> Approval: ...


class ApprovalMismatch(Exception):
    """The approval does not belong to the change about to run."""


class DenyAllApprover:
    """Safe default: nothing needing approval ever proceeds."""

    def approve(self, change: ProposedChange, decision: Decision) -> Approval:
        return Approval(False, "policy:deny-all", change.digest(), "no approver configured")


class ScriptedApprover:
    """For tests and simulations: a function decides, and the answer is still digest-bound."""

    def __init__(self, decide: Callable[[ProposedChange, Decision], bool], name: str = "scripted"):
        self._decide = decide
        self._name = name

    def approve(self, change: ProposedChange, decision: Decision) -> Approval:
        return Approval(self._decide(change, decision), self._name, change.digest())


class CLIApprover:
    """Ask a person at the terminal. Free text from proposers is sanitised before display."""

    def __init__(self, name: str = "operator"):
        self._name = name

    def approve(self, change: ProposedChange, decision: Decision) -> Approval:
        print(f"\nProposed change ({decision.risk.name.lower()} risk, source: {change.source})")
        print(f"  action : {change.action}")
        print(f"  device : {change.device}")
        print(f"  params : {change.params}")
        print(f"  why    : {clean_text(change.rationale)}")
        answer = input("Approve? type 'yes' to approve, anything else rejects: ").strip().lower()
        return Approval(answer == "yes", self._name, change.digest(), "interactive")


def verify_approval(change: ProposedChange, approval: Approval) -> None:
    """Raise unless the approval is positive and covers exactly this change."""
    if not approval.approved:
        raise ApprovalMismatch("change was not approved")
    if approval.change_digest != change.digest():
        raise ApprovalMismatch("approval was given for a different change than the one about to run")
