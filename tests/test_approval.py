import pytest

from netops_agent.approval import (
    ApprovalMismatch,
    DenyAllApprover,
    ScriptedApprover,
    verify_approval,
)
from netops_agent.executor import DryRunExecutor, ProposalFileExecutor
from netops_agent.models import Approval, Decision, ProposedChange, Risk, Verdict

DECISION = Decision(Verdict.NEEDS_APPROVAL, Risk.HIGH)
CHANGE_A = ProposedChange("f1", "shutdown_interface", "leaf01", {"interface": "swp1"})
CHANGE_B = ProposedChange("f1", "shutdown_interface", "leaf01", {"interface": "swp2"})


def test_default_approver_denies_everything():
    approval = DenyAllApprover().approve(CHANGE_A, DECISION)
    assert not approval.approved
    with pytest.raises(ApprovalMismatch):
        verify_approval(CHANGE_A, approval)


def test_approval_is_bound_to_the_exact_change():
    approval = ScriptedApprover(lambda c, d: True).approve(CHANGE_A, DECISION)
    verify_approval(CHANGE_A, approval)  # fine
    with pytest.raises(ApprovalMismatch, match="different change"):
        verify_approval(CHANGE_B, approval)  # same action, different interface


def test_digest_ignores_rationale_but_not_parameters():
    reworded = ProposedChange("f1", "shutdown_interface", "leaf01", {"interface": "swp1"}, "new words")
    assert reworded.digest() == CHANGE_A.digest()
    assert CHANGE_B.digest() != CHANGE_A.digest()


def test_executors_refuse_a_mismatched_approval(tmp_path):
    approval = Approval(True, "someone", CHANGE_A.digest())
    for executor in (DryRunExecutor(), ProposalFileExecutor(tmp_path)):
        with pytest.raises(ApprovalMismatch):
            executor.execute(CHANGE_B, approval)


def test_proposal_file_executor_writes_a_reviewable_file(tmp_path):
    approval = Approval(True, "someone", CHANGE_A.digest())
    result = ProposalFileExecutor(tmp_path).execute(CHANGE_A, approval)
    assert result.status == "proposed"
    files = list(tmp_path.glob("*.yml"))
    assert len(files) == 1 and "shutdown_interface-leaf01" in files[0].name
