import json

from conftest import IN_WINDOW, OUT_OF_WINDOW

from netops_agent.approval import DenyAllApprover, ScriptedApprover
from netops_agent.audit import AuditLog
from netops_agent.executor import DryRunExecutor
from netops_agent.models import Approval
from netops_agent.pipeline import Pipeline
from netops_agent.proposer import LLMProposer, RuleProposer
from netops_agent.telemetry import load_samples


def build(policy, tmp_path, approver=None, proposer=None, now=IN_WINDOW):
    executor = DryRunExecutor()
    pipeline = Pipeline(
        proposer or RuleProposer(),
        policy,
        approver or DenyAllApprover(),
        executor,
        AuditLog(tmp_path / "audit.jsonl"),
        clock=lambda: now,
    )
    return pipeline, executor


def test_incident_with_default_deny_runs_only_low_risk_actions(root, policy, tmp_path):
    samples, rejected = load_samples(root / "samples" / "incident.json")
    pipeline, executor = build(policy, tmp_path)
    summary = pipeline.run(samples, rejected)

    assert summary.findings == 4
    assert {c.action for c in executor.calls} == {"open_ticket"}
    assert summary.denied == 1  # shutdown on protected spine01
    assert summary.rejected_by_human == 2  # nobody approved the shutdown or the soft clear
    assert len(rejected) == 1  # the 'swp1; reboot' row never reached the detectors
    assert pipeline.audit.verify()[0]


def test_a_human_approval_unlocks_exactly_what_they_approved(root, policy, tmp_path):
    samples, _ = load_samples(root / "samples" / "incident.json")
    approver = ScriptedApprover(lambda change, decision: change.action == "clear_bgp_soft", "alice")
    pipeline, executor = build(policy, tmp_path, approver)
    summary = pipeline.run(samples)

    actions = sorted((c.action, c.device) for c in executor.calls)
    assert ("clear_bgp_soft", "leaf02") in actions
    assert not any(a == "shutdown_interface" for a, _ in actions)
    assert summary.rejected_by_human == 1


def test_nothing_that_changes_a_device_runs_outside_the_window(root, policy, tmp_path):
    samples, _ = load_samples(root / "samples" / "incident.json")
    approver = ScriptedApprover(lambda c, d: True)
    pipeline, executor = build(policy, tmp_path, approver, now=OUT_OF_WINDOW)
    pipeline.run(samples)
    assert {c.action for c in executor.calls} == {"open_ticket"}


def test_hourly_device_limit_holds_across_runs(root, policy, tmp_path):
    samples, _ = load_samples(root / "samples" / "incident.json")
    approver = ScriptedApprover(lambda c, d: c.action == "clear_bgp_soft")
    first, exec_first = build(policy, tmp_path, approver)
    first.run(samples)
    second, exec_second = build(policy, tmp_path, approver)  # same audit log, same hour
    second.run(samples)

    assert sum(c.action == "clear_bgp_soft" for c in exec_first.calls) == 1
    assert sum(c.action == "clear_bgp_soft" for c in exec_second.calls) == 0


def test_a_hostile_llm_cannot_widen_what_runs(root, policy, tmp_path):
    """The model asks for a reboot and a shell command. Policy denies both; the audit log shows why."""
    samples, _ = load_samples(root / "samples" / "incident.json")
    hostile = json.dumps(
        {
            "changes": [
                {"action": "reboot_device", "params": {}, "rationale": "needed"},
                {"action": "shutdown_interface", "params": {"interface": "swp1; reload"}, "rationale": "ok"},
            ]
        }
    )
    proposer = LLMProposer(lambda prompt: hostile, list(policy.actions))
    pipeline, executor = build(policy, tmp_path, ScriptedApprover(lambda c, d: True), proposer)
    summary = pipeline.run(samples)

    assert executor.calls == []
    assert summary.denied == 8  # two denied proposals for each of four findings
    reasons = [
        r for e in pipeline.audit.events() if e["type"] == "decision" for r in e["payload"]["decision"]["reasons"]
    ]
    assert any("not on the allowlist" in r for r in reasons)
    assert any("invalid value" in r for r in reasons)


def test_unparseable_llm_output_is_audited_not_executed(root, policy, tmp_path):
    samples, _ = load_samples(root / "samples" / "incident.json")
    proposer = LLMProposer(lambda prompt: "Sure! Just run: reboot", list(policy.actions))
    pipeline, executor = build(policy, tmp_path, proposer=proposer)
    summary = pipeline.run(samples)
    assert executor.calls == [] and summary.proposer_errors == 4
    assert any(e["type"] == "proposal_rejected" for e in pipeline.audit.events())


def test_executor_is_blocked_if_an_approval_does_not_match(root, policy, tmp_path):
    """An approver that returns approval for some other change must not unlock execution."""

    class SwappingApprover:
        def approve(self, change, decision):
            return Approval(True, "mallory", "0" * 64)  # a digest for a different change

    samples, _ = load_samples(root / "samples" / "incident.json")
    pipeline, executor = build(policy, tmp_path, SwappingApprover())
    summary = pipeline.run(samples)
    assert {c.action for c in executor.calls} == {"open_ticket"}
    assert summary.outcomes["approval_mismatch"] == 2
    assert any(e["type"] == "execution_blocked" for e in pipeline.audit.events())
