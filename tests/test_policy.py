from datetime import datetime, timezone

import pytest
from conftest import IN_WINDOW, OUT_OF_WINDOW

from netops_agent.models import ProposedChange, Risk, Verdict
from netops_agent.policy import Policy, PolicyContext


def change(action="open_ticket", device="leaf01", **params):
    return ProposedChange("f1", action, device, params)


def ctx(now=IN_WINDOW, recent=(), run_count=0):
    return PolicyContext(now=now, recent_changes=recent, run_change_count=run_count)


def test_low_risk_is_auto_allowed(policy):
    decision = policy.evaluate(change("open_ticket"), ctx())
    assert (decision.verdict, decision.risk) == (Verdict.ALLOW_AUTO, Risk.LOW)


def test_medium_and_high_need_a_human(policy):
    assert policy.evaluate(change("clear_bgp_soft", peer="swp1"), ctx()).verdict == Verdict.NEEDS_APPROVAL
    assert policy.evaluate(change("shutdown_interface", interface="swp1"), ctx()).verdict == Verdict.NEEDS_APPROVAL


def test_unlisted_action_is_denied(policy):
    decision = policy.evaluate(change("reboot_device"), ctx())
    assert decision.verdict == Verdict.DENY
    assert "not on the allowlist" in decision.reasons[0]


def test_unknown_device_is_denied(policy):
    decision = policy.evaluate(change("open_ticket", device="core99"), ctx())
    assert decision.verdict == Verdict.DENY
    assert any("not a known device" in r for r in decision.reasons)


@pytest.mark.parametrize("bad", ["swp1; reboot", "swp1 && reload", "../../etc", "", "swp", "eth0", "swp1\nreload"])
def test_injection_style_parameter_values_are_denied(policy, bad):
    decision = policy.evaluate(change("shutdown_interface", interface=bad), ctx())
    assert decision.verdict == Verdict.DENY
    assert any("invalid value" in r for r in decision.reasons)


def test_extra_and_missing_parameters_are_denied(policy):
    extra = policy.evaluate(change("shutdown_interface", interface="swp1", force="yes"), ctx())
    missing = policy.evaluate(change("shutdown_interface"), ctx())
    assert extra.verdict == missing.verdict == Verdict.DENY
    assert any("'force' is not allowed" in r for r in extra.reasons)
    assert any("'interface' is required" in r for r in missing.reasons)


def test_protected_device_escalates_risk(policy):
    ticket = policy.evaluate(change("open_ticket", device="spine01"), ctx())
    soft_clear = policy.evaluate(change("clear_bgp_soft", device="spine01", peer="swp1"), ctx())
    assert ticket.verdict == Verdict.ALLOW_AUTO  # open_ticket never touches the device
    assert soft_clear.risk == Risk.HIGH and soft_clear.verdict == Verdict.NEEDS_APPROVAL


def test_high_risk_on_protected_device_is_denied_outright(policy):
    decision = policy.evaluate(change("shutdown_interface", device="spine01", interface="swp2"), ctx())
    assert decision.verdict == Verdict.DENY
    assert decision.risk == Risk.CRITICAL


def test_changes_outside_the_window_are_denied_but_tickets_are_not(policy):
    assert policy.evaluate(change("clear_bgp_soft", peer="swp1"), ctx(now=OUT_OF_WINDOW)).verdict == Verdict.DENY
    assert policy.evaluate(change("open_ticket"), ctx(now=OUT_OF_WINDOW)).verdict == Verdict.ALLOW_AUTO


def test_window_wraps_midnight(policy):
    def at(hour, minute=0):
        return datetime(2026, 10, 17, hour, minute, tzinfo=timezone.utc).timestamp()

    assert policy.in_window(at(22, 0))
    assert policy.in_window(at(23, 59))
    assert policy.in_window(at(3, 59))
    assert not policy.in_window(at(4, 0))
    assert not policy.in_window(at(21, 59))


def test_run_limit_blocks_further_changes(policy):
    decision = policy.evaluate(change("clear_bgp_soft", peer="swp1"), ctx(run_count=3))
    assert decision.verdict == Verdict.DENY
    assert any("run limit" in r for r in decision.reasons)


def test_per_device_hourly_limit(policy):
    recent = [("leaf01", IN_WINDOW - 600)]
    blocked = policy.evaluate(change("clear_bgp_soft", device="leaf01", peer="swp1"), ctx(recent=recent))
    other = policy.evaluate(change("clear_bgp_soft", device="leaf02", peer="swp1"), ctx(recent=recent))
    assert blocked.verdict == Verdict.DENY
    assert other.verdict == Verdict.NEEDS_APPROVAL


def test_policy_without_a_window_never_blocks_on_time():
    policy = Policy({"version": 1, "known_devices": ["a"], "actions": {"x": {"risk": "medium"}}})
    assert policy.in_window(OUT_OF_WINDOW)


@pytest.mark.parametrize(
    "config",
    [
        {"known_devices": []},  # no version
        {"version": 1, "actions": {"x": {"risk": "critical"}}},  # critical cannot be assigned
        {"version": 1, "actions": {"x": {}}},  # risk missing
    ],
)
def test_bad_policy_files_are_rejected(config):
    with pytest.raises(ValueError):
        Policy(config)
