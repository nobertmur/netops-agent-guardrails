"""The guardrails. Nothing reaches an executor without a verdict from here.

The policy treats every proposal as untrusted, whether it came from rules or from an LLM.
It never takes the proposer's word for risk: risk comes from the action's entry in policy.yml.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .models import Decision, ProposedChange, Risk, Verdict


@dataclass
class PolicyContext:
    """What the policy needs to know about the recent past."""

    now: float  # epoch seconds
    recent_changes: Sequence[tuple[str, float]] = ()  # (device, epoch) of changes in the last hour
    run_change_count: int = 0  # changes already allowed during this run
    _per_device: Counter = field(init=False, repr=False, default_factory=Counter)

    def __post_init__(self) -> None:
        self._per_device = Counter(device for device, _ in self.recent_changes)

    def changes_on(self, device: str) -> int:
        return self._per_device[device]

    def record(self, device: str) -> None:
        self._per_device[device] += 1
        self.run_change_count += 1


def _minutes(clock: str) -> int:
    hours, minutes = clock.split(":")
    return int(hours) * 60 + int(minutes)


class Policy:
    def __init__(self, config: dict[str, Any]):
        if config.get("version") != 1:
            raise ValueError("policy: unsupported or missing 'version' (expected 1)")
        self.known_devices = set(config.get("known_devices", []))
        self.protected_devices = set(config.get("protected_devices", []))
        self.actions: dict[str, dict[str, Any]] = {}
        for name, spec in (config.get("actions") or {}).items():
            risk = str(spec.get("risk", "")).upper()
            if risk not in Risk.__members__ or risk == "CRITICAL":
                raise ValueError(f"policy: action {name!r} needs risk low, medium or high")
            self.actions[name] = {
                "risk": Risk[risk],
                # Actions that never touch a device (like opening a ticket) skip protected-device
                # escalation and do not count toward change limits.
                "modifies_device": bool(spec.get("modifies_device", True)),
                "params": {key: re.compile(rx) for key, rx in (spec.get("params") or {}).items()},
            }
        limits = config.get("limits") or {}
        self.max_per_run = int(limits.get("max_changes_per_run", 3))
        self.max_per_device_hour = int(limits.get("max_changes_per_device_per_hour", 1))
        window = config.get("change_window")
        self.window = (_minutes(window["start"]), _minutes(window["end"])) if window else None

    @classmethod
    def from_file(cls, path: Path) -> Policy:
        return cls(yaml.safe_load(Path(path).read_text()))

    def modifies_device(self, action: str) -> bool:
        spec = self.actions.get(action)
        return bool(spec and spec["modifies_device"])

    def in_window(self, now: float) -> bool:
        """True when `now` (UTC) is inside the change window. The window may wrap midnight."""
        if self.window is None:
            return True
        moment = datetime.fromtimestamp(now, tz=timezone.utc)
        minute = moment.hour * 60 + moment.minute
        start, end = self.window
        return start <= minute < end if start <= end else minute >= start or minute < end

    def evaluate(self, change: ProposedChange, ctx: PolicyContext) -> Decision:
        spec = self.actions.get(change.action)
        if spec is None:
            return Decision(Verdict.DENY, Risk.CRITICAL, (f"action '{change.action}' is not on the allowlist",))

        reasons: list[str] = []
        if change.device not in self.known_devices:
            reasons.append(f"device '{change.device}' is not a known device")

        allowed = spec["params"]
        for key in sorted(set(change.params) - set(allowed)):
            reasons.append(f"parameter '{key}' is not allowed for {change.action}")
        for key, pattern in allowed.items():
            if key not in change.params:
                reasons.append(f"parameter '{key}' is required for {change.action}")
            elif not pattern.fullmatch(str(change.params[key])):
                reasons.append(f"parameter '{key}' has an invalid value")
        if reasons:
            return Decision(Verdict.DENY, spec["risk"], tuple(reasons))

        risk: Risk = spec["risk"]
        if spec["modifies_device"] and change.device in self.protected_devices:
            risk = risk.escalate()
            if risk == Risk.CRITICAL:
                return Decision(
                    Verdict.DENY,
                    risk,
                    (f"{change.action} on protected device '{change.device}' is human-only",),
                )

        if risk > Risk.LOW:
            if not self.in_window(ctx.now):
                reasons.append("outside the change window")
            if ctx.run_change_count >= self.max_per_run:
                reasons.append(f"run limit of {self.max_per_run} changes reached")
            if ctx.changes_on(change.device) >= self.max_per_device_hour:
                reasons.append(f"device limit of {self.max_per_device_hour} change(s) per hour reached")
        if reasons:
            return Decision(Verdict.DENY, risk, tuple(reasons))

        if risk == Risk.LOW:
            return Decision(Verdict.ALLOW_AUTO, risk, ("low-risk action",))
        return Decision(Verdict.NEEDS_APPROVAL, risk, (f"{risk.name.lower()}-risk action needs a human",))
