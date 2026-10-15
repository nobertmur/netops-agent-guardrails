"""Plain data types shared by every stage of the pipeline."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum
from typing import Any

# Names that reach prompts, approval screens and commands must look like identifiers.
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def canonical_json(value: Any) -> str:
    """Stable JSON used for hashing and the audit log."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def clean_text(text: str, max_len: int = 300) -> str:
    """Strip control characters, collapse whitespace and cap the length of free text."""
    return " ".join(_CONTROL.sub(" ", str(text)).split())[:max_len]


class Severity(str, Enum):
    WARNING = "warning"
    CRITICAL = "critical"


class Risk(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def escalate(self) -> Risk:
        return Risk(min(self + 1, Risk.CRITICAL))


class Verdict(str, Enum):
    ALLOW_AUTO = "allow_auto"
    NEEDS_APPROVAL = "needs_approval"
    DENY = "deny"


@dataclass(frozen=True)
class Sample:
    """One telemetry reading."""

    timestamp: int  # epoch seconds
    device: str
    metric: str  # if_error_rate | bgp_session_up | latency_ms
    subject: str  # interface or peer the reading is about
    value: float


@dataclass(frozen=True)
class Finding:
    """Something the detectors noticed. Structured data only, no device-supplied free text."""

    kind: str
    device: str
    subject: str
    severity: Severity
    evidence: dict[str, Any]

    @property
    def id(self) -> str:
        return f"{self.kind}:{self.device}:{self.subject}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["id"] = self.id
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True)
class ProposedChange:
    """An action someone (rules or an LLM) wants taken. Always untrusted until policy says otherwise."""

    finding_id: str
    action: str
    device: str
    params: dict[str, str] = field(default_factory=dict)
    rationale: str = ""
    source: str = "rules"  # rules | llm

    def digest(self) -> str:
        """Fingerprint of what would actually run. Approvals are bound to this value."""
        body = {
            "finding_id": self.finding_id,
            "action": self.action,
            "device": self.device,
            "params": self.params,
        }
        return hashlib.sha256(canonical_json(body).encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["digest"] = self.digest()
        return data


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    risk: Risk
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict.value, "risk": self.risk.name.lower(), "reasons": list(self.reasons)}


@dataclass(frozen=True)
class Approval:
    approved: bool
    approver: str
    change_digest: str
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ExecutionResult:
    status: str  # dry_run | proposed | applied
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
