"""Load telemetry samples, rejecting anything that does not look like a clean reading."""

from __future__ import annotations

import json
from pathlib import Path

from .models import SAFE_NAME, Sample

METRICS = {"if_error_rate", "bgp_session_up", "latency_ms"}


def parse_sample(row: dict) -> Sample:
    """Turn one raw row into a Sample or raise ValueError saying why not."""
    try:
        sample = Sample(
            timestamp=int(row["timestamp"]),
            device=str(row["device"]),
            metric=str(row["metric"]),
            subject=str(row["subject"]),
            value=float(row["value"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"malformed row: {exc}") from exc
    if sample.metric not in METRICS:
        raise ValueError(f"unknown metric {sample.metric!r}")
    for label, text in (("device", sample.device), ("subject", sample.subject)):
        if not SAFE_NAME.match(text):
            raise ValueError(f"unsafe {label} name {text!r}")
    return sample


def load_samples(path: Path) -> tuple[list[Sample], list[str]]:
    """Return (good samples sorted by time, human-readable rejection reasons)."""
    rows = json.loads(Path(path).read_text())
    samples: list[Sample] = []
    rejected: list[str] = []
    for index, row in enumerate(rows):
        try:
            samples.append(parse_sample(row))
        except ValueError as exc:
            rejected.append(f"row {index}: {exc}")
    samples.sort(key=lambda s: (s.timestamp, s.device, s.metric, s.subject))
    return samples, rejected
