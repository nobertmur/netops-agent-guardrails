"""Explainable detectors: thresholds, transition counts and a z-score baseline.

No trained model is involved. Each finding carries the numbers that triggered it,
so an operator (or an approval screen) can see exactly why it fired.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass

from .models import Finding, Sample, Severity


@dataclass(frozen=True)
class DetectorConfig:
    error_warn: float = 1.0  # errors per second
    error_critical: float = 10.0
    error_sustained: int = 3  # consecutive samples at or above the threshold
    flap_window_s: int = 600
    flap_warn: int = 3  # up-to-down transitions inside the window
    latency_recent: int = 3
    latency_min_baseline: int = 10
    latency_z: float = 4.0
    latency_std_floor_ms: float = 0.5


def _series(samples: list[Sample]) -> dict[tuple[str, str, str], list[Sample]]:
    grouped: dict[tuple[str, str, str], list[Sample]] = defaultdict(list)
    for sample in samples:
        grouped[(sample.device, sample.metric, sample.subject)].append(sample)
    for series in grouped.values():
        series.sort(key=lambda s: s.timestamp)
    return grouped


def detect_interface_errors(samples: list[Sample], cfg: DetectorConfig) -> list[Finding]:
    findings = []
    for (device, metric, subject), series in _series(samples).items():
        if metric != "if_error_rate" or len(series) < cfg.error_sustained:
            continue
        tail = [s.value for s in series[-cfg.error_sustained :]]
        if all(v >= cfg.error_critical for v in tail):
            severity, threshold = Severity.CRITICAL, cfg.error_critical
        elif all(v >= cfg.error_warn for v in tail):
            severity, threshold = Severity.WARNING, cfg.error_warn
        else:
            continue
        evidence = {"last_values": tail, "threshold_per_s": threshold, "sustained_samples": len(tail)}
        findings.append(Finding("interface_errors", device, subject, severity, evidence))
    return findings


def detect_bgp_flaps(samples: list[Sample], cfg: DetectorConfig) -> list[Finding]:
    findings = []
    for (device, metric, subject), series in _series(samples).items():
        if metric != "bgp_session_up" or not series:
            continue
        newest = series[-1].timestamp
        recent = [s for s in series if s.timestamp >= newest - cfg.flap_window_s]
        drops = sum(1 for a, b in zip(recent, recent[1:], strict=False) if a.value >= 1 and b.value < 1)
        if drops >= cfg.flap_warn:
            evidence = {"drops_in_window": drops, "window_s": cfg.flap_window_s, "threshold": cfg.flap_warn}
            findings.append(Finding("bgp_flap", device, subject, Severity.WARNING, evidence))
    return findings


def detect_latency_anomalies(samples: list[Sample], cfg: DetectorConfig) -> list[Finding]:
    findings = []
    for (device, metric, subject), series in _series(samples).items():
        if metric != "latency_ms" or len(series) < cfg.latency_min_baseline + cfg.latency_recent:
            continue
        values = [s.value for s in series]
        baseline, recent = values[: -cfg.latency_recent], values[-cfg.latency_recent :]
        mean = statistics.fmean(baseline)
        std = max(statistics.pstdev(baseline), cfg.latency_std_floor_ms)  # flat baselines must not divide by ~0
        z = (statistics.fmean(recent) - mean) / std
        if z >= cfg.latency_z:
            evidence = {
                "baseline_mean_ms": round(mean, 2),
                "recent_mean_ms": round(statistics.fmean(recent), 2),
                "z_score": round(z, 1),
                "threshold_z": cfg.latency_z,
            }
            findings.append(Finding("latency_anomaly", device, subject, Severity.WARNING, evidence))
    return findings


def detect_all(samples: list[Sample], cfg: DetectorConfig | None = None) -> list[Finding]:
    cfg = cfg or DetectorConfig()
    findings = (
        detect_interface_errors(samples, cfg) + detect_bgp_flaps(samples, cfg) + detect_latency_anomalies(samples, cfg)
    )
    return sorted(findings, key=lambda f: f.id)
