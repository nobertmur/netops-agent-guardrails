from netops_agent.detect import (
    DetectorConfig,
    detect_all,
    detect_bgp_flaps,
    detect_interface_errors,
    detect_latency_anomalies,
)
from netops_agent.models import Sample, Severity

CFG = DetectorConfig()


def series(metric, values, device="leaf01", subject="swp1", step=60):
    return [Sample(1_000 + i * step, device, metric, subject, v) for i, v in enumerate(values)]


def test_sustained_critical_errors_fire():
    findings = detect_interface_errors(series("if_error_rate", [0.1, 0.1, 40, 40, 40]), CFG)
    assert [f.severity for f in findings] == [Severity.CRITICAL]
    assert findings[0].id == "interface_errors:leaf01:swp1"
    assert findings[0].evidence["last_values"] == [40, 40, 40]


def test_warning_band_is_reported_as_warning():
    findings = detect_interface_errors(series("if_error_rate", [0.1, 2, 3, 4]), CFG)
    assert [f.severity for f in findings] == [Severity.WARNING]


def test_a_single_spike_does_not_fire():
    assert detect_interface_errors(series("if_error_rate", [0.1, 0.1, 0.1, 50, 0.1]), CFG) == []


def test_too_few_samples_do_not_fire():
    assert detect_interface_errors(series("if_error_rate", [50, 50]), CFG) == []


def test_bgp_flaps_counted_inside_window():
    findings = detect_bgp_flaps(series("bgp_session_up", [1, 0, 1, 0, 1, 0, 1]), CFG)
    assert len(findings) == 1
    assert findings[0].evidence["drops_in_window"] == 3


def test_old_flaps_outside_window_are_ignored():
    values = [1, 0, 1, 0, 1, 0] + [1] * 30  # flaps happened long before the newest sample
    assert detect_bgp_flaps(series("bgp_session_up", values), CFG) == []


def test_steady_session_does_not_fire():
    assert detect_bgp_flaps(series("bgp_session_up", [1] * 20), CFG) == []


def test_latency_jump_is_flagged_with_evidence():
    values = [2.0, 2.1, 1.9] * 5 + [30, 30, 30]
    findings = detect_latency_anomalies(series("latency_ms", values), CFG)
    assert len(findings) == 1
    assert findings[0].evidence["recent_mean_ms"] == 30.0
    assert findings[0].evidence["z_score"] >= CFG.latency_z


def test_flat_baseline_does_not_divide_by_zero():
    values = [2.0] * 15 + [2.1, 2.1, 2.1]  # tiny change on a perfectly flat series
    assert detect_latency_anomalies(series("latency_ms", values), CFG) == []


def test_not_enough_baseline_means_no_finding():
    assert detect_latency_anomalies(series("latency_ms", [2.0] * 5 + [50, 50, 50]), CFG) == []


def test_detect_all_is_sorted_and_deterministic():
    samples = series("if_error_rate", [40] * 5) + series("bgp_session_up", [1, 0] * 4, device="leaf02")
    ids = [f.id for f in detect_all(samples)]
    assert ids == sorted(ids)
    assert ids == [f.id for f in detect_all(list(reversed(samples)))]
