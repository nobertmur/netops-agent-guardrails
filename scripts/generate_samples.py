"""Generate samples/incident.json: a deterministic simulated incident.

Run from the repository root:  python scripts/generate_samples.py
Every series is fixed (no randomness), so the demo output never changes.
"""

import json
from pathlib import Path

START = 1_792_000_000  # arbitrary fixed epoch
STEP = 60  # one sample a minute


def at(i: int) -> int:
    return START + i * STEP


def build() -> list[dict]:
    rows: list[dict] = []

    def add(i, device, metric, subject, value):
        rows.append({"timestamp": at(i), "device": device, "metric": metric, "subject": subject, "value": value})

    for i in range(30):
        # leaf01 swp1: clean, then sustained heavy errors -> critical
        add(i, "leaf01", "if_error_rate", "swp1", 0.1 if i < 25 else 40.0)
        # spine01 swp2: same pattern on a protected device
        add(i, "spine01", "if_error_rate", "swp2", 0.2 if i < 25 else 35.0)
        # leaf02 BGP session to swp2 drops four times
        add(i, "leaf02", "bgp_session_up", "swp2", 0.0 if i in (22, 24, 26, 28) else 1.0)
        # leaf03 latency: steady 2ms with a slight wobble, then a jump to 30ms
        add(i, "leaf03", "latency_ms", "swp1", (2.0 + (0.1 if i % 2 else -0.1)) if i < 27 else 30.0)
        # leaf02 swp1: perfectly healthy control series
        add(i, "leaf02", "if_error_rate", "swp1", 0.1)

    # A hostile row: a name that tries to smuggle a command. The loader must reject it.
    rows.append(
        {"timestamp": at(30), "device": "leaf01", "metric": "if_error_rate", "subject": "swp1; reboot", "value": 99}
    )
    return rows


if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "samples" / "incident.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(build(), indent=1) + "\n")
    print(f"wrote {out}")
