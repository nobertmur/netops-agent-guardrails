"""Append-only, hash-chained audit log (JSON Lines).

Each record stores the hash of the previous one, so editing, deleting or reordering any line
breaks verification from that point on. This detects tampering; it does not prevent it, so ship
the log to write-once storage as well in a real deployment.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .models import canonical_json

GENESIS = "0" * 64


def _hash(prev_hash: str, record: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical_json(record)).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)

    def events(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open() as handle:
            for line in handle:
                if line.strip():
                    yield json.loads(line)

    def _last_hash(self) -> tuple[str, int]:
        last_hash, count = GENESIS, 0
        for event in self.events():
            last_hash, count = event["hash"], event["seq"]
        return last_hash, count

    def append(self, event_type: str, payload: dict[str, Any], ts: float) -> dict[str, Any]:
        prev_hash, seq = self._last_hash()
        record = {"seq": seq + 1, "ts": ts, "type": event_type, "payload": payload, "prev_hash": prev_hash}
        record["hash"] = _hash(prev_hash, {k: v for k, v in record.items() if k != "hash"})
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def verify(self) -> tuple[bool, str]:
        """Return (ok, message). The message names the first record that fails."""
        expected_prev, expected_seq = GENESIS, 1
        for event in self.events():
            body = {k: v for k, v in event.items() if k != "hash"}
            if event.get("seq") != expected_seq:
                return False, f"record {event.get('seq')}: expected sequence number {expected_seq}"
            if event.get("prev_hash") != expected_prev:
                return False, f"record {event['seq']}: previous-hash link is broken"
            if event.get("hash") != _hash(expected_prev, body):
                return False, f"record {event['seq']}: contents do not match their hash"
            expected_prev, expected_seq = event["hash"], expected_seq + 1
        return True, f"{expected_seq - 1} records verified"

    def recent_executions(self, since: float) -> list[tuple[str, float]]:
        """(device, timestamp) of every device-changing execution at or after `since`."""
        return [
            (event["payload"]["change"]["device"], event["ts"])
            for event in self.events()
            if event["type"] == "execution" and event["ts"] >= since and event["payload"].get("modifies_device", True)
        ]
