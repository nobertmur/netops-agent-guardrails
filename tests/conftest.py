from datetime import datetime, timezone
from pathlib import Path

import pytest

from netops_agent.policy import Policy

ROOT = Path(__file__).resolve().parent.parent
IN_WINDOW = datetime(2026, 10, 17, 23, 0, tzinfo=timezone.utc).timestamp()  # 23:00 UTC
OUT_OF_WINDOW = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc).timestamp()  # 12:00 UTC


@pytest.fixture()
def root() -> Path:
    return ROOT


@pytest.fixture()
def policy() -> Policy:
    return Policy.from_file(ROOT / "policy.yml")
