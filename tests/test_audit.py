import json

from netops_agent.audit import AuditLog


def make_log(tmp_path, n=4):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(n):
        log.append("finding", {"n": i}, ts=1000 + i)
    return log


def test_empty_log_verifies(tmp_path):
    assert AuditLog(tmp_path / "none.jsonl").verify() == (True, "0 records verified")


def test_intact_chain_verifies(tmp_path):
    ok, message = make_log(tmp_path).verify()
    assert ok and message == "4 records verified"


def test_editing_a_record_is_detected(tmp_path):
    log = make_log(tmp_path)
    lines = log.path.read_text().splitlines()
    record = json.loads(lines[1])
    record["payload"]["n"] = 999
    lines[1] = json.dumps(record, sort_keys=True)
    log.path.write_text("\n".join(lines) + "\n")
    ok, message = log.verify()
    assert not ok and "record 2" in message


def test_deleting_a_record_is_detected(tmp_path):
    log = make_log(tmp_path)
    lines = log.path.read_text().splitlines()
    del lines[1]
    log.path.write_text("\n".join(lines) + "\n")
    ok, message = log.verify()
    assert not ok and "record 3" in message


def test_reordering_records_is_detected(tmp_path):
    log = make_log(tmp_path)
    lines = log.path.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    log.path.write_text("\n".join(lines) + "\n")
    assert not log.verify()[0]


def test_appending_continues_the_chain(tmp_path):
    log = make_log(tmp_path, 2)
    log.append("finding", {"n": 2}, ts=2000)
    assert log.verify() == (True, "3 records verified")


def test_recent_executions_filters_by_time_and_device_changes(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    change = {"device": "leaf01"}
    log.append("execution", {"change": change, "modifies_device": True}, ts=100)
    log.append("execution", {"change": change, "modifies_device": True}, ts=5000)
    log.append("execution", {"change": change, "modifies_device": False}, ts=5001)  # a ticket
    log.append("decision", {"change": change}, ts=5002)
    assert log.recent_executions(since=1000) == [("leaf01", 5000)]
