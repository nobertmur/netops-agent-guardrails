from netops_agent.cli import main

NOW = "2026-10-17T23:00:00Z"


def test_run_then_verify_succeeds(root, tmp_path, capsys):
    audit = tmp_path / "audit.jsonl"
    code = main(
        [
            "run",
            "--samples",
            str(root / "samples/incident.json"),
            "--policy",
            str(root / "policy.yml"),
            "--audit",
            str(audit),
            "--now",
            NOW,
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "findings=4" in out and "executed=4" in out and "audit log: " in out
    assert main(["verify", "--audit", str(audit)]) == 0


def test_verify_fails_on_a_tampered_log(root, tmp_path, capsys):
    audit = tmp_path / "audit.jsonl"
    main(
        [
            "run",
            "--samples",
            str(root / "samples/incident.json"),
            "--policy",
            str(root / "policy.yml"),
            "--audit",
            str(audit),
            "--now",
            NOW,
        ]
    )
    audit.write_text(audit.read_text().replace('"executed": 4', '"executed": 0'))
    capsys.readouterr()
    assert main(["verify", "--audit", str(audit)]) == 1
    assert "FAILED" in capsys.readouterr().out
