"""Command line: run the pipeline on a telemetry file, or verify an audit log."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from .approval import CLIApprover, DenyAllApprover
from .audit import AuditLog
from .executor import DryRunExecutor, ProposalFileExecutor
from .pipeline import Pipeline
from .policy import Policy
from .proposer import RuleProposer
from .telemetry import load_samples


def _parse_now(text: str | None) -> float | None:
    if text is None:
        return None
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def cmd_run(args: argparse.Namespace) -> int:
    samples, rejected = load_samples(args.samples)
    policy = Policy.from_file(args.policy)
    fixed_now = _parse_now(args.now)
    executor = ProposalFileExecutor(args.proposals_dir) if args.executor == "proposal-files" else DryRunExecutor()
    approver = CLIApprover() if args.approver == "interactive" else DenyAllApprover()
    kwargs = {"clock": (lambda: fixed_now)} if fixed_now is not None else {}
    pipeline = Pipeline(RuleProposer(), policy, approver, executor, AuditLog(args.audit), **kwargs)

    summary = pipeline.run(samples, rejected)
    print(f"findings={summary.findings} proposals={summary.proposals} executed={summary.executed}")
    print(f"denied={summary.denied} not_approved={summary.rejected_by_human} rejected_rows={len(rejected)}")
    ok, message = AuditLog(args.audit).verify()
    print(f"audit log: {message}" if ok else f"audit log FAILED: {message}")
    return 0 if ok else 1


def cmd_verify(args: argparse.Namespace) -> int:
    ok, message = AuditLog(args.audit).verify()
    print(message if ok else f"FAILED: {message}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netops-agent", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="detect, propose, judge and (dry-)execute")
    run.add_argument("--samples", type=Path, required=True)
    run.add_argument("--policy", type=Path, default=Path("policy.yml"))
    run.add_argument("--audit", type=Path, default=Path("audit.jsonl"))
    run.add_argument("--approver", choices=["deny", "interactive"], default="deny")
    run.add_argument("--executor", choices=["dry-run", "proposal-files"], default="dry-run")
    run.add_argument("--proposals-dir", type=Path, default=Path("proposals"))
    run.add_argument("--now", help="ISO time to use instead of the clock, e.g. 2026-10-17T23:00:00Z")
    run.set_defaults(func=cmd_run)

    verify = sub.add_parser("verify", help="check the audit log's hash chain")
    verify.add_argument("--audit", type=Path, default=Path("audit.jsonl"))
    verify.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
