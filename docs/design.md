# Design

## Purpose

Show how to put an autonomous or LLM-assisted agent on a network operations workflow without
letting it do anything a human has not agreed it may do. The detection and remediation logic is
deliberately simple and explainable. The value is in the controls around it.

## Pipeline

```
 telemetry --> detectors --> findings --> proposer --> proposals --> POLICY --> approval --> executor
 (validated)   (z-score,     (structured   (rules or   (untrusted)    (risk,     (human,     (dry-run or
               thresholds,    data only)    LLM)                       limits,    bound to    proposal file,
               flap counts)                                            window)    the change)  never a login)
      \______________________________________ every step is appended to the audit log ______________________/
```

| Stage | Module | Responsibility |
| --- | --- | --- |
| Load | `telemetry.py` | Reject rows with unsafe names or unknown metrics before anything sees them |
| Detect | `detect.py` | Explainable detectors; each finding carries the numbers that triggered it |
| Propose | `proposer.py` | Rules or an LLM suggest actions. Output is untrusted |
| Judge | `policy.py` | Allowlist, parameter patterns, risk, protected devices, change window, rate limits |
| Approve | `approval.py` | Human decision bound to a digest of the exact change |
| Execute | `executor.py` | Re-checks the approval digest; records or writes a proposal, never logs in to a device |
| Record | `audit.py` | Hash-chained JSON Lines; edits, deletions and reordering are detectable |

## Policy semantics

1. Unknown action: denied. The allowlist is the only source of capability.
2. Unknown device, or any parameter missing, extra or not matching its pattern: denied.
3. Risk comes from `policy.yml`. A proposer cannot declare its own change low-risk.
4. Changes to a protected device are one risk level higher. High becomes critical, and critical is denied: those stay human-only.
5. Medium and high risk changes are denied outside the change window and beyond the per-run and per-device-hour limits. Limits count across runs through the audit log.
6. Low risk is auto-allowed, medium and high need a human, and the default approver rejects everything.

## Threat model

| Threat | Control | Test |
| --- | --- | --- |
| Prompt injection through device-supplied text (interface descriptions, log lines) | Only validated identifiers and numbers reach detectors, findings and prompts. Rows with unsafe names are dropped | `test_pipeline.py`, `tests/test_proposer.py` |
| Model asks for an action outside its remit (reboot, arbitrary CLI) | Allowlist in `policy.yml` | `test_a_hostile_llm_cannot_widen_what_runs` |
| Model smuggles a command in a parameter (`swp1; reload`) | Per-parameter regular expressions, full match | `test_injection_style_parameter_values_are_denied` |
| Model chooses which device to touch | `device` is copied from the finding; extra keys in model output are rejected | `test_llm_cannot_choose_the_device` |
| Model output is malformed, oversized or not JSON | Strict parser; failure is audited and nothing runs | `test_malformed_llm_output_is_rejected` |
| Model text tries to manipulate the approver | Rationale is stripped of control characters and capped | `test_rationale_is_sanitised_and_capped` |
| Approval for change A reused to run change B | Approval carries a SHA-256 of the change; executor re-verifies | `test_approval_is_bound_to_the_exact_change` |
| Agent loops and hammers one device | Per-run and per-device-per-hour limits | `test_hourly_device_limit_holds_across_runs` |
| Someone edits the audit trail afterwards | Hash chain; `verify` names the first broken record | `tests/test_audit.py` |
| Critical infrastructure changed by automation | Protected-device escalation to denied | `test_high_risk_on_protected_device_is_denied_outright` |

## What this does not claim

- The hash chain detects tampering but cannot prevent it. Forward the log to write-once storage.
- The detectors are statistical baselines, not a trained model, and the remediation rules are
  illustrative. Tune them on real telemetry before trusting them.
- No executor here touches a real device. A production executor should open a pull request in
  the configuration repository (see the sibling `network-automation-pipeline` project) so the
  normal review, rendering and guarded rollout apply.
- Policy is only as good as its regular expressions and limits. Review `policy.yml` like code.

## Wiring a real LLM

`LLMProposer` takes any `complete(prompt: str) -> str` function, so there is no provider
dependency:

```python
from netops_agent.proposer import LLMProposer


def complete(prompt: str) -> str: ...  # call your model provider here and return its text


proposer = LLMProposer(complete, allowed_actions=list(policy.actions))
```

The model sees only structured finding data and the action names. Whatever it replies goes
through the same strict parser and the same policy as the rule-based proposer.
