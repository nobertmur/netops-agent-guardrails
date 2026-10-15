# ADR 0001: The policy gate owns risk, proposers never do

Status: accepted

## Context

An LLM proposer can be wrong, manipulated through text it reads, or simply creative. If
proposals carried their own risk rating or target, a manipulated proposer could label a
dangerous action as safe, or aim an approved action at a different device.

## Decision

Proposals contain only an action name, parameters and a rationale. The device is copied from the
finding. Risk, approval requirements and limits are all looked up in `policy.yml` by action name.
The approver sees and signs a digest of the executable fields, and the executor re-verifies it.

## Consequences

- Swapping the rule proposer for an LLM does not widen the agent's capabilities.
- Adding a capability is a reviewed change to `policy.yml`, visible in a pull request.
- Cost: every new action needs a policy entry and parameter patterns before it can run at all.
  That friction is the intended safeguard.
