## What changes

<!-- One or two sentences. -->

## Guardrail checklist

- [ ] Nothing new can reach a device without passing `Policy.evaluate`
- [ ] New action? It is listed in `policy.yml` with a risk level and parameter patterns, and has tests for allow, deny and bad parameters
- [ ] Proposer output is still treated as untrusted (no new field is trusted without validation)
- [ ] New audit event types are appended through `AuditLog.append`
- [ ] `make ci` passes
