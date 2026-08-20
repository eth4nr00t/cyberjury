# Unit Review Mandate

## Scope and Context

Judge only the source and grounded evidence supplied for this unit. Trace every exposed entrypoint
through the managers, controllers, data access code, and libraries included in that evidence. Do not
assume an off-file control exists. When a controlling fact is unavailable, use a published evidence
request id when the surrounding prompt permits it.

Read the supplied stack notes, authorization model, selected vulnerability classes, false positive
traps, and severity rubric as part of the unit evidence. The coded workspace names the rubric
`inventory/_severity.md`, while the model receives its content in the surrounding prompt. The
source remains authoritative when prose and implementation disagree.

## Hunt High Impact Classes

Prioritize broken authorization and IDOR, business logic and state machine bypass, replay, signature
and key trust flaws, race conditions, injection, mass assignment, SSRF, and missing authentication.
Report another catalog class when the unit provides concrete evidence for it.

## Enumerate Harm

When attacker influenced input reaches a sink, downstream service, model call, callback, log, or
cache, enumerate every concrete harm enabled by that flow. Grade by the worst reachable effect. A
single flow may disclose data, cross a tenant boundary, exhaust a shared resource, or perform an
unauthorized state change.

## Verify Controls

For every candidate, decide the following from code in the evidence:

- **Authorization granularity**: determine whether the decision binds the correct principal, owner,
  tenant, resource, and action. Authentication alone is not authorization.
- **Disclosure and value exposure**: trace secret, credential, and private values to the final
  reader. A field is safe only when reachable code excludes or authorizes it.
- **Replay and signatures**: require both authentic data and the freshness or one time state the
  operation needs. A signature alone does not prevent replay.
- **State and concurrency**: determine whether the guarded state and dependent effect are one
  atomic operation. Judge the production storage semantics visible in the evidence.
- **Input and value sources**: trace request, session, cookie, service, tenant, and stored values to
  their actual trust boundary. A server derived value is trusted only when its origin proves it.
- **State and accounting**: verify that every branch updates the intended record, tenant, amount,
  entitlement, and lifecycle state.
- **Failure mode**: read error, timeout, retry, and fallback branches and determine whether the
  security decision fails closed.
- **Reachability and siblings**: prove that an exposed entrypoint reaches the sink with attacker
  chosen values. Compare supplied sibling paths for a dropped invariant.

## Refute in Place

Name the controlling fact that would make each candidate safe and settle it from the supplied
evidence. Confirm the finding when the control is absent or bypassable. Refute it when the control
holds. Mark it blocked when the result depends on a runtime fact that the review cannot read.

Recall comes first. A weaker impact changes severity, not whether a real evidenced defect is
returned. Do not report dependency advisories, pure hardening advice, a refuted candidate, or a
speculative issue with no concrete source location and exploit path.

## Evidence and Severity

Every returned finding needs an exact file and line, the attacker controlled source or reachable
state, the dangerous operation, the missing or bypassable control, and the resulting security
effect. Use the supplied severity rubric. Preserve a blocked finding with the exact missing fact
when the traced code still establishes a plausible exploit path.

A proof of concept may strengthen confidence, but this model judgment does not run tools or create
proof files. Static evidence is sufficient when it establishes the complete source to sink path and
the absent control.

## Return Structured Results

Return only the JSON shape required by the surrounding role prompt. Do not emit Markdown or prose
outside that object. Do not write candidate files, save proof files, mutate the workspace, or change
unit status. The coded engine validates the response and owns accumulation, persistence,
verification, proof reconciliation, and completion bookkeeping.
