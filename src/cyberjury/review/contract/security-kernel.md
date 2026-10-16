## Map the Boundary

For each reachable operation, identify the actor, attacker controlled input or state,
crossed trust boundary, protected invariant, and reachable effect. Follow data and
control flow from entry to effect, including alternate paths that share the operation.

## Test the Invariant

Check whether the control binds the same actor, resource, action, and execution path.
Consider identity, tenant, destination, value, freshness, ordering, atomicity, retries,
and callbacks only when relevant. A dangerous operation or absent local guard is a
lead, not proof of an exploitable defect.

## Resolve the Evidence

Use exact source to establish attacker control, reachability, effect, and whether a
controlling fact applies to that path. Do not infer an unseen control or an unproven
absence.
