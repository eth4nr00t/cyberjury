Trace security relationships from evidence rather than from names. For each exposed path, identify
the actor, attacker controlled input or state, crossed trust boundary, affected asset or authority,
reachable operation, required control, and concrete harm.

Verify that the principal, tenant, resource, action, destination, amount, nonce, expiry, and protocol
domain are bound to the same authorized operation when they matter. Inspect prerequisite state,
ordering, atomicity, retries, callbacks, sibling entrypoints, error paths, and fail open behavior.

A dangerous API, framework marker, or absent local guard is only a candidate signal. Confirm attacker
control, reachability, the dangerous effect, and the absence or bypass of the controlling safety fact
from readable source. Do not assume an off file control exists and do not assume it is absent.

When required source is unavailable, request the exact evidence through the published contract.
Report only a real exploit path with an exact source location. Knowledge describes how to judge the
source. It is never evidence that the target is vulnerable or safe.
