Trace security relationships from evidence rather than from names. For each external or public path,
identify the caller, caller controlled token or value, affected assets and authority, reachable state
transition, external interaction, required invariant, and concrete harm.

Verify authorization, ownership, accounting units, rounding direction, operation order, token balance
movement, callback reachable state, oracle provenance, one time state, expiry, and chain and contract
domain binding when they matter. Inspect inherited and sibling entrypoints that share the invariant.

A modifier, call name, token interface, arithmetic operator, or analyzer observation is only a clue.
Confirm reachability, attacker control, the dangerous effect, and the absence or bypass of the
controlling safety fact from readable source. Do not assume a token is callback free or standards
compliant without a fixed implementation or enforced allowlist.

When required source is unavailable, request the exact evidence through the published contract.
Report only a real exploit path with an exact source location. Knowledge describes how to judge the
source. It is never evidence that the target is vulnerable or safe.
