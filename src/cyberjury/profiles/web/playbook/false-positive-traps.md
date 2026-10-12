# False-Positive Traps

Recurring ways a static read misjudges a finding, in both directions: calling it real
when it is safe, and refuting a real one on an incomplete read. The refutation step checks
each candidate against every trap below. Most name the controlling fact to confirm in the
code.

## State Changes and External Effects

- A lock acquired by `SELECT ... FOR UPDATE`, or any side-effecting query, is held by the
  database transaction until commit. Executing the query takes the lock. Controlling fact:
  is the query executed inside the transaction on the same row that concurrent requests
  contend for? If yes, it serializes them.
- The obvious state change does not refute a race by itself. `transaction.atomic()` plus a
  real row lock serializes concurrent redeems even on READ COMMITTED. Controlling fact: is
  the lock held across the check and the state-changing action?
- A discarded or unused return value does not mean a side-effecting query did not run. The
  result being thrown away is not a reason to claim that contended requests were not
  serialized. Controlling fact: does the query execute on every path before the act?
- A transaction wrapper without a lock on the contended row does not serialize requests.
  Controlling fact: is there a real lock, on the right row, held until commit?

## Controls off the Entry Point

- The authentication, ownership, or signature check may be in a decorator, middleware,
  permission class, base class, or wrapper, not in the handler being read. Controlling fact:
  does the check live anywhere on the full dispatch path, including base classes and
  decorators?
- An authenticated caller, a fail-closed scheme, or a token described as single use does
  not by itself make a request non-replayable. Controlling fact: is the exact signed request
  accepted twice, or is a nonce consumed and a freshness window checked?

## Input and Value Sources

- An id, ticket, or key read from the session, a signed cookie, or a server-set field is not
  attacker-controlled even though it arrives in the request object. Controlling fact: where
  is the value actually set, not where it is read?
- A value the framework derives from an authenticated identity, not from the request body,
  is trusted input. Controlling fact: is the identity authenticated before the derivation?
- A cross-service or cross-tenant read is a finding only when the two sides are distinct
  trust domains. Controlling fact: is the principal, service, tenant, or worker inside or
  outside the boundary, and is that same decision applied to every finding?
- A self-set value is still attacker-influenced when the setter is a distinct tenant, but
  trusted when the setter is the same principal as the victim. Controlling fact: who can
  perform the setter action?
- A value that reaches a sink from a constant or server-derived source is not attacker input.
  Controlling fact: is there a concrete user-controlled assignment anywhere on the path?

## Reachability

- A dangerous sink is exploitable only if attacker input actually reaches it. Controlling
  fact: is there a concrete path from an entrypoint to the sink? If the value at the sink is
  constant or server-derived, or the only caller is internal, there is no exploit.

## Refuting Safely: Recall Comes First

Refute only when a controlling fact makes the code genuinely safe: the access is authorized,
the input cannot reach the sink, or the lock genuinely holds. A real finding wrongly
refuted is worse than a false positive kept, so these rules bind the refutation:

- Do not refute merely because a handler is described as idempotent or has rate limiting. Confirm
  whether a repeated request can repeat the protected effect. Proven transactional idempotency can
  refute replay, while bounded impact and rate limiting only lower the severity of a real finding.
- A finding usually has several harm paths: information disclosure, denial of service by
  inactivating a victim's resource, an unauthenticated state trigger, and fund movement.
  Rule out every path to refute, not just the first one.
- An unauthenticated endpoint reachable by an enumerable id that reads sensitive state or
  changes state is a real finding. Do not refute it.
- When you are not certain it is safe on all paths, keep it real.
