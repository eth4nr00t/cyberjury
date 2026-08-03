# False-Positive Traps

Recurring ways a static read misjudges a finding, in both directions: calling it
real when it is safe, and the inverse, refuting a real one on an incomplete read.
The refutation step checks a candidate against every trap below. Most name the
controlling fact to confirm in the code, the rest state that fact themselves. When a
real run later proves a new recurring misjudgement, add it here.

## Locks and Transactions

- A lock acquired by `SELECT ... FOR UPDATE`, or any side-effecting query, is held
  by the database transaction until commit. Executing the query takes the lock.
  A discarded or unused return value does not mean the lock was not taken, so
  "the result is thrown away" is not a reason to call a redeem unserialized.
  Controlling fact: is the locking query executed inside the transaction at all,
  on the same row two concurrent requests contend for? If yes, it serializes them.
- `transaction.atomic()` plus a real row lock serializes concurrent redeems even
  on READ COMMITTED. The race only exists if no lock is taken on the contended row.

## Input That Looks Attacker-Controlled but Is Not

- An id, ticket, or key read from the session, a signed cookie, or a server-set
  field is not attacker-controlled even though it arrives in the request object.
  Controlling fact: where is the value actually set, not where it is read?
- A value the framework derives from an authenticated identity, not from the
  request body, is trusted input.

## Controls That Live off the Handler Body

- The auth, ownership, or signature check may be in a decorator, a middleware, a
  permission class, a base class, or a wrapper, not in the handler you are reading.
  Controlling fact: does the check live anywhere on the full dispatch path,
  including base classes and decorators?

## Replay and Freshness

- "The caller is authenticated", "the scheme fails closed", or "the token is
  single-use" do not by themselves make a request non-replayable. Conversely, if a
  nonce is consumed and a freshness window is enforced, the replay concern is moot.
  Controlling fact: is the exact signed request accepted twice, or is a nonce
  consumed and a timestamp window checked?

## Trust Boundaries

- A cross-service or cross-tenant read is only a finding if the two sides are
  actually distinct trust domains. Decide once whether a given principal, an internal
  service role, a sibling tenant, a worker, is inside or outside the boundary, then
  apply that one answer to every finding touching it. Do not confirm one finding by
  treating the principal as hostile and refute another by treating the same principal
  as trusted, that contradiction is itself the bug to resolve before grading either.
- A self-set value is still attacker-influenced when the setter is a distinct
  tenant, but is trusted when the setter is the same principal as the victim.

## Reachability

- A dangerous sink is only exploitable if attacker input actually reaches it.
  Controlling fact: is there a concrete path from an entrypoint to the sink? If the
  value at the sink is a constant or server-derived, or the only caller is internal,
  there is no exploit.

## Refuting Safely: Recall Comes First

The inverse traps. Refute only when a controlling fact makes the code genuinely
safe: the access is actually authorized, the input cannot reach the sink, or the
lock genuinely holds. A real finding wrongly refuted is worse than a false
positive kept, so these bind the refutation:

- Do not refute for low or bounded impact, idempotency, or rate-limiting. Those
  lower the severity, they do not delete a real finding.
- A finding usually has several harm paths: information disclosure, denial of
  service by inactivating a victim's resource, an unauthenticated state trigger,
  fund movement. You must rule out every path to refute. Ruling out one is not a
  refutation: proving the attacker cannot activate their own resource does not
  refute a finding whose harm is inactivating the victim's. Proving a trigger is
  idempotent does not refute an unauthenticated read that leaks data.
- An unauthenticated endpoint reachable by an enumerable id that reads sensitive
  state or changes state is a real finding, do not refute it.
- When you are not certain it is safe on all paths, keep it real.
