# Unit Review Mandate

## Scope and Context

You own only the files listed in this unit. Going deep on them is your whole job. Do not
review anything else.

Read every entrypoint these files expose and trace each one into the managers, controllers,
DAOs, and libraries it calls, down to the real sink. The flaw usually lives below the
entrypoint, in a manager or DAO, not in the view. Read the shared `_stack.md` and
`inventory/_auth_model.md` for how this stack enforces access, `_vulnerabilities.md` for
the relevant class definitions with vulnerable and secure examples, and
`_false_positive_traps.md` for recurring ways a static read misjudges them.

## Hunt High-Impact Classes

Hunt broken authorization and IDOR, business-logic and state-machine bypass, replay,
signature and key-trust flaws, race conditions, injection, mass assignment, SSRF, and
missing authentication.

## Enumerate Harm

When attacker-influenced input reaches a sink, downstream service, AI or LLM call,
callback, log, or cache, enumerate every harm it enables, not only the first one you see,
and grade by the worst. The same flow can expose data, cross a tenant boundary, trigger a
denial of service, or cause an unauthenticated state change. Name each harm path.

## Verify Controls

For every control on the path, decide on the code you actually read, never on the presence
of a named control:

- **Authorization granularity**: does the check scope to the right principal, owner,
  tenant, or service, or only prove the caller is some valid user? Compare sibling
  endpoints, versions, branches, and object types for a dropped or weakened check.
- **Disclosure and value exposure**: does a list or `ReadAll` return a secret field, hash,
  token, password, or key to a caller with less privilege? Does the same path expose a
  cross-tenant record or a privileged action? A hidden field is safe only when the code
  actually excludes it.
- **Replay and signatures**: does a signed or authenticated privileged request both consume
  a one-time nonce and enforce a freshness window? A signature alone is not enough.
- **State and concurrency**: is a check-then-act serialized by a lock held across the act?
  A `select_for_update` whose result is discarded still holds the row lock on a production
  RDBMS inside a transaction, so judge production semantics, not a SQLite or in-memory test
  where locking is a no-op.
- **Input and value sources**: does attacker input reach the sink through a request, session,
  cookie, service, or tenant boundary? A server-derived value is trusted only when the code
  proves where it was set.
- **State and accounting**: does the path update the right record, tenant, or resource on
  every branch? A bounded or idempotent state change is still a finding when an attacker
  can trigger it without the required authorization.
- **Failure mode**: when a control errors, times out, or falls back, does the path fail
  closed or fail open? Read error and fallback branches, not only the success path.
- **Reachability and siblings**: can every exposed entrypoint reach the sink with chosen
  values, and do sibling routes carry the same invariant? An internal-only caller or a
  constant sink value is not an exploit.

## Refute in Place

Name the one controlling fact that would make a candidate safe, read that exact code, and
settle it. Confirmed if the control is absent or bypassable, refuted if it holds, and
blocked if it turns on a runtime fact you cannot read.

## Recall and Scope

Recall comes first. When in doubt, surface the finding. A weaker signal is a lower severity,
not a dropped finding. Report every real issue with a concrete exploit path. Do not report
dependency or component CVEs, a candidate the facts refute, or a pure best-practice or
hardening gap with no concrete exploit path.

An unauthenticated endpoint reachable by an enumerable id, or a missing-auth or IDOR path
that exposes another user's data or changes state, is concrete. Grade it by
`inventory/_severity.md`. A request using the enumerated id is its PoC.

## Proof

Write a runnable PoC when you can. A request by id or a replayed signed request usually
suffices. When you cannot run one, still report the finding with `Status: blocked` and the
exact `Needs:`, or cite the traced controlling fact in Analysis. Lack of a PoC lowers
confidence. It does not drop a real finding.

## Grade Findings

Grade every real finding by `inventory/_severity.md` and report all of them, CRITICAL
through LOW. There is no refuting a finding for low impact. A real, evidenced defect is
graded and surfaced at its level. Only a finding whose controlling fact holds when you read
the code is dropped. Do not talk a real finding down with a plausible word such as
"idempotent", "it yields the same token", or "it only returns status". Those lower the
severity per the rubric. They do not make the finding disappear.

## Write Findings

Write each confirmed or blocked finding to `candidates/<name>.md`: Risk, Type, Source as
`METHOD /path`, Status, Analysis citing `file:line`, Attack Path, and Fix. Save a runnable
PoC to `pocs/<name>.<ext>` under the same `<name>` so finalize can match it. Record every
cleared control with the controlling fact that cleared it, so a wrong clear is visible.
Then set this unit's Status to `reviewed`.
