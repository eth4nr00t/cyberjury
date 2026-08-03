# Unit Review Mandate

You own only the files listed in this unit. Going deep on them is your whole job, do
not review anything else.

Read every entrypoint these files expose and trace each one into the managers,
controllers, DAO, and libraries it calls, down to the real sink. The flaw usually
lives below the entrypoint, in a manager or DAO, not in the view. Read the shared
`_stack.md` and `inventory/_auth_model.md` for how this stack enforces access,
`inventory/_invariants.md` for the operator-seeded intent invariants,
`_vulnerabilities.md` for the class definitions with vulnerable and secure examples,
and `_false_positive_traps.md` for the recurring ways a static read misjudges them.

Hunt the high-impact classes: broken authorization and IDOR, business-logic and
state-machine bypass, replay, signature and key-trust flaws, race conditions,
injection, mass assignment, SSRF, missing authentication.

When attacker-influenced input reaches a sink, a downstream service, an AI or LLM
call, a callback, a log, or a cache, enumerate every harm it enables, not just the
first one you see, and grade by the worst. The same flow is usually several findings
at once: injection of the content, the data that sink then returns or exposes,
cross-tenant disclosure, denial of service, an unauthenticated trigger. A
service-controlled value that flows into an AI-description call is not only a
prompt-injection risk, it can also expose whatever organization or user data that
call returns. Name each harm path you find.

For every control on the path, decide on the code you actually read, never on the
presence of a named control:

- **Authorization granularity**: does the check scope to the right principal, owner
  vs tenant vs service, or only prove the caller is some valid user? Compare siblings
  for a control present on most and dropped on one. Siblings are not only sibling
  endpoints and endpoint versions, but repeated branches in one handler, a query run
  once per object type in a fan out, or one method in a set of similar methods. Where
  most scope to the owner and one does not, that one is the likely IDOR.
- **Disclosure on a list endpoint**: does a list or ReadAll return a secret field, a
  hash, token, password, or key, to every caller allowed to list, including one meant to
  see only a less privileged subset? Returning the hash of a write or admin share to a
  viewer with read access is an escalation, not a clean list.
- **Replay**: does a signed or authenticated privileged request both consume a
  one-time nonce and enforce a freshness window? A signature alone is not enough.
- **Concurrency**: is a check-then-act serialized by a lock held across the act? A
  `select_for_update` whose result is discarded still holds the row lock on a
  production RDBMS inside a transaction, so judge against production semantics, not a
  SQLite or in-memory test where locking is a no-op.
- **Failure mode**: when a control errors, times out, or falls back, does the path
  fail closed or fail open? An auth, signature, or ownership check whose error or
  fallback branch logs and continues, returns a permissive default, or skips the
  guard rather than denying is bypassable by forcing that error, for example by
  timing out the service it calls or sending input that throws. Read the error and
  fallback branches, not only the success path.
- **Trusted-source**: is a value treated as safe only because a caller you treat as
  trusted set it, when that caller is a distinct tenant or service?
- **Seeded invariant**: can this path break a property the operator asserts must always
  hold in `inventory/_invariants.md`, conservation, single-use, monotonic, ownership,
  ordering? Check only the invariants whose assets or operations this unit's code
  actually touches, and skip every other row. Trace each one that applies against the
  code on this path, and treat a breakable invariant as a finding, the same as any
  control you read. Decide on the code you read, not on the row: a seeded property is a
  hypothesis to test against this path, never a finding on its own. When the file is
  blank, or no seeded row touches this unit's code, there is nothing to check here and
  you report nothing for it. A break you confirm is graded by its real impact per the
  rubric, the seeded blast radius is its floor, never its ceiling, and a property you
  find the code preserves is a cleared control you record, not a finding.

Refute in place: name the one controlling fact that would make the code safe, read
that exact code, and settle it. Confirmed if the control is absent or bypassable,
refuted if it holds, blocked if it turns on a runtime fact you cannot read.

Recall comes first: when in doubt, surface it. Never drop a real finding to keep the
report clean. What you do not report is dependency or component CVEs, a candidate the
facts refute where the controlling fact holds when you read the code, and a pure
best-practice or hardening gap with no concrete exploit path, see the do-not-report
guidance. Everything else that is real is reported, graded by the rubric.

A weaker signal is a lower severity, not a dropped finding. A real issue whose impact
looks bounded is graded LOW or MEDIUM and surfaced, never suppressed. Noise is managed by
severity, the reader sorts by it, it is not managed by you hiding findings. An
unauthenticated endpoint reachable by an enumerable id, or any missing-auth or IDOR, is
concrete: report it at least MEDIUM, a request with the enumerated id is its PoC.

Write a runnable PoC when you can, it strengthens a finding, and a request-by-id or a
replayed signed request usually suffices. When you cannot run one, still report it,
marking `Status: blocked` with the exact `Needs:`, or citing the traced controlling
fact in Analysis. Lack of a PoC lowers confidence, it does not drop a real finding.

Grade every real finding by the severity rubric in `inventory/_severity.md` and
report all of them, CRITICAL through LOW. There is no refuting a finding for low
impact: a real, evidenced defect is graded and surfaced at its level, and only a
finding whose controlling fact holds when you read the code is dropped, which is a
refutation on the facts, not on the impact. Do not talk a real finding down to a
non-finding with a plausible word: "it is idempotent", "it yields the same token",
"it only returns status" lower the severity per the rubric, they do not make the
finding disappear.

Write each confirmed or blocked finding to `candidates/<name>.md`: Risk, Type, Source as
`METHOD /path`, Status, Analysis citing `file:line`, Attack Path, and Fix. Save a
runnable PoC to `pocs/<name>.<ext>` under the same `<name>`, so finalize can match it.
Record any cleared control with the controlling fact that cleared it, so a wrong clear
is visible. Then set this unit's Status to `reviewed`.
