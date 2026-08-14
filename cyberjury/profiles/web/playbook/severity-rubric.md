# Severity Rubric

Every real finding is reported at a calibrated severity. There is no "refuted for
low impact": a real, evidenced defect is graded and surfaced, never talked out of
existence to dodge a bar. Only an unreal finding, one whose controlling fact holds
when you read the code, is dropped, and that is a refutation on the facts, not on
the impact.

Grade by impact times exploitability, on the code you read:

- **CRITICAL**: a control protecting funds, signing, custody, or authentication
  defeated with little or no precondition, or unauthenticated. Mint or move funds,
  take over an account, forge a trusted signature, RCE, read or write any user's
  secret material at will.
- **HIGH**: the same control defeated with a precondition that is a line in the attack
  path, not a reason to drop the finding: capture one request, hold one credential, win
  a race. Cross-user or cross-tenant IDOR to sensitive data or a privileged action,
  replay of a privileged signed request, a missing authorization check on a
  state-changing endpoint, mass assignment of a privileged field.
- **MEDIUM**: a real but bounded defect. An unauthenticated read of status or
  metadata, an enumerable-id information leak, a defect needing heavy preconditions or
  yielding limited impact, an idempotent state trigger reachable without auth. A real
  missing-auth or enumerable defect that looks low impact lands here, reported, not
  refuted.
- **LOW**: a real issue with a narrow or weak exploit path. A bypassable control, a
  token compared in non-constant time, or a low-impact missing-auth or enumerable
  defect. A pure hardening or best-practice gap with no concrete exploit path is not a
  LOW, it is not reported at all, see the do-not-report list.

Firm rules, these override a cautious instinct to downgrade to nothing:

- An endpoint that is state-changing, sensitive, or returns data by an enumerable id
  and is reachable without the authentication its siblings require is reported, at
  least MEDIUM. "It only returns status", "it is rate-limited", "it is idempotent"
  lower the severity, they do not make it a non-finding.
- A signed or privileged request with no consumed nonce or no freshness window is a
  replay finding, at least HIGH for a privileged action, even when the impact looks
  bounded. A signed request that drives a privileged or internal script counts as a
  privileged action.
- Disclosure of a live credential, token, signing key, or secret that authenticates
  or authorizes to another system is HIGH, not a mere information leak. A Bearer token
  or API key written to a log or returned to a caller is usable, so the harm is the
  access it grants, not the bytes themselves.
- When you are unsure between two levels, report at the higher and say why. Unsure
  how to grade is not a reason to drop, only an unreal finding is dropped.

## Out of Scope vs LOW

Recall comes first, so a real finding is almost never dropped. Out of scope and not
reported: dependency or component CVEs, since this tool does not do dependency scanning,
a candidate the facts refute where the controlling fact holds when you read the code, and
a pure best-practice or hardening gap, a config default, or a config-leak-only risk with
no concrete exploit path, see the do-not-report list.

Everything else real is reported, graded. A weak signal is LOW, not dropped: a
bounded-impact finding with a real exploit path is graded LOW or MEDIUM and surfaced.
Noise is managed by sorting on severity, never by suppressing a real finding. A missed
real finding is worse than a LOW the reader skips.
