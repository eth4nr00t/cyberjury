# Severity Rubric

Every real finding is reported at a calibrated severity. There is no "refuted for low
impact" outcome. A real, evidenced defect is graded and surfaced, never talked out of
existence.
Only an unreal finding, one whose controlling fact holds when you read the code, is
dropped. That is a refutation on the facts, not on the impact.

Grade by impact times exploitability, on the code you read:

- **CRITICAL**: a control protecting funds, signing, custody, or authentication is
  defeated with little or no precondition, or is unauthenticated. Mint or move funds, take
  over an account, forge a trusted signature, achieve RCE, or read or write any user's
  secret material at will.
- **HIGH**: the same control is defeated with a precondition that is one line in the attack
  path, not a reason to drop the finding. Examples include capturing one request, holding
  one credential, winning a race, cross-user or cross-tenant IDOR to sensitive data,
  replaying a privileged signed request, missing authorization on a state-changing
  endpoint, and mass assignment of a privileged field.
- **MEDIUM**: a real but bounded defect. Examples include an unauthenticated read of status
  or metadata, an enumerable id information leak, a defect needing heavy preconditions, an
  idempotent state trigger without authentication, or limited impact from a real missing
  auth check. Report it. Do not refute it.
- **LOW**: a real issue with a narrow or weak exploit path, such as a bypassable control, a
  token compared in non-constant time, or a low-impact missing-auth defect. A pure
  hardening or best-practice gap with no concrete exploit path is not LOW. It is not
  reported. See the out-of-scope list.

Firm rules override a cautious instinct to downgrade to nothing:

- An endpoint that is state-changing, sensitive, or returns data by an enumerable id and
  is reachable without the authentication its siblings require is reported at least
  MEDIUM. Status-only responses, rate limiting, and idempotency lower severity. They do not
  make it a non-finding.
- A signed or privileged request with no consumed nonce or no freshness window is a replay
  finding, at least HIGH for a privileged action, even when impact looks bounded. A signed
  request that drives a privileged or internal script counts as privileged.
- Disclosure of a live credential, token, signing key, or secret that authenticates or
  authorizes to another system is HIGH, not a mere information leak. The harm is the access
  it grants.
- A privileged endpoint that changes authentication, ownership, or tenant state and is
  reachable without the access control its siblings require is at least HIGH, and CRITICAL
  when it directly takes over an account or releases secret material.
- When unsure between two levels, report the higher and say why. Uncertainty about grading
  is not a reason to drop a finding. Only an unreal finding is dropped.

## Out of Scope vs LOW

Recall comes first, so a real finding is almost never dropped. Do not report dependency or
component CVEs, a candidate the facts refute, or a pure best-practice or hardening gap with
no concrete exploit path. A config default or config-leak-only risk with no concrete
exploit path is also out of scope.

Everything else real is reported and graded. A weak signal is LOW, not dropped. A
bounded-impact finding with a real exploit path is LOW or MEDIUM and surfaced. Noise is
managed by sorting on severity, never by suppressing a real finding. A missed real finding
is worse than a LOW the reader skips.
