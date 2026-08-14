"""The Web Application Security profile, the default review profile.

Its content root is this package directory, holding its `knowledge/`, `playbook/`, and
`detection.yaml`. Diff prompt focus and do-not-report blocks live here as profile data.
The engine modules import these as their defaults. Beyond `cyberjury.profiles.base` it
imports only its own `facts` package, whose grammars stay lazy, so the engine can depend
on it without a cycle.
"""

from pathlib import Path

from cyberjury.profiles.base import ReviewProfile
from cyberjury.profiles.web.facts import TreeSitterCallGraph


def _web_poc(**kw):
    """Build the web PoC writer lazily so profile imports do not pull a provider."""
    from cyberjury.profiles.web.poc import WebPoC

    return WebPoC(**kw)


WEB_DIFF_FOCUS = """\
Hunt especially for high-impact, exploitable problems:
- Business logic flaws: approval/state-machine bypass, skipped steps, replay of a
  privileged action with no nonce or time window.
- Authorization: missing or bypassable checks, IDOR (cross-user, cross-tenant, or
  cross-service access to a resource by a user-supplied id).
- Authentication and signatures: auth bypass, JWT verification flaws, trusting a
  caller-supplied key as the trust anchor, unvalidated callback URLs.
- Injection: SQL, command, code/eval, template, deserialization of untrusted data.
- Mass assignment: a user-controlled body bound wholesale into a model.
- Secrets and crypto: hardcoded credentials, weak or misused crypto.
"""

WEB_DIFF_DO_NOT_REPORT = """\
Do NOT report, regardless of severity:
- Dependency or component CVEs.
- Style, naming, or general best-practice suggestions.
- Speculative issues you cannot tie to a concrete exploit in the code shown.
- Risks that only matter if a production config is leaked (do not assume the code
  shown reflects production configuration).
For input-driven issues, flag only when untrusted input can plausibly reach the
sink. A constant, a stored field, trusted config, or an operator-supplied CLI
argument is not attacker-controlled.
"""

WEB_PROFILE = ReviewProfile(
    name="web",
    content_root=Path(__file__).resolve().parent,
    diff_focus=WEB_DIFF_FOCUS,
    diff_do_not_report=WEB_DIFF_DO_NOT_REPORT,
    poc_backend=_web_poc,
    facts_backend=TreeSitterCallGraph(),
)
