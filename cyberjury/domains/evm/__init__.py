"""The evm domain: smart contract security knowledge for Solidity and the EVM.

Its content root is this package directory, holding the Solidity `knowledge/`, the
repository-review `playbook/`, and `detection.yaml`. Diff prompt focus and do-not-report
blocks live here as domain data. This package imports only `cyberjury.domains.base` and
its own light facts backend module, both free of the optional EVM dependency, so loading
the domain never needs Slither or Foundry.
"""

from pathlib import Path

from cyberjury.domains.base import Domain
from cyberjury.domains.evm.facts.slither import SlitherFacts


def _forge_poc(**kw):
    """Build the Foundry PoC backend lazily.

    so importing the domain never pulls forge or a provider, only building a backend does,
    and selecting the domain stays free of the extra.
    """
    from cyberjury.domains.evm.poc import ForgePoC

    return ForgePoC(**kw)


EVM_DIFF_FOCUS = """\
Hunt especially for high-impact, fund-affecting problems:
- Reentrancy: an external call or token transfer before the state update, cross-function
  and read-only reentrancy, missing checks-effects-interactions ordering or nonReentrant guard.
- Access control: a missing or wrong modifier on a privileged function, an unprotected
  or re-callable initializer, tx.origin used for authorization, a public mint, burn,
  withdraw, or upgrade, owner-only logic reachable by anyone.
- Oracle and price manipulation: a spot price or raw balance read as a price, flash-loan
  assisted manipulation, a missing TWAP, bound, or staleness check.
- Accounting and precision: rounding that favors the attacker, ERC-4626 first-depositor
  share inflation, division before multiplication, arithmetic in an unchecked block.
- Upgradeability: delegatecall to attacker-influenced code, proxy storage collision, an
  unprotected initializer, a reachable selfdestruct.
- Signatures: a signed message replayable with no nonce, chainid, or domain separator,
  ecrecover malleability, a signer recovered without checking it is nonzero.
"""

EVM_DIFF_DO_NOT_REPORT = """\
Do NOT report, regardless of severity:
- Gas-optimization or code-style notes with no security impact.
- Compiler-version, floating-pragma, or dependency advisories, this tool does not do
  dependency scanning.
- Missing-event or missing-NatSpec notes that do not change exploitability.
- Speculative issues you cannot tie to a concrete exploit in the code shown.
- Overflow or underflow under Solidity 0.8 checked arithmetic, unless the code is in an
  unchecked block or uses a pre-0.8 pragma.
- A missing nonReentrant guard when the shown code already updates state before the
  external call. Correct checks-effects-interactions ordering is itself the defense.
Report only what the shown code proves. Do not infer a flaw from a function, modifier,
caller, or guard that is not in the diff, and do not assume a check is absent merely
because the diff does not show it.
For input-driven issues, flag only when an external caller can actually reach the sink
with attacker-chosen values. A constant, an immutable set at construction, or an
owner-only path is not attacker-controlled. An owner-only, admin-only, or admin-signed
path is trusted: do not assume the owner or admin is compromised or careless to
manufacture an exploit, flag it only when the shown code itself exposes the flaw.
"""

EVM = Domain(
    name="evm",
    content_root=Path(__file__).resolve().parent,
    diff_focus=EVM_DIFF_FOCUS,
    diff_do_not_report=EVM_DIFF_DO_NOT_REPORT,
    facts_backend=SlitherFacts(),
    poc_backend=_forge_poc,
    dedup_by_file=True,
)
