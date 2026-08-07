# Direct Model Review Compared with Diff Review and Repository Review

Direct model review means asking Claude, Codex, or another coding agent to review code
directly. That is often the best path for a small, one off review.

Diff Review and Repository Review are useful when security review needs a repeatable
harness around the model: scoped inputs, domain guidance, review state, verification,
fail loud behavior, structured output, and gates.

The score marks fit for that dimension, not absolute security quality.

Legend: `++` strong fit, `+` usable, `0` no inherent edge, `-` weak fit.

## Diff Review Compared with Direct Model Review

Diff Review answers one narrow question: did this change introduce a reportable security
issue?

| Dimension | Direct Model | Diff Review | Decision |
|:---|:---|:---|:---|
| One off review | ++ | + | Use direct model review when the check is ad hoc and no artifact is required. |
| PR gate | - | ++ | Use Diff Review when the result must block CI or feed code scanning. |
| Review boundary | + | ++ | Use Diff Review when the security question is limited to changed code. |
| Input consistency | 0 | ++ | Use Diff Review when every run must read the same file, stdin stream, or git range. |
| Context scale | - | + | Use Diff Review for larger diffs, and use Repository Review when unchanged files decide the risk. |
| Security guidance | + | ++ | Use Diff Review when domain guidance should be applied consistently. |
| Recall control | 0 | + | Use Diff Review when multiple review roles or adversarial rounds are needed, and measure recall before claiming improvement. |
| Precision control | 0 | + | Use Diff Review when filters and challenge roles are needed, and measure precision before claiming fewer false positives. |
| Failure handling | - | ++ | Use Diff Review when blank, malformed, or unparsable model output must fail the run. |
| Result format | - | ++ | Use Diff Review when JSON, SARIF, markdown, text, or severity thresholds are required. |
| Operating cost | ++ | + | Use direct model review when setup cost matters more than repeatability. |
| Model leverage | 0 | + | Use Diff Review when the same base model should run through multiple roles, or when roles should use different providers. |

A clean Diff Review does not clear the repository. It only means the reviewed diff did
not produce a reportable finding.

## Repository Review Compared with Direct Model Review

Repository Review answers a broader question: was the repository reviewed through a
tracked worklist, and which findings survived verification?

| Dimension | Direct Model | Repository Review | Decision |
|:---|:---|:---|:---|
| One off exploration | ++ | - | Use direct model review for quick exploration before starting a tracked audit. |
| Repository scope | - | ++ | Use Repository Review when the target is the repository, not one pasted slice. |
| Attack surface and coverage | - | ++ | Use Repository Review when reviewed and unreviewed areas must stay visible. |
| Context organization | 0 | + | Use Repository Review when file selection should be owned by a worklist, not session flow. |
| Authorization and invariants | 0 | ++ | Use Repository Review when trust boundaries or business rules must be reused across units. |
| Domain grounding | 0 | + | Use Repository Review when facts support matters. EVM adds facts and PoC support, and web adds tree-sitter call and import grounding. Treat quality claims as measured only after evals. |
| Recall control | - | + | Use Repository Review when recall needs worklists, repeated passes, and candidate union, and validate recall with evals. |
| Precision control | 0 | + | Use Repository Review when candidates should pass a separate verification route, and validate precision with evals. |
| Failure handling | - | ++ | Use Repository Review when failed units or verification errors must remain visible. |
| Convergence | - | ++ | Use Repository Review when the run should stop by convergence state, not by a chat conclusion. |
| Resume and audit trail | - | ++ | Use Repository Review when interruption, resume, or later finalize are expected. |
| Completion gate | - | ++ | Use Repository Review when completion must be checked from workspace state. |
| Result format | - | ++ | Use Repository Review when findings, refuted candidates, JSON, and gate state must be preserved. |
| Operating cost | ++ | - | Use direct model review when speed and token cost matter more than coverage tracking. |
| Model leverage | 0 | ++ | Use Repository Review when multiple passes, candidate union, and verification should combine one or more models. |

Repository Review does not prove the repository is vulnerability free. It records whether
the review workflow reached its tracked completion conditions and reports the confirmed
findings that survived verification.

## Where Vendor Native Review Fits

Vendor native security review can be the better choice when the main need is a managed
product: hosted execution, deep platform integration, pull request comments, automatic
patch workflows, enterprise controls, and a polished developer experience.

The local review paths are the better fit when the main need is inspectable
orchestration, model routing, custom domain knowledge, repository owned artifacts, and
fail loud behavior.

## Evidence and Limits

The tool implements the harness features described here, such as chunking, fail loud
parsing, workspace state, verification, and gates. Claims about higher recall or
precision depend on the selected model, target codebase, and review budget, and should be
validated with evals.

Implementation basis:

- Domain knowledge and content layout: `cyberjury/domains/`
- CLI formats, severity thresholds, and role wiring: `cyberjury/cli.py`
- Report rendering and severity gates: `cyberjury/report.py`
- Provider and role backend defaults: `cyberjury/providers/factory.py`
- Diff chunking and noise handling: `cyberjury/review/diff/engine.py`
- Diff fail loud parsing: `cyberjury/review/diff/audit.py`
- Adversarial Diff Review roles: `cyberjury/review/diff/adversarial.py`
- Diff false positive filters: `cyberjury/review/diff/filter.py`
- Repository workspace scaffold: `cyberjury/review/repository/scaffold.py`
- Repository unit slicing and worklist: `cyberjury/review/repository/model.py`
- Repository multi pass loop and convergence: `cyberjury/review/repository/pass_loop.py`
- Repository candidate union: `cyberjury/review/repository/union.py`
- Repository verification: `cyberjury/review/repository/verifier.py`
- Repository completion gate: `cyberjury/review/repository/gate.py`
