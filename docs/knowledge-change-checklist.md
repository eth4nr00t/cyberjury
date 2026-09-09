# Knowledge Change Checklist

Use this checklist for changes to profile knowledge content. Read
[Knowledge Design](knowledge-design.md) for the contracts. Review engine code, prompt builders,
evaluation metadata, scorers, and gates through their owning workflows.

## Status Rules

| Status | Meaning |
| :--- | :--- |
| `pass` | The requirement holds with concrete evidence. |
| `fail` | The requirement does not hold. Record a finding. |
| `not applicable` | The requirement cannot apply, with a reason. |
| `not measured` | The check applies but could not complete. Record the blocker. |

A failed or missing check is never a clean result.

## Change Types

- **Security kernel:** `knowledge/security-kernel.md`
- **Security catalog:** `knowledge/security-catalog.yaml`
- **Language guide:** `knowledge/guides/languages/<language>.md`
- **Framework guide:** `knowledge/guides/frameworks/<language>/<framework>.md`
- **Protocol guide:** `knowledge/guides/protocols/<protocol>.md`
- **Profile playbook:** `playbook/*.md`
- **Detection configuration:** `detection.yaml`

Files outside these paths need the workflow of their owning subsystem.

## Scope and Integrity

- [ ] Every changed file has a change type and governing design section.
- [ ] Files outside this checklist are identified for separate review.
- [ ] The change contains no proprietary material.
- [ ] The change contains no unrelated churn.
- [ ] The motivating case and independent validation target are recorded.
- [ ] No answer key, scorer, benchmark expectation, or gate changed to raise a score.
- [ ] No Python branch implements stack or vulnerability behavior.

## Security Kernel

- [ ] The kernel defines a general reasoning procedure rather than a detector list.
- [ ] It covers actor, authority, attacker control, state, operation, controls, and harm.
- [ ] It contains no benchmark, stack, sink, or target identifier.
- [ ] Its identity and content hash change are observable in the assignment receipt.

## Security Catalog

- [ ] The schema number is supported and every object has only allowed fields.
- [ ] Category and rule ids are stable, unique, lowercase, and sorted at render time.
- [ ] Every alias has one owner and collides with no canonical category.
- [ ] Every category has at least one rule and every rule names a known category.
- [ ] Category metadata contains no fixed finding severity.
- [ ] Each security property is sufficient for broad discovery.
- [ ] Each required evidence field states the positive exploit facts.
- [ ] Each refuting evidence field names controlling safety facts.
- [ ] Each report boundary identifies the source operation or transition that owns the report.
- [ ] Fixed evidence positive and negative pairs exercise each changed behavior.
- [ ] Candidate rule and category mismatches fail before verification.
- [ ] Rule and category requests expand in stable catalog order.
- [ ] A new candidate expands its rule before final commitment.
- [ ] A terminal response assesses every expanded rule exactly once.

## Stack Guides

- [ ] Guide schema and profile loading tests pass.
- [ ] Every framework guide declares an existing parent language.
- [ ] The H1 and exact H2 sequence satisfy the guide body contract.
- [ ] Detection signals have representative positive and negative targets.
- [ ] Framework routing inherits generic language signals.
- [ ] The body establishes attack surface, trust boundaries, review guidance, and safe boundaries.
- [ ] The guide does not copy category or decision rule contracts.
- [ ] Executable or structured examples have validation in their actual format.
- [ ] Version specific third party API claims are rejected from ordinary guides.

## Detection Configuration

- [ ] Loader and schema tests pass.
- [ ] Every changed pattern has positive and negative classification evidence.
- [ ] Production source, configuration, manifests, lockfiles, and compile roots remain represented.
- [ ] Skip and test classification does not suppress production code.

## Playbooks

- [ ] Changed content reaches the intended prompt or workspace artifact.
- [ ] The playbook references catalog ids instead of defining another security contract.
- [ ] Severity and reporting guidance remain consistent with every output format.

## Integration

- [ ] All profile files load and render in stable order.
- [ ] Framework inheritance and guide references resolve.
- [ ] The discovery brief contains every profile rule exactly once.
- [ ] Diff Review and Repository Review assign the same brief contract.
- [ ] Standard and adversarial roles share the same base brief and completion rules.
- [ ] The assignment receipt binds profile, grounding, unit order, and exact content hashes.
- [ ] Category normalization and output compatibility tests pass.
- [ ] No source based relevance step removes a security category or rule.

## Validation

- [ ] Focused tests for every changed type pass.
- [ ] Ruff checks pass where applicable.
- [ ] Structured data checks pass.
- [ ] `git diff --check` passes.
- [ ] Failed or unavailable checks are recorded as `fail` or `not measured`.

## Detection Quality

A model facing kernel, catalog, guide, playbook, routing, or default behavior change requires a two
arm backtest. Follow `Comparing Two Configurations` in
[Detection Quality Backtest](detection-quality-backtest.md). Recall decides first. Record false
positives, extra findings, stability, model calls, tokens, duration, and incomplete work.

The target that motivated the change can only sanity check it. At least one independent real target
must test generality. An unavailable comparison remains `not measured`.

## Decision

1. Use `rejected` when any required item fails.
2. Use `blocked` when missing evidence prevents a reliable decision.
3. Use `accepted with follow-up` only when the remaining evidence cannot support an unmeasured
   behavior improvement.
4. Use `accepted` only when every required item passes or is genuinely not applicable.

Record the final review with these headings.

```markdown
## Applicability

## Contract Evidence

## Validation

## Backtest

## Findings

## Decision
```
