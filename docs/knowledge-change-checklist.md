# Knowledge Change Checklist

Use this checklist only for changes to profile knowledge content. It accepts vulnerability
classes, guides, the knowledge index, profile playbooks, and `detection.yaml`. Read
[Knowledge Design](knowledge-design.md) for the contracts being checked. Review engine code,
prompt builders, evaluation metadata, scorers, and gates through their own change workflow.

This document owns review evidence and the acceptance decision. It does not redefine the
knowledge model.

## Status Rules

| Status | Meaning |
| :--- | :--- |
| `pass` | The requirement holds, with concrete evidence. |
| `fail` | The requirement does not hold. Record a finding. |
| `not applicable` | The requirement cannot apply to this change, with a reason. |
| `not measured` | The check applies but could not be completed. Record the blocker and next action. |

A `not measured` status is not a pass. A failed loader, parser, facts backend, provider,
verifier, or backtest is an error, never a clean result.

## Change Types

Classify each changed profile path before reviewing it. This catalog maps each accepted type to
its profile relative path and authoritative contract. Mixed changes use every matching entry.

- **Vulnerability class:** `knowledge/vulnerabilities/<id>.md` follows
  [Vulnerability Classes](knowledge-design.md#vulnerability-classes).
- **Language guide:** `knowledge/guides/languages/<language>.md` follows
  [Language, Framework, and Protocol Guides](knowledge-design.md#language-framework-and-protocol-guides).
- **Framework guide:** `knowledge/guides/frameworks/<language>/<framework>.md` follows
  [Language, Framework, and Protocol Guides](knowledge-design.md#language-framework-and-protocol-guides).
- **Protocol guide:** `knowledge/guides/protocols/<protocol>.md` follows
  [Language, Framework, and Protocol Guides](knowledge-design.md#language-framework-and-protocol-guides).
- **Knowledge index:** `knowledge/index.md` follows
  [Directory Layout](knowledge-design.md#directory-layout).
- **Profile playbook:** `playbook/*.md` follows [Playbooks](knowledge-design.md#playbooks).
- **Detection configuration:** `detection.yaml` follows
  [Detection Configuration](knowledge-design.md#detection-configuration).

Any changed file outside these paths is outside this checklist. List it in Applicability and
review it through the workflow for its owning subsystem. Do not classify an engine or evaluation
change as knowledge to avoid its required validation.

## Review Procedure

Use the final diff as the review scope. Read only the surrounding content, loaders, tests, and
indexes needed to verify the changed contract.

1. Classify every changed file with [Change Types](#change-types).
2. Name the exact Knowledge Design sections that govern each file.
3. Complete the applicable evidence sections below without silently skipping an item.
4. Run focused validation for every changed type.
5. Run the two arm backtest when [Backtest Applicability](#backtest-applicability) requires it.
6. Apply the [Decision Rule](#decision-rule), then record findings, unmeasured checks, and the final
   decision in [Review Output](#review-output).

## Scope and Integrity Evidence

- [ ] Applicability lists every changed file, its change type, and its governing design section.
- [ ] Files outside this checklist are identified for separate review.
- [ ] The diff contains no proprietary material.
- [ ] The diff contains no unrelated churn.
- [ ] Evidence against
      [No Benchmark Overfitting](knowledge-design.md#no-benchmark-overfitting) names the motivating
      case and the independent target used to test generality.
- [ ] The change does not alter an answer key, scorer, benchmark expectation, or gate to make the
      knowledge pass.
- [ ] Any Python change that implements stack or vulnerability behavior is rejected from this
      checklist and reviewed as an engine boundary violation.

## Vulnerability Class Evidence

Apply this section only to changed vulnerability classes.

- [ ] Profile schema tests pass for every changed class.
- [ ] The H1 and exact H2 sequence satisfy the vulnerability body structure contract.
- [ ] Contract evidence names the text that establishes the security condition, review path,
      representative contrast, and safe boundary.
- [ ] The review record includes the Security Behavior Coverage artifact defined below when the
      change adds or removes an example, changes a claimed security behavior, or changes language,
      framework, runtime, or format applicability.
- [ ] Every new or materially changed executable example has a parser, formatter, compiler, or
      focused test result. An unavailable toolchain is recorded as `not measured`.
- [ ] Changed selection hints have deterministic positive and negative routing results.
- [ ] Changed ids, aliases, impact, or taxonomy data have focused compatibility test results.

## Guide Evidence

Apply this section only to changed language, framework, or protocol guides.

- [ ] Guide schema tests pass for every changed guide.
- [ ] Profile loading tests pass for every changed guide.
- [ ] Every changed framework guide declares a valid parent language.
- [ ] The H1 and exact H2 sequence satisfy the guide body structure contract.
- [ ] Detection evidence names representative positive and negative targets for every changed
      signal family.
- [ ] Framework inheritance evidence shows that generic language routing is inherited rather than
      repeated.
- [ ] Contract evidence names the text that establishes the attack surface, trust boundaries,
      review guidance, and safe boundaries.
- [ ] Referenced vulnerability ids resolve.
- [ ] Guide prose references vulnerability classes without copying their complete contracts.
- [ ] Executable or structured examples have validation results in their actual language or format.

## Detection Evidence

Apply this section only to `detection.yaml`.

- [ ] The profile detection schema and loader tests pass.
- [ ] Every changed extension, manifest, directory, or name pattern has positive and negative
      classification evidence.
- [ ] Production source, security relevant configuration, manifests, lockfiles, and compile roots
      remain represented in the resulting file map.
- [ ] Skip and test classification results show that production code is not suppressed.

## Index and Playbook Evidence

Apply the relevant items to `knowledge/index.md` and profile playbooks.

- [ ] The knowledge index test proves that the documented ids equal the loadable class ids.
- [ ] Changed playbook content renders from the selected profile and reaches the intended review
      prompt or workspace artifact.
- [ ] Playbook guidance references the profile catalog rather than defining a second category or
      vulnerability contract.

## Integration Evidence

- [ ] Repository loaders parse every changed profile file and render the expected content.
- [ ] Guide references, framework inheritance, vulnerability ids, and aliases resolve across the
      profile.
- [ ] Selection tests cover changed paths, source evidence, facts evidence, and hints that can
      change the selected knowledge.
- [ ] Knowledge planning tests prove that every selected class remains complete and appears in one
      emitted pack.
- [ ] Category normalization and report compatibility tests pass when ids or aliases change.
- [ ] The diff contains no content reduction justified only by a pack target, example count, or
      coverage table shape.

## Validation and Backtest

### Focused Validation

- [ ] Focused tests for every changed type pass.
- [ ] Example validation results name the tool and the exact example or fixture checked.
- [ ] Ruff lint checks pass when applicable.
- [ ] Formatter checks pass when applicable.
- [ ] Structured data checks pass when applicable.
- [ ] The `git diff --check` command passes.
- [ ] Every failed or unavailable check is recorded as `fail` or `not measured` with its evidence.

### Backtest Applicability

Use this table to decide whether a two arm backtest is required.

| Change | Backtest rule |
| :--- | :--- |
| Model facing vulnerability body, guide, or playbook | Required |
| Selection hint, alias, impact, category, routing, or detection behavior | Required |
| Knowledge packing or rendering behavior | Outside this checklist and required by the engine workflow |
| Human only index or prose with no loaded content change | Not required, with loader evidence |
| Formatting or observability that leaves selected and rendered content unchanged | Not required, with evidence |

Changing loaded heading structure is model facing even when every sentence and code fence is
preserved. A heading-only structure change therefore requires the two arm backtest.

When required, follow `Comparing Two Configurations` in
`detection-quality-backtest.md`. That runbook is the only source for arm controls,
completion rules, recorded metrics, and comparison commands.

- [ ] The target selection record satisfies the runbook independence rules.
- [ ] The generated comparison output and its workspace records are attached without manual
      transcription.
- [ ] Any unavailable comparison output remains `not measured`.
- [ ] Every extra report is inspected manually, and the decision records whether improvement
      generalizes beyond the motivating target.

## Decision Rule

1. Record `rejected` when any required item is `fail`.
2. Record `blocked` when required evidence is `not measured` and the missing evidence prevents a
   reliable decision.
3. Record `accepted with follow-up` only when the remaining work does not support an unmeasured
   behavior improvement and does not block acceptance.
4. Record `accepted` only when every required item is `pass` or has a justified `not applicable`
   status and validation is complete.

## Review Output

End the review with this record:

```markdown
## Applicability

changed file, knowledge change type, governing design section, and backtest requirement

## Contract Evidence

design section, status, and concrete evidence

## Validation

command or evaluation, result, and artifact

## Backtest

targets, arm completion, measured quality and cost, or justified not required status

## Findings

location, failed check, problem, and required correction

## Decision

accepted, rejected, blocked, or accepted with follow-up
```

Add `Security Behavior Coverage` after Contract Evidence only when a vulnerability class change
adds or removes an example, changes a claimed security behavior, or changes language, framework,
runtime, or format applicability. A heading-only structure change, selection hint change, or prose
correction does not require this artifact unless it also changes one of those facts.

```markdown
## Security Behavior Coverage

### <Security Behavior>

- Applicability: `<languages, runtimes, or formats>`
- Example decision: `<representative pair and why another pair is or is not required>`
- Validation: `<tool and result>`
```

Populate this artifact according to the example policy in
[Vulnerability Classes](knowledge-design.md#vulnerability-classes).
