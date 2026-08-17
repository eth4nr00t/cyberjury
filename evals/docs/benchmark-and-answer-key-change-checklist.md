# Benchmark And Answer Key Change Checklist

Use this checklist when adding or changing a benchmark manifest, answer key, source revision,
task scope, ground truth entry, location, finding class, or evaluation metadata. Read
[Benchmark And Answer Key Specification](benchmark-and-answer-key-specification.md) for the schema
and rationale. Read [Detection Quality Backtest](./detection-quality-backtest.md) for claims about detection
quality or scoring behavior.

This checklist applies to the schema 1 specification. A YAML parse alone is not a validation
result. Every applicable item needs a status and evidence.

## Status Rules

| Status | Meaning |
| --- | --- |
| `pass` | The requirement holds, with concrete evidence. |
| `fail` | The requirement does not hold. Record a finding. |
| `not applicable` | The check cannot apply, with a reason. |
| `not measured` | The check applies but could not be completed. Record the blocker and next action. |

`not measured` is not a pass. A failed parser, source checkout, facts backend, provider, scorer,
or backtest is an error, never a clean result.

## Review Procedure

Use the complete change as the scope. Read the adjacent source, manifest, answer key, domain
knowledge, tests, and loader only when needed to judge the contract.

- Classify each changed file as manifest, answer key, source ground truth, schema, loader, scorer,
  or evaluation metadata.
- Select the required sections from the list below.
- Validate the changed data and all cross-file references.
- Record evidence for every applicable item. A statement that something was checked is not evidence.
- Record every failure and every unmeasured check.
- Apply the decision rule at the end of this document.

- Manifest or task metadata. Required sections are [1](#1-scope-and-identity), [2](#2-field-content), [3](#3-cross-file-integrity), [5](#5-validation-and-evidence), and [6](#6-quality-measurement) when backtest applies. Run schema, source resolution, task scope, metadata, and knowledge references checks. Backtest when behavior or scoring changes.
- Answer entry. Required sections are [1](#1-scope-and-identity), [2](#2-field-content), [3](#3-cross-file-integrity), [4](#4-ground-truth), [5](#5-validation-and-evidence), and [6](#6-quality-measurement) when backtest applies. Run schema, locations, source review, role, and facts checks. Backtest when scorer or matching behavior changes.
- Schema, loader, scorer, or gate. Required sections are [1](#1-scope-and-identity), [2](#2-field-content), [3](#3-cross-file-integrity), [5](#5-validation-and-evidence), and [6](#6-quality-measurement). Run field contract, contract tests, failure paths, report matching, and coverage checks. Backtest is required.
- Benchmark suite or coverage metadata. Required sections are [1](#1-scope-and-identity), [3](#3-cross-file-integrity), [5](#5-validation-and-evidence), and [6](#6-quality-measurement). Run inventory, coverage, deterministic tests, and gate behavior checks. Backtest when quality claims are made.

For a mixed change, use the union of all required sections. Do not omit a section to avoid a
check. When a change type calls for backtest, section 6 is required in addition to the other
sections listed for that change type.

## 1. Scope And Identity

- [ ] The manifest and answer key use `schema_version: 1`.
- [ ] The manifest `benchmark_id` is a stable lowercase kebab-case project slug between 1 and 80 characters.
- [ ] The answer key `benchmark_id` exactly equals the manifest `benchmark_id`.
- [ ] Every task id is unique. Repository tasks use `repository-vulnerable`.
- [ ] Every diff task id has the correct `diff-introduce` or `diff-fix` prefix and the seven
      character lowercase revision suffix.
- [ ] Every answer entry id is unique in its overlapping task scopes and is a stable semantic slug.
- [ ] No id is only an advisory id, line number, basename, sink, generic finding class, or display name.
- [ ] An id remains unchanged when the same issue moves across a revision. A new issue receives a
      new id.

## 2. Field Content

### Manifest And Source

- [ ] `kind` is `project` and `domain` resolves to a registered domain.
- [ ] `source` is exactly one valid `git` or `explorer` union.
- [ ] A git source has exactly one source of `url` or `path`, a full immutable `ref`, and a
      normalized repository-relative `scope`.
- [ ] An explorer source has a registered chain, normalized address, and normalized source-relative
      `scope`. When source files cannot be reproduced from explorer data alone, it has a
      `source_snapshot` with `type`, HTTPS `url`, an immutable `revision`, a
      `sha256:<64 lowercase hex>` `digest`, and an optional normalized `scope`.
- [ ] When an explorer source has `prepare`, its `schema` resolves to the selected domain's closed
      JSON Schema, its `data` validates against that schema, and the extension registry documents
      every key, type, allowed value, and reproducibility requirement.
- [ ] Every source scalar has its declared type. Branches, tags, abbreviated revisions, mutable
      URLs, credentials, production endpoints, and answer-key hints are absent.

### Stack, Knowledge, And Tags

- [ ] `stack.languages`, `stack.frameworks`, and `stack.protocols` are unique sorted canonical ids.
- [ ] `knowledge.vulnerabilities` and `knowledge.guides` resolve in the selected domain and are
      unique and sorted.
- [ ] A domain-aware benchmark has at least one guide reference.
- [ ] Every tag uses a lowercase namespace from `visibility`, `target`, `language`, `framework`,
      or `protocol`.
- [ ] Tags contain no spaces, underscores, bare values, free-form issue labels, duplicates, or
      unregistered ids. Tags are sorted and no longer than 64 characters.
- [ ] Task metadata overlays use the same contracts, add only valid metadata, and never broaden
      the manifest scope or alter scoring.

### Tasks

- [ ] Every task declares a `kind` matching the manifest, an explicit `scope`, and a
      source identity for that type. A missing scope is invalid even when the intended scope is the
      repository.
- [ ] Git repository tasks have a full immutable `ref`. Git diff tasks have full
      immutable `base_ref`, full `ref`, and `outcome`.
- [ ] Explorer repository tasks have `chain`, normalized `address`, and
      `source_snapshot`. Explorer diff tasks are rejected until an immutable before and
      after snapshot contract exists.
- [ ] `outcome` is `findings` or `clean` and is present only on diff tasks.
- [ ] Repository tasks do not use `outcome`, `expectation`, `base`, or `target`.
- [ ] A task cannot broaden the manifest source scope.
- [ ] Optional `review.context` and `review.mode` use only the declared enums and do not change
      ground truth.
- [ ] `review.context: repository` is used only for a diff task whose evidence requires code outside
      the patch, and its `rationale` names that evidence.
- [ ] `review.mode: adversarial` is used only when standard roles or rounds are insufficient, and its
      `rationale` names the required extra roles or rounds.

### Answer Key Entries

- [ ] `entries` is non-empty and each entry has `id`, `role`, `locations`, `knowledge`, `facts`,
      and a non-empty `task_ids` list.
- [ ] `role` is exactly `planted` or `safe`.
- [ ] Planted entries have a canonical `finding_class` and a severity of `CRITICAL`, `HIGH`, `MEDIUM`,
      or `LOW`.
- [ ] Safe entries have a `finding_class` and the `finding_class` is part of the entry identity.
- [ ] `cwe` values match `CWE-<digits>` and are defensible. They are not used to replace the internal
      finding class.
- [ ] `locations` groups file, endpoint, symbol, and snippet locations.
- [ ] The answer key contains no free-form `note` field or separate role lists. Causal facts are in
      `facts`. Provenance is in `references`.

## 3. Cross-File Integrity

- [ ] Every `task_ids` task id exists in the manifest.
- [ ] Entry ids do not have both roles in overlapping task scopes.
- [ ] Entry knowledge references are a subset of the merged manifest knowledge, and every reference
      resolves to the selected domain.
- [ ] `outcome: clean` is treated as a task state, not a result counter. Result records use
      separate `false_positives` and `extra` collections.
- [ ] Git task refs use the same source as the manifest and remain inside its scope.
- [ ] Explorer repository tasks match the manifest chain and address and use a source snapshot with
      the declared immutable revision and digest.
- [ ] Diff task id prefixes and revision suffixes agree with `outcome` and ref.
- [ ] Every exact file, endpoint, symbol, or snippet location exists at every pinned revision in its
      `task_ids` scope.
- [ ] Repository planted entries have matching diff coverage when the benchmark enables that
      contract. The same issue keeps its id, finding_class, knowledge, and applicable locations.
- [ ] Unknown fields, nulls, empty required values, scalar coercion, and synthetic ids are rejected.

## 4. Ground Truth

### Planted Entries

- [ ] The issue is exploitable at the pinned revision.
- [ ] The facts identify attacker control, control gap, dangerous action or state transition, concrete
      impact, and the reason the locations prove the issue.
- [ ] One entry represents one distinct issue. Separate independent exploit paths have separate ids.
- [ ] The facts are based on source facts at the pinned revision, not only an advisory or scanner
      output.

### Safe Entries

- [ ] The entry is a security-relevant lookalike that a reviewer could reasonably inspect.
- [ ] The facts identify the controlling authorization, validation, isolation, or invariant.
- [ ] A generic clean function, naming convention, or unreachable code path is not used as a safe
      entry.
- [ ] A clean diff task has a safe location after its planted entries are filtered to the task
      revision.

### Locations And Evidence

- [ ] File locations are exact normalized repository-relative paths. Basename fallback is forbidden.
- [ ] Endpoint locations use one canonical method and path form with consistent parameter markers.
- [ ] Symbol locations are narrowed by a file or endpoint.
- [ ] Snippet locations are short literal source snippets used only when stronger locations are unavailable.
- [ ] Locations contain no line numbers, globs, regular expressions, prose, or duplicate spellings.
- [ ] Facts fields are non-empty English factual statements, one fact per field.
- [ ] Facts contain no reviewer instructions, expected report wording, exploit code, or special
      entry matching hint.
- [ ] Advisory ids and URLs appear only in `references` and do not replace causal evidence.

## 5. Validation And Evidence

- [ ] JSON Schema 2020-12 validation passes with closed objects, strict types, required fields,
      enums, oneOf source discriminators, and non-empty string constraints.
- [ ] Semantic validation passes for identity, source unions, task scopes, refs, knowledge,
      locations, roles, and clean-task filtering.
- [ ] Source review confirms every planted issue and safe boundary at the immutable ref.
- [ ] Deterministic coverage and eval tests pass. Missing or unresolved knowledge references are
      fixed rather than ignored.
- [ ] Every failure, incomplete checkout, unavailable parser, failed provider, or unmeasured check
      is recorded as an error or `not measured`, never as clean.
- [ ] The review under test never receives the answer key or source-only ground truth fields.

## 6. Quality Measurement

- [ ] A change to the schema, loader, scorer, matching behavior, or evaluation behavior uses the two-arm baseline versus changed procedure in [Detection Quality Backtest](./detection-quality-backtest.md).
- [ ] Both arms use identical targets, revisions, scopes, context, mode, rounds, model, provider, verification, concurrency, and budget.
- [ ] The review records recall, found, missed, n_reports, precision_known, errors, requests, tokens, and elapsed time for each arm.
- [ ] A recall regression on any target rejects the change.
- [ ] A change that keeps recall equal while increasing cost does not become the default unless another target shows recall up.
- [ ] Cost is recorded even when it does not reject a change.

## Review Output

End the review with a short record:

~~~markdown
## Applicability
changed files, change types, required sections, and whether a backtest is required

## Results
section, status, and concrete evidence

## Findings
location, checklist item, problem, and required correction

## Validation
commands, outputs, failures, unmeasured checks, and remaining risk

## Decision
accept or reject, with the reason
~~~

## Decision Rule

Reject the change when a required structural or semantic check fails, an anchor cannot be located,
ground truth is unsupported by source evidence, a required check is unmeasured without an accepted
blocker, or the change relies on implicit defaults, fuzzy matching, or benchmark-specific leakage.

Accept only when the data contract, cross-file integrity, source ground truth, and required quality
measurement all pass. A data-integrity pass does not prove that the review is secure or that a
knowledge change improves recall. Those claims require independent real targets and two-arm
evidence.
