# Benchmark Checklist

Use this checklist when adding or changing a benchmark manifest, answer key, source revision, task,
ground truth check, location, vulnerability mapping, or evaluation metadata. Read the
[Benchmark Contract](benchmark-contract.md) for the contract. Read
[Detection Quality Backtest](backtest.md) for quality claims.

This checklist applies to schema version `1`. Every applicable item needs a status and evidence.

## Status Rules

| Status | Meaning |
| :--- | :--- |
| `pass` | The requirement holds, with concrete evidence. |
| `fail` | The requirement does not hold. Record a finding. |
| `not applicable` | The check cannot apply, with a reason. |
| `not measured` | The check applies but could not be completed. Record the blocker and next action. |

`not measured` is not a pass. A failed parser, source checkout, facts backend, provider, scorer, or
backtest is an error, never a clean result.

## Review Procedure

Use the complete change as the scope. Read the adjacent source, manifest, answer key, profile
knowledge, tests, and loader when needed to judge the contract.

- Classify each changed file as manifest, answer key, source ground truth, schema, loader, scorer, or evaluation metadata.
- Select every required section for the changed file types.
- Run validation and record concrete command output as evidence.
- Record every failure and every unmeasured check.
- Use the union of required sections for a mixed change.

Manifest or task metadata requires sections 1, 2, 3, and 5. Add section 6 when a backtest applies.
Answer checks require sections 1, 2, 3, 4, and 5. Schema, loader, scorer, gate, selection, or
coverage changes require sections 1, 2, 3, 5, and 6.

## 1. Scope And Identity

- [ ] The manifest and answer key use `schema_version: 1`.
- [ ] `benchmark_id` is a stable lowercase kebab case slug between 1 and 80 characters.
- [ ] The answer key `benchmark_id` exactly equals the manifest value.
- [ ] Every task id is unique. Repository tasks use `repository-<commit prefix>`.
- [ ] Every diff id matches `diff-<seven lowercase commit characters>-<positive sequence>`.
- [ ] Each diff sequence starts at `1` and follows the diff task order in the manifest.
- [ ] Every answer check id is stable and unique within overlapping task scopes.
- [ ] Ids are not line numbers, basenames, sink names, generic finding classes, or display labels.

## 2. Field Content

### Manifest And Source

- [ ] `profile` resolves to a registered profile.
- [ ] `source` is exactly one valid `git` or `explorer` union.
- [ ] A git source has exactly one of `identity.url` or `identity.repository_path`, plus a full immutable `identity.commit`.
- [ ] An explorer source has `identity.chain` and `identity.address`.
- [ ] `source.path` is present and is `.` or a normalized repository relative path.
- [ ] `prepare`, when present, contains only supported profile preparation data.
- [ ] Mutable branches, tags, abbreviated commits, credentials, production endpoints, and answer hints are absent.
- [ ] `stack` lists unique sorted canonical languages, frameworks, and protocols.
- [ ] `knowledge.vulnerabilities` and `knowledge.guides` are unique sorted ids resolved by the selected profile.
- [ ] Tags are absent. Selection information is represented by `profile`, `stack`, `knowledge`, or source identity.

### Tasks

- [ ] Every task has `kind` set to `repository` or `diff`.
- [ ] Repository task ids use `repository-<commit prefix>` and agree with the effective source token.
- [ ] A git repository task revision, when present, contains a full `revision.commit`.
- [ ] Diff tasks have full immutable `revision.base_commit` and `revision.commit` values.
- [ ] Diff tasks use `expectation: findings` or `expectation: clean`.
- [ ] A diff id prefix equals `revision.commit[:7]` and its sequence agrees with task order.
- [ ] Tasks do not declare a path override. Every task uses `source.path`.
- [ ] Explorer tasks do not contain git revisions. Explorer diff tasks are rejected.
- [ ] Every task declares a review context and mode from the declared enums.
- [ ] Review context and mode describe the actual evidence and review behavior required by the task.

### Answer Checks

- [ ] `checks` is non empty. Each check has id, task scope, expectation, locations, and knowledge.
- [ ] Check ids use stable lower kebab case semantic slugs.
- [ ] `applies_to` contains only manifest task ids and is non empty.
- [ ] `expectation` is exactly `findings` or `clean`.
- [ ] Findings checks have one canonical vulnerability and severity.
- [ ] Clean checks have one canonical vulnerability and no severity.
- [ ] Locations contain repository relative files and optional endpoints or symbols.

## 3. Cross File Integrity

- [ ] Every `applies_to` value exists in the manifest.
- [ ] A check id has no overlapping task scopes.
- [ ] Check knowledge is a subset of the manifest knowledge and resolves in the selected profile.
- [ ] Every answer key location exists at every pinned revision in its task scope.
- [ ] Every clean diff task has a clean answer check.
- [ ] Every findings diff task has a findings answer check.
- [ ] Git targets use the manifest source and the declared immutable commits.
- [ ] Unknown fields, nulls, empty required values, duplicate ids, and invalid source unions are rejected.

## 4. Ground Truth

### Findings Checks

- [ ] The issue is exploitable at the pinned revision.
- [ ] One findings check represents one distinct issue. Independent exploit paths have separate ids.
- [ ] The check locations come from source review, not only an advisory or scanner output.

### Clean Checks

- [ ] The check is a security relevant lookalike a reviewer could reasonably inspect.
- [ ] The locations identify the authorization, validation, isolation, or invariant that controls the operation.
- [ ] Generic clean code and unreachable paths are not used as clean checks.
- [ ] A clean task has clean coverage after checks are filtered to the task revision.

### Locations And Evidence

- [ ] File paths are exact normalized repository relative paths. Basename fallback is forbidden.
- [ ] Endpoint locations use one canonical method and path form.
- [ ] Symbols are narrowed by a file or endpoint.
- [ ] Locations contain no line numbers, globs, regular expressions, prose, or duplicate spellings.

## 5. Validation And Evidence

- [ ] JSON Schema validation passes with closed objects, strict types, required fields, enums, and source unions.
- [ ] Semantic validation passes for identity, source path, task sequencing, revisions, knowledge, locations, expectations, and clean coverage.
- [ ] Source review confirms every findings check and clean boundary at the immutable revision.
- [ ] Deterministic eval, coverage, and contract tests pass.
- [ ] Failed providers, incomplete checkouts, unavailable parsers, and unmeasured checks are recorded as errors or `not measured`.
- [ ] The review under test never receives the answer key or source only ground truth.

## 6. Quality Measurement

- [ ] Schema, loader, scorer, matching, or evaluation behavior changes use the two arm procedure in [Detection Quality Backtest](backtest.md).
- [ ] Both arms use identical targets, commits, paths, context, mode, rounds, model, provider, verification, concurrency, and budget.
- [ ] Each arm records recall, found, missed, report count, precision, errors, requests, tokens, and elapsed time.
- [ ] Any recall regression rejects the change.
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

Reject when a required structural or semantic check fails, a location cannot be verified, ground
truth is unsupported by source evidence, or a required measurement is missing without an accepted
blocker. Accept only when the data contract, cross file integrity, source ground truth, and required
quality measurement pass.
