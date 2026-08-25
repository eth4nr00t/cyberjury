# Benchmark Change Checklist

Use this checklist only when changing benchmark data, such as a manifest, answer key, source
revision, task, ground truth check, location, knowledge attribution, or evaluation metadata stored
with a benchmark. This checklist records the review evidence. The
[Benchmark Contract](benchmark-contract.md) remains the sole authority for data shape and field
semantics.

Schema, loader, scorer, matching, gate, selection, coverage, and evaluation behavior changes are
implementation changes rather than benchmark data changes. Validate them with their focused tests.
Use [Detection Quality Backtest](detection-quality-backtest.md) when they can affect detection
quality. Complete both workflows when one change contains benchmark data and implementation work.

This checklist applies to schema version `1`. Every applicable item needs a status and evidence.

## Status Rules

| Status | Meaning |
| :--- | :--- |
| `pass` | The requirement holds, with concrete evidence. |
| `fail` | The requirement does not hold. Record a finding. |
| `not applicable` | The check cannot apply, with a reason. |
| `not measured` | The check applies but could not be completed. Record the blocker and next action. |

A `not measured` status is not a pass. A failed validator, source checkout, or test is an error,
never a clean result.

## 1. Applicability

- [ ] Every changed benchmark file is classified as a manifest, answer key, source ground truth,
      or benchmark evaluation metadata.
- [ ] The affected benchmark, tasks, checks, and source revisions are listed.
- [ ] The applicable Benchmark Contract headings are recorded without copying their rules into
      this review.
- [ ] Any accompanying implementation change has a separate review and test record.
- [ ] Any accompanying change that can affect detection quality has a separate measurement record.
- [ ] Public data is reproducible and contains no private, confidential, or proprietary content.

## 2. Contract Validation

- [ ] `python -m evals validate <benchmark-directory>` passes.
- [ ] `python -m evals coverage` passes after registry or coverage relevant changes.
- [ ] The validator rejects rather than normalizes invalid data introduced by a negative test.
- [ ] The manifest and answer key resolve to the intended profile, tasks, and immutable source.
- [ ] Every referenced knowledge item and source location resolves at each applicable revision.
- [ ] Validation output and any focused contract test output are attached as evidence.

## 3. Ground Truth Evidence

### Findings Checks

- [ ] Source review at the pinned revision confirms a real exploitable issue.
- [ ] Each check represents one distinct issue and names the concrete exploit scenario.
- [ ] Locations come from source review rather than only an advisory or scanner output.
- [ ] The vulnerability, severity, and knowledge attribution match the evidenced issue.

### Clean Checks

- [ ] The check covers a security relevant lookalike that a reviewer could reasonably inspect.
- [ ] The cited locations contain the authorization, validation, isolation, or invariant that
      controls the operation.
- [ ] Generic clean code and unreachable paths are not used as clean checks.
- [ ] Every clean task retains clean coverage after checks are filtered to its revision.

### Source and Scope

- [ ] Each location is a complete file plus line or file plus symbol alternative that identifies
      the intended source boundary without answer hints.
- [ ] Task scopes agree with the source revision and the evidence reviewed for each check.
- [ ] A source revision change includes fresh evidence for every affected findings and clean check.
- [ ] The review under test never receives the answer key or source only ground truth.

## 4. Failure Accounting

- [ ] Failed checkouts, unavailable analyzers, validation failures, and unmeasured checks are
      recorded as failures or `not measured`.
- [ ] No failed or incomplete step is reported as a clean benchmark result.
- [ ] Every blocker has an owner or next action.

## Review Output

End the review with this record:

~~~markdown
## Applicability
changed benchmark files, affected tasks and checks, applicable contract headings

## Evidence
source revisions, source review, ground truth, and knowledge attribution

## Validation
commands, outputs, failures, unmeasured checks, and remaining risk

## Findings
location, failed checklist item, problem, and required correction

## Decision
accept or reject, with the reason
~~~

Reject when contract validation fails, a location cannot be verified, ground truth lacks source
evidence, a required check is unmeasured without an accepted blocker, or an incomplete step is
reported as clean. Accept only when the benchmark data validates and every applicable item has
concrete evidence.
