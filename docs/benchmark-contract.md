# Benchmark Contract

This document defines the version 1 contract for benchmark manifests and answer keys. It covers
source identity, review paths, task revisions, ground truth, knowledge attribution, and validation.

Use the [Benchmark Change Checklist](benchmark-change-checklist.md) when changing benchmark data.
Schema, loader, scorer, and other evaluation behavior changes are implementation changes. Use
[Detection Quality Backtest](detection-quality-backtest.md) when they can affect detection quality.

## Scope

This contract defines:

- benchmark manifests
- answer keys
- source identity and review paths
- repository and diff task revisions
- ground truth identity and locations
- knowledge attribution
- structural and semantic validation

It does not define prompts, scoring policy, engine orchestration, or backtest procedure.

## Benchmark Manifest

```yaml
schema_version: 1
benchmark_id: example-project
profile: web
source:
  kind: git
  identity:
    url: https://github.com/example/example-project.git
    commit: 0123456789abcdef0123456789abcdef01234567
  path: .
stack:
  languages: [python]
  frameworks: [fastapi]
  protocols: []
knowledge:
  vulnerabilities: [insecure-direct-object-reference]
  guides: [frameworks/python/fastapi, languages/python]
tasks:
  - id: repository-0123456
    kind: repository
    review:
      context: repository
      mode: standard
  - id: diff-a1b2c3d-1
    kind: diff
    revision:
      base_commit: 0123456789abcdef0123456789abcdef01234567
      commit: a1b2c3d456789abcdef0123456789abcdef01234
    expectation: findings
    review:
      context: repository
      mode: standard
```

Manifest rules:

- `schema_version` is `1`.
- `benchmark_id` is a stable lowercase kebab case benchmark slug.
- `profile` is a registered profile such as `web` or `evm`.
- `source` identifies the immutable origin and the repository relative review path.
- `stack` declares the languages, frameworks, and protocols in scope.
- `knowledge` lists vulnerability and guide ids for the selected profile.
- `tasks` is a non empty list.
- `tags` is not part of the contract. Tag information belongs in the fields that consume it.

### Source

The `source.kind` field is `git` or `explorer`.

Git sources use this shape:

```yaml
source:
  kind: git
  identity:
    url: https://github.com/example/example-project.git
    commit: 0123456789abcdef0123456789abcdef01234567
  path: .
```

The `identity.url` field is an HTTPS repository URL. A local source uses
`identity.repository_path` instead. The `identity.commit` field is always a full immutable commit.
The `path` field is required and uses a normalized repository relative review path. A source may
include `prepare` for profile specific preparation data.

Explorer sources use the same outer shape with an explorer identity:

```yaml
source:
  kind: explorer
  identity:
    chain: ethereum
    address: '0x0000000000000000000000000000000000000000'
  path: .
```

Explorer sources currently support repository tasks only. Diff tasks require two immutable git
commits and are rejected for explorer sources.

### Tasks

Repository tasks use `repository-<commit prefix>`, where the prefix is the first seven lowercase
characters of the effective commit. Git tasks inherit the source identity and path. A git
repository task may provide `revision.commit` to override the source commit. Explorer repository
tasks use the first seven lowercase hexadecimal characters of the address as the source token.

Diff tasks require a nested revision and an expectation:

```yaml
- id: diff-a1b2c3d-1
  kind: diff
  revision:
    base_commit: 0123456789abcdef0123456789abcdef01234567
    commit: a1b2c3d456789abcdef0123456789abcdef01234
  expectation: findings
```

The `expectation` value is `findings` or `clean`. A diff id is
`diff-<commit prefix>-<sequence>`, where the commit prefix is the first seven lowercase hexadecimal
characters of `revision.commit` and the sequence starts at `1` for the first diff task in that
manifest. The sequence distinguishes two tasks that use the same commit.

Tasks do not contain a path override. Every task reviews `source.path`. `review` is explicit and
contains the context and mode used by the task. Tasks do not contain stack, knowledge, or tag
overlays.

## Answer Key

```yaml
schema_version: 1
benchmark_id: example-project
checks:
  - id: memory-update-cross-account-write
    applies_to:
      - diff-a1b2c3d-1
    expectation: findings
    knowledge:
      vulnerabilities:
        - insecure-direct-object-reference
      guides:
        - languages/python
    severity: HIGH
    locations:
      - file: models/memories.py
        symbol: update_memory
      - file: routers/memories.py
        line: 84
    changes:
      - file: routers/memories.py
        line: 84
        side: new

  - id: memory-delete-owner-filter
    applies_to:
      - repository-0123456
    expectation: clean
    knowledge:
      vulnerabilities:
        - insecure-direct-object-reference
      guides:
        - languages/python
    locations:
      - file: routers/memories.py
        symbol: delete_memory_by_id
```

Answer key rules:

- `schema_version` is `1`.
- `benchmark_id` exactly matches the manifest.
- `checks` is non empty.
- `id` is a stable semantic check slug in lowercase kebab case.
- `applies_to` names every manifest task covered by the check.
- `expectation` is `findings` or `clean`.
- `knowledge` contains `vulnerabilities` and `guides` lists whose values are subsets of the
  manifest knowledge.
- `knowledge.vulnerabilities` contains exactly one canonical vulnerability for each check.
- `severity` is required for findings checks and forbidden for clean checks.
- `locations` lists complete accepted source alternatives. Each item names an exact repository
  relative `file` and exactly one `line` or `symbol`. Multiple items are alternatives, so a file
  and symbol never combine with entries from separate lists.
- Existing checks may use the object form with `files`, `endpoints`, and `symbols` while benchmark
  projects are converted one at a time. New or revised checks use the structured list form.
- `changes` identifies exact changed files, lines, and `old` or `new` sides for one diff task.
  Findings checks record introduction evidence and clean checks record repair evidence. A report
  matched to the check must cite one declared change. Repository checks do not declare changes.

One report credits at most one findings check. A check id may appear in disjoint task scopes when
its accepted locations change between revisions. A check id may not have overlapping task scopes.
A clean expectation means that the task has clean answer coverage for its fixed revision.
Extra reports remain extra and are not relabeled.

## Validation

Run the validator against a benchmark directory:

```bash
python -m evals validate evals/benchmarks/<group>/<project>
python -m evals validate evals/benchmarks/<group>/<project> --source-root /path/to/checkout
```

Validation applies the closed JSON Schemas in `evals/benchmarks/schemas/`, then checks benchmark and answer key
identity, task references, path containment, knowledge references, diff id sequencing, locations,
and clean task coverage. With `--source-root`, every repository task location must exist inside the
manifest source checkout. Diff task locations belong to their historical revisions and are checked
against the historical checkout when a report is scored.

Diff case materialization validates each `changes` entry against the parsed patch before
review or scoring. The declared file, side, and line must identify an exact changed line.
Validation also rejects structured checks that share a vulnerability class, accepted location, and
exact change within one task because deterministic scoring cannot distinguish them.

Unknown fields, nulls, empty required values, abbreviated commits, duplicate task ids, overlapping
check scopes, and invalid source unions are rejected. A failed checkout, parser, provider, or other
incomplete check is an error, not a clean benchmark result.

## Directory Layout

```text
evals/benchmarks/
  languages/<language>/<project>/
    benchmark.yaml
    answer-key.yaml
  frameworks/<language>/<framework>/<project>/
    benchmark.yaml
    answer-key.yaml
  protocols/<protocol>/<project>/
    benchmark.yaml
    answer-key.yaml
```

Private sources use the same layout outside the repository and must satisfy the same contract.
