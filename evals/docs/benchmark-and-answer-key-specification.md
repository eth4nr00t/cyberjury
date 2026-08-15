# Benchmark And Answer Key Specification

Benchmark And Answer Key Specification defines how benchmark manifests and answer keys are
structured, loaded, selected, and validated. It covers manifests, answer keys, source and task
scope, ground truth identity, location matching, knowledge attribution, and validation rules.

Use the [Benchmark And Answer Key Change Checklist](benchmark-and-answer-key-change-checklist.md)
to accept a concrete change. Use [Detection Quality Backtest](./detection-quality-backtest.md) for
claims about detection quality or scoring behavior.

Schema version `1` is the only version defined here.

## Normative Language

The uppercase words MUST, MUST NOT, SHOULD, and MAY have the meanings defined by
[RFC 2119](https://www.rfc-editor.org/info/rfc2119/) and
[RFC 8174](https://www.rfc-editor.org/info/rfc8174/).

## Scope

This schema covers:

- benchmark manifests
- answer keys
- source and task scope
- ground truth identity
- location matching
- knowledge attribution
- validation rules

It does not define prompts, scoring policy, engine orchestration, or backtest procedure.

## Benchmark Manifest

```yaml
schema_version: 1
kind: project
benchmark_id: example-project
domain: web
source:
  kind: git
  url: https://github.com/example/example-project.git
  ref: 0123456789abcdef0123456789abcdef01234567
  scope: .
stack:
  languages: [python]
  frameworks: [fastapi]
  protocols: []
knowledge:
  vulnerabilities: [insecure-direct-object-reference]
  guides: [languages/python, frameworks/python/fastapi]
tags:
  - visibility:public
  - target:real
  - language:python
  - framework:fastapi
tasks:
  - id: repository-vulnerable
    kind: repository
    ref: 0123456789abcdef0123456789abcdef01234567
    scope: .
  - id: diff-introduce-example-a1b2c3d
    kind: diff
    base_ref: 0123456789abcdef0123456789abcdef01234567
    ref: a1b2c3d456789abcdef0123456789abcdef01234
    scope: .
    outcome: findings
```

Manifest rules:

- `schema_version` is `1`.
- `kind` is the literal `project`.
- `benchmark_id` is the stable benchmark slug.
- `domain` selects the knowledge tree.
- `source` identifies the immutable origin.
- `stack` declares the languages, frameworks, and protocols in scope.
- `knowledge` lists the vulnerability and guide ids for the benchmark.
- `tags` is an ordered selector list.
- `tasks` is a non-empty list of benchmark tasks.

Source fields:

- `kind` is `git` or `explorer`.
- `url` or `path` identifies a git source.
- `ref` is a full immutable git object id.
- `scope` is the review boundary within the source.
- `chain` and `address` identify an explorer source.
- `source_snapshot` is a reproducible source capture when the explorer response is incomplete.
- `prepare` holds domain specific preparation data.

Task fields:

- `id` is the stable task slug.
- `kind` is `repository` or `diff`.
- `ref` is required for git tasks.
- `base_ref` is required for git diff tasks.
- `scope` is required for every task.
- `outcome` is required only for diff tasks and is `findings` or `clean`.
- `review` is optional and records a justified override of context or mode.
- `stack`, `knowledge`, and `tags` may appear as additive overlays.

## Answer Key

```yaml
schema_version: 1
benchmark_id: example-project
entries:
  - id: memory-update-missing-owner-check
    role: planted
    finding_class: insecure-direct-object-reference
    cwe: [CWE-639]
    severity: HIGH
    locations:
      files: [models/memories.py]
      endpoints: [POST /memories/<id>/update]
      symbols: [update_memory]
    knowledge:
      vulnerabilities: [insecure-direct-object-reference]
      guides: [languages/python]
    facts:
      attacker_control: An authenticated user supplies another memory id.
      control_gap: The handler does not verify ownership before mutation.
      dangerous_action: The handler writes the selected memory record.
      impact: One user can modify another user's memory.
      location_reason: The endpoint and function identify the issue path.
    task_ids: [repository-vulnerable]
    references:
      - CVE-2024-7041
  - id: memory-delete-scoped-by-user
    role: safe
    finding_class: insecure-direct-object-reference
    locations:
      files: [routers/memories.py]
      symbols: [delete_memory_by_id]
    knowledge:
      vulnerabilities: [insecure-direct-object-reference]
      guides: [languages/python]
    facts:
      controlling_fact: The handler filters by both memory id and user id.
      location_reason: The sibling delete path shows the scoped control.
    task_ids: [repository-vulnerable]
```

Answer key rules:

- `schema_version` is `1`.
- `benchmark_id` matches the manifest `benchmark_id`.
- `entries` is a non-empty list of answer entries.
- `id` is the stable semantic entry slug.
- `role` is `planted` or `safe`.
- `finding_class` is required for every entry.
- `cwe` is optional and holds external classification ids.
- `severity` is required for planted entries.
- `locations` groups file, endpoint, symbol, and snippet locations.
- `knowledge` is the entry level knowledge attribution.
- `facts` records the grounded facts for the entry.
- `task_ids` is the complete list of manifest task ids this answer entry covers.
- `references` is optional provenance and never replaces facts.

Location rules:

- `files` is a list of normalized repository relative paths.
- `endpoints` is a list of normalized endpoint strings.
- `symbols` is a list of exact source symbols.
- `snippets` is a list of short exact snippets.
- A location must be precise enough to match a review result without line numbers or free form prose.

Facts rules:

- Planted entries use `attacker_control`, `control_gap`, `dangerous_action`, `impact`, and `location_reason`.
- Safe entries use `controlling_fact` and `location_reason`.
- Each field contains one factual statement.
- Facts are grounded in the pinned source revision.
- The `facts` object is closed for schema version `1`.
- No other `facts` keys are defined in schema version `1`.

Matching rules:

- The role, finding_class, knowledge, facts, and locations define one ground truth identity.
- One report credits at most one planted entry.
- `task_ids` is explicit scope. An entry id may not be both planted and safe in overlapping scopes.
- `outcome: clean` means the scoped planted tasks are safe at the pinned source revision.
- Extra reports stay extra. They are recorded, not relabeled.

## Validation

Use JSON Schema 2020-12 first, then semantic validation.

- Reject unknown fields, nulls, empty required values, and scalar coercion.
- Require the manifest and answer key ids to match.
- Require every `task_ids` value to exist.
- Require every exact location to exist at the pinned source revision.
- Require every clean task to have a safe location after filtering.

## Directory Layout

Public project benchmarks follow this layout:

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

One project directory owns one manifest and one shared answer key. Private sources use the same
layout outside the repository and must preserve the same schema and validation rules.

## Related Standards

RFC 2119 and RFC 8174 define normative language.
JSON Schema 2020-12 provides structural validation.
CWE provides optional external weakness mappings.

References:

- RFC 2119: https://www.rfc-editor.org/info/rfc2119/
- RFC 8174: https://www.rfc-editor.org/info/rfc8174/
- JSON Schema specification: https://json-schema.org/specification
- MITRE CWE: https://cwe.mitre.org/about/
