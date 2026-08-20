# Knowledge Design

Knowledge Design defines the profile content model and the knowledge inputs supplied to the
review engine. It covers vulnerability classes, guides, playbooks, detection metadata, selection,
packing, and category normalization.

Use the [Knowledge Change Checklist](knowledge-change-checklist.md) to accept a concrete change.
Use [Engine Design](engine-design.md) for shared orchestration, prompt execution, and
completion semantics.

## Design Principles

### Knowledge Is Data

Security knowledge belongs in the selected profile's content tree. The review engine is
generic and should not contain language, framework, protocol, or vulnerability-specific
detection rules. Adding a class or stack should normally be a Markdown or YAML change,
not a Python change.

### Recall Comes First

A selector or packer may improve focus, but it must not silently remove a matching class or part
of a class body. Relevance ordering controls reading order, never inclusion. Engine failure and
finding retention semantics live in [Engine Design](engine-design.md#core-invariants).

### Findings Need Evidence

Knowledge describes what to investigate. A report still needs a concrete file and line
or symbol, an attacker-controlled input or reachable state, and an exploitable scenario.
Do not turn style advice, dependency CVEs, speculation, or configuration-only concerns
into findings.

### No Benchmark Overfitting

Knowledge changes must improve the general review capability, not encode an answer key.
Do not add a benchmark's finding, sink name, variable name, endpoint, file path, commit
shape, or remediation shape as a special case. Do not write a selection hint whose only
purpose is to activate a class on one known benchmark. A benchmark may expose a missing
general concept, but the resulting guidance must describe that concept in reusable terms.

Do not change an answer key, scorer, benchmark expectation, or gate merely to make a
knowledge change pass. Do not use benchmark-specific examples in the knowledge body when
they reveal the planted issue. Keep benchmark target code and proprietary material out
of the knowledge tree.

Public benchmarks are regression and sanity evidence. They do not prove general recall because a
model may have seen them. A target that informed the change can confirm a regression but cannot
prove improvement. Acceptance requires evidence from an independent real target under the
[Knowledge Change Checklist](knowledge-change-checklist.md). The backtest runbook owns the exact
comparison controls.

Apply the integrity checks and record their evidence with the
[Knowledge Change Checklist](knowledge-change-checklist.md).

## Directory Layout

Each registered profile shares the knowledge, playbook, and detection content contract. A profile
may also bind facts and proof of concept backends. Those engine extensions are not knowledge
content and follow [Engine Design](engine-design.md#facts-and-grounding).

```text
cyberjury/profiles/<profile>/
  knowledge/
    index.md
    vulnerabilities/<id>.md
    guides/
      languages/<language>.md
      frameworks/<language>/<framework>.md
      protocols/<protocol>.md
  playbook/
    methodology.md
    unit-review.md
    severity-rubric.md
    false-positive-traps.md
  detection.yaml
```

The layout resolves through `cyberjury.profiles.base.content_paths` into a `ContentPaths`
record. `cyberjury.profiles.registry` is the only profile registry. `web` is the default profile
and covers Web Application Security. `evm` covers EVM Application Security for Solidity smart
contracts. `--profile auto` uses a simple extension heuristic: a target with Solidity files
selects `evm`, and other targets select `web`. The selected name then resolves through the
registry. Unknown profiles fail loudly.

The package-level constants in `cyberjury.resources` expose the default profile paths. Code
that needs another profile uses `ReviewProfile.paths` instead of importing a second constant set.

The `index.md` file is a human-readable class index. The Markdown loader skips it, so it is not a
vulnerability class and must not be used as one.

## Vulnerability Classes

A vulnerability class lives in `knowledge/vulnerabilities/<id>.md`. The file stem is the
canonical category and must match the frontmatter `id`.

### Frontmatter

```yaml
---
id: sql-injection
title: SQL Injection
impact: CRITICAL
tags: [cwe-89, owasp-a03, injection]
selection_hints: ["cursor.execute", ".raw(", "query +="]
aliases: [sql-injection-variant]
---
```

The fields are ordered and constrained as follows:

| Field | Required | Constraint |
| :--- | :--- | :--- |
| `id` | yes | Matches the lowercase kebab-case file stem and remains stable. |
| `title` | yes | Names the class as it appears in prompts and docs. |
| `impact` | yes | One of `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`. |
| `tags` | yes | Carry profile taxonomy and stay data-driven. |
| `selection_hints` | yes | Are non-empty and unique after case folding. |
| `aliases` | no | Stay as genuine model-output variants and do not collide with ids or other aliases. |

The body is the complete guidance given to a model. A new or changed class must cover:

- The body covers the security condition, attacker control, reachability, every distinct dangerous
  mechanism it claims, relevant defenses, and the controlling facts that make a similar flow safe.
- The body distinguishes a real issue from a false positive.
- The body includes one vulnerable and secure pair for each materially different security behavior.
  A language needs its own pair only when its source pattern or runtime behavior changes the review
  rule.

Choose one primary organization axis for the body. A class with one mechanism may group examples by
language. An umbrella class with several independent mechanisms should group by mechanism and use
language subheadings only where they help. Do not switch between language and mechanism headings at
the same level.

A `Not a Finding` section states the safe boundary. The
[review record](knowledge-change-checklist.md#review-output), rather than the model-facing class
body, contains the Language Coverage table. Every language guide in the owning profile appears in
that table, as does every materially distinct mechanism the class claims. The table does not
enumerate language and mechanism combinations that are irrelevant.

A representative vulnerable and secure pair may cover several languages when attacker control, the
dangerous operation, exploit conditions, relevant defenses, and runtime behavior are equivalent. A
syntax difference alone does not require another pair. A runtime or control difference does.
Unsupported languages or mechanisms should be marked `not applicable` with a technical reason
instead of adding a forced example. Examples should stay general rather than naming a benchmark
target.

Code examples must use languages supported by the owning profile and teach the reusable property
in a minimal, self-contained scenario. Include the least context needed to establish attacker
control, exploit conditions, the dangerous operation, and the controlling safety facts. Actors,
state, timing, or bindings belong when the security behavior depends on them. Production
scaffolding, reusable utility implementations, and exhaustive error handling belong in tests or
the review record, not the model-facing body. Configuration and protocol examples must use their
actual formats. Executable examples should be validated with an available parser, formatter,
compiler, or focused test. An unavailable toolchain is recorded as an unmeasured gap. The
[Knowledge Change Checklist](knowledge-change-checklist.md) contains the acceptance procedure for
these rules.

Selection hints are advisory routing signals, not a vulnerability detector. Prefer
distinctive sinks, APIs, protocol fields, and control-flow markers. Do not use common
syntax or broad words such as `auth`, `public`, `amount`, `status`, or `constructor` as
the only signal. A class with no matching hint can still be reported when the model has
evidence for it.

Each materially different dangerous operation should use a hint when it has a stable low noise
API, syntax form, annotation, or protocol token. This does not require one hint for every spelling
or example. When no narrow signal exists, rely on the reviewer route that permits an unselected
class and measure that risk in the required backtest instead of adding a broad hint. Every new hint
family needs representative positive and negative routing coverage.

The web taxonomy requires Common Weakness Enumeration and Open Worldwide Application Security
Project tags. Ethereum Virtual Machine classes use Smart Contract Weakness Classification tags
where a suitable SWC exists. Profile tests cover classes without a suitable SWC. Keep taxonomy
decisions in Markdown metadata, not in Python.

## Language, Framework, and Protocol Guides

Guides live under one of the three guide directories and share a typed frontmatter contract.
The body explains where input enters, how trust and authorization are expressed, important
sinks, and stack-specific failure modes.

```yaml
---
id: django
title: Django
kind: framework
language: python
detect:
  files: ["manage.py", "**/urls.py"]
  manifest_hints: ["django"]
  imports: ["django."]
  content: []
entrypoint_files: ["**/views.py"]
entrypoint_markers: ["path("]
logic_layer_files: ["**/services.py"]
public_api_patterns: []
---
```

The fields are ordered and constrained as follows:

| Field | Required | Constraint |
| :--- | :--- | :--- |
| `id` | yes | Matches the file stem and is unique within the profile. |
| `title` | yes | Names the guide as it appears in stack notes. |
| `kind` | yes | Is `language`, `framework`, or `protocol`. |
| `language` | frameworks only | Names the parent language guide. |
| `detect` | yes | Is a map whose values are string lists for file globs, manifest hints, imports, and content tokens. |
| `entrypoint_files` | yes | Is a string list of likely application entrypoints. |
| `entrypoint_markers` | yes | Is a string list of source markers that seed entrypoints. |
| `logic_layer_files` | yes | Is a string list of downstream business logic files. |
| `public_api_patterns` | yes | Contains multiline regular expressions. |

An empty list is valid for a field with no signal. Generic routing belongs to language
guides. Framework guides declare only framework-specific additions and inherit the parent
language's entrypoint, marker, logic-layer, and public API routing at load time. Protocol
guides are language neutral and primarily contribute detection and review guidance.

Guide selection is deterministic and data-driven:

1. File globs are matched against target paths.
2. Manifest hints are matched only against dependency manifest text.
3. Import markers and content tokens are matched against source or diff text.
4. Matching guides are returned in the language, framework, and protocol pool order.

An ordinary source word must not activate a framework through a manifest-only hint. Routing
tests belong in the [Knowledge Change Checklist](knowledge-change-checklist.md) when a detection
signal changes.

## Detection Configuration

The profile `detection.yaml` file is classification metadata, not vulnerability knowledge.

| Field | Required | Constraint |
| :--- | :--- | :--- |
| `skip_dirs` | yes | Is a string list of directories to skip. |
| `skip_root_dirs` | no | Is a string list of root directories to skip when present. |
| `source_extensions` | yes | Is a string list of source file extensions. |
| `config_extensions` | yes | Is a string list of configuration file extensions. |
| `manifests` | yes | Is a string list of manifest file names. |
| `compile_roots` | no | Is a string list of files that let a facts backend compile a target. |
| `test_dirs` | yes | Is a string list of test directories. |
| `test_name_patterns` | yes | Is a string list of test name patterns. |
| `doc_extensions` | yes | Is a string list of documentation file extensions. |
| `lockfiles` | yes | Is a string list of lockfiles. |

Repository modeling consumes this data to build a deterministic file map. New extensions or
conventions belong here rather than in stack-specific branches.

## Playbooks

Playbook files are operational review knowledge. They define methodology, unit review
instructions, severity grading, and false-positive traps. They are selected from the profile
like vulnerability and guide content, but they do not define finding categories.

Repository Review materializes selected playbooks as model and operator inputs. The
`playbook/methodology.md` file maps to `methodology.md`, and
`playbook/false-positive-traps.md` maps to `_false_positive_traps.md`. The source Markdown under
the profile remains authoritative. Workspace lifecycle, state, and artifact ownership live in
[Repository Review Workflow](engine-design.md#repository-review-workflow).

## Runtime Knowledge Flow

Knowledge loading is shared. Each review path adapts its evidence before selecting guides and
vulnerability classes. This document owns the flow through complete knowledge inputs. Engine
prompt construction starts after this boundary.

```mermaid
flowchart TD
    A[Detect Target] --> B[Load Profile Content]
    B -- Diff Path --> C[Adapt Diff Evidence]
    B -- Repository Path --> D[Adapt Repository Evidence]
    C -- Diff Selection --> E[Select Guides and Classes]
    D -- Repository Selection --> E
    E --> F[Build Complete Packs]
    F --> G[Return Knowledge Inputs]
```

The engine consumes these inputs through
[Prompt Construction](engine-design.md#prompt-construction). The two review paths use the same
vulnerability catalog and selection semantics.

### Diff Review

The diff adapter selects guides from changed paths and diff text. For each judgment unit,
vulnerability classes come from the patch plus grounded repository context when available.
Matched classes are ranked by impact, the longest matching hint, number of hints, and stable id.
The selector keeps every match.

### Repository Review

Scaffolding selects guides from the repository file list, manifests, and source sample. Each review
unit selects vulnerability classes once from its own source and extracted facts before the
catalog builds its pack plan.

### Bounded Knowledge Packs

The `VulnerabilityCatalog.plan` method partitions selected classes without truncating any class.
A class larger than the configured pack limit remains intact in its own pack. If nothing matches,
one pack with the display label `general review` is still emitted. The label is not a category id.
A pack owns only its assigned classes, while a reviewer may report a compelling class that the
selector did not choose.

The packing target is not a content budget. Do not remove a mechanism, attacker condition, safe
boundary, or required example merely to keep two classes in one judgment. Complete knowledge may
occupy its own pack, and the resulting cost is measured in the required backtest. Completeness does
not justify repeated equivalent examples or production-sized sample implementations.

The catalog owns selection and the complete pack plan. The engine consumes that plan and owns
parallel execution, failure accounting, accumulation, and verification. Profile content owns the
security explanation.

### Categories and Aliases

Diff Review prompts expose the loaded vulnerability ids and allow `other` when none fit.
Repository Review prompts expose the loaded ids, then canonicalize known aliases while keeping
unknown labels distinct during candidate identity so unrelated classes are not merged. Model
labels are normalized to lowercase hyphenated ids before these path-specific rules apply.

## Adding or Changing Knowledge

The [Knowledge Change Checklist](knowledge-change-checklist.md) covers the change type,
required evidence, validation, backtest applicability, and acceptance decision.
