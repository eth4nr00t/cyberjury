# Knowledge Design

Knowledge Design defines how review knowledge is structured, loaded, selected, and validated.
It covers vulnerability classes, stack guides, protocol guides, detection metadata, review
workflow, and evaluation coverage.

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

A selector, packer, deduplicator, or verifier may improve focus, but it must not silently
remove a plausible class or finding. Relevance ordering controls reading order, never
inclusion. A failed or incomplete model or facts step is a failed review step, not a
clean result.

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

Public benchmarks are regression and sanity evidence. They do not prove general recall,
because a model may have seen them. Validate a knowledge change on real targets that did
not define the change, and prefer unseen private targets for the strongest signal. The
baseline and changed arms must differ only in the proposed knowledge change. A gain that
appears only on the originating benchmark is evidence of overfitting, not an accepted
quality improvement.

Apply the integrity checks and record their evidence with the
[Knowledge Change Checklist](knowledge-change-checklist.md).
The design requirement is simple: a knowledge change must describe a reusable security property
and must be tested beyond the target that motivated it.

## Content Layout

Each registered profile shares the knowledge, playbook, and detection content contract.
Profile-specific facts and verification components are optional extensions.

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

The `cyberjury.profiles.base.content_paths` function resolves this layout into a `ContentPaths`
record. The `cyberjury.profiles.registry` module is the only profile registry. The `web` profile
covers Web Application Security and is the default. The `evm` profile covers EVM Application
Security for Solidity smart contracts. `--profile auto` uses a simple extension heuristic: a
target with Solidity files selects `evm`, and other targets select `web`. The selected name is
then resolved through the registry. An unknown profile fails loudly.

The `cyberjury.resources` module exposes the default profile paths as package-level constants.
Code that needs another profile uses `ReviewProfile.paths` rather than importing another set of
global constants.

The `index.md` file is a human-readable class index. The Markdown loader skips it, so it is not a
vulnerability class and must not be used as one.

## Vulnerability Classes

Store one class in `knowledge/vulnerabilities/<id>.md`. The file stem is the canonical
category and must match the frontmatter `id`.

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

Fields are ordered as `id`, `title`, `impact`, `tags`, `selection_hints`, and optional
`aliases`. The canonical `id` matches the lowercase kebab-case file stem and remains
stable. `impact` is one of `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`. Tags carry profile
taxonomy, hints are non-empty and unique after case folding, and aliases are genuine
model-output variants that do not collide with ids or other aliases.

The body is the complete guidance given to a model. A new or changed class must cover:

- The body covers the security condition, attacker control, reachability, and relevant defenses.
- The body distinguishes a real issue from a false positive.
- The body includes a vulnerable and secure pair for each language whose meaning or source
  pattern differs.

State the safe boundary in a `Not a Finding` section. The
[review record](knowledge-change-checklist.md#review-output), rather than the model-facing class
body, contains the Language Coverage table for every language guide in the owning profile. A
representative vulnerable and secure pair is enough when the meaning is unchanged across
applicable languages. Mark an unsupported language as `not applicable` with a technical reason
instead of adding a forced example. Keep examples general rather than naming a benchmark target.

Code examples must use languages supported by the owning profile and teach the reusable property
in a minimal, self-contained scenario. Configuration and protocol examples must use their actual
formats. Validate executable examples with an available parser, formatter, compiler, or focused
test. Record an unavailable toolchain as an unmeasured gap. The
[Knowledge Change Checklist](knowledge-change-checklist.md)
contains the acceptance procedure for these rules.

Selection hints are advisory routing signals, not a vulnerability detector. Prefer
distinctive sinks, APIs, protocol fields, and control-flow markers. Do not use common
syntax or broad words such as `auth`, `public`, `amount`, `status`, or `constructor` as
the only signal. A class with no matching hint can still be reported when the model has
evidence for it.

The web taxonomy requires Common Weakness Enumeration and Open Worldwide Application Security
Project tags. Ethereum Virtual Machine classes use Smart Contract Weakness Classification tags
where a suitable SWC exists. Profile tests cover classes without a suitable SWC. Keep taxonomy
decisions in Markdown metadata, not in Python.

## Language, Framework, and Protocol Guides

Guides live under one of the three guide directories and share a typed frontmatter
contract. Their body explains where input enters, how trust and authorization are expressed,
important sinks, and stack-specific failure modes.

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

Guide fields are ordered as `id`, `title`, `kind`, optional `language`, `detect`,
`entrypoint_files`, `entrypoint_markers`, `logic_layer_files`, and `public_api_patterns`.
`id`, `title`, `kind`, and `language` are strings. `detect` is a map whose values are string
lists for file globs, manifest hints, imports, and content tokens. The four routing fields are
string lists. `public_api_patterns` contains multiline regular expressions. Framework guides
reference an existing parent language guide.

Use an empty list for a valid field with no signal. Language guides own generic routing.
Framework guides declare only framework-specific additions and inherit the parent
language's entrypoint, marker, logic-layer, and public API routing at load time. Protocol
guides are language neutral and primarily contribute detection and review guidance.

Guide selection is deterministic and data-driven:

1. File globs are matched against target paths.
2. Manifest hints are matched only against dependency manifest text.
3. Import markers and content tokens are matched against source or diff text.
4. Matching guides are returned in the language, framework, and protocol pool order.

An ordinary source word must not activate a framework through a manifest-only hint. Add routing
tests with the [Knowledge Change Checklist](knowledge-change-checklist.md) when a detection signal
changes.

## Detection Configuration

The `detection.yaml` file is profile classification metadata, not vulnerability knowledge. Its
supported fields are `skip_dirs`, optional `skip_root_dirs`, `source_extensions`, `config_extensions`,
`manifests`, optional `compile_roots`, `test_dirs`, `test_name_patterns`, `doc_extensions`, and
`lockfiles`. All values are string lists. `compile_roots` identifies files that let a facts
backend compile a target. Repository modeling consumes this data to build a deterministic file
map. Add a new extension or convention here rather than adding a stack-specific branch.

## Playbooks and Review Workspace

Playbook files are operational review knowledge. They define methodology, unit review
instructions, severity grading, and false-positive traps. They are selected from the
profile just like vulnerability and guide content, but they do not define finding
categories.

Repository Review copies selected material into a private workspace. The workspace also stores
the review state and reports:

- `_stack.md`, `_vulnerabilities.md`, `METHODOLOGY.md`, and `_false_positive_traps.md`
- `inventory/`, `units/`, `candidates/`, `findings/`, and `pocs/`
- `findings.json`, `_run.json`, `_finalize.json`, `_union.json`, `_verified.json`, and
  `_timeline.json`
- `_refuted.md`, `_pocs.md`, and the `.cyberjury-workspace` marker
- optional `_facts.md`, `_facts_by_file.json`, `_facts_units.json`, `_facts_graph.json`,
  `_facts_manifest.json`, `_facts_error.txt`, and `_target.md`

The `playbook/methodology.md` file becomes `METHODOLOGY.md`. The
`playbook/false-positive-traps.md` file becomes `_false_positive_traps.md`. These are review inputs
and provenance, not substitutes for source Markdown under version control. `_run.json` and
`_finalize.json` are completion and comparison records, not debug output.

## Runtime Knowledge Flow

Knowledge loading is shared, then each review path adapts its target input before selecting and
packing knowledge for prompt construction. The diagram summarizes the flow. The sections below
define the rules.

```mermaid
flowchart TD
    A[Detect Target] --> B[Load Profile Content]
    B --> C[Adapt to Diff Review]
    B --> D[Adapt to Repository Review]
    C --> E[Select Knowledge]
    D --> E
    E --> F[Build Complete Packs]
    F --> G[Render Prompt]
    G --> H[Run Model Judgment]
    H --> I[Verify and Report Findings]
```

The two review paths use the same vulnerability catalog and selection semantics.

### Diff Review

The diff adapter selects guides from changed paths and diff text. For each judgment unit,
vulnerability classes are selected from the patch plus grounded repository context when
available. Matched classes are ranked by impact, the longest matching hint, number of
hints, and stable id. The selector keeps every match.

### Repository Review

Scaffolding selects guides from the repository file list, manifests, and source sample.
It writes the complete rendered vulnerability library to `_vulnerabilities.md` and the
selected stack guidance to `_stack.md`. Each review unit then selects vulnerability
knowledge from its own source and extracted facts. The same unit evidence is reused for
each knowledge pack, so a pack boundary cannot change the selection evidence.

### Bounded Knowledge Packs

The `VulnerabilityCatalog.plan` method partitions selected classes without truncating any class.
A class larger than the configured pack limit remains intact in its own pack. If nothing matches,
one pack with the display label `general review` is still emitted. The label is not a category id.
A pack owns only its assigned classes, while a reviewer may report a compelling class that the
selector did not choose.

The rendered Markdown body is sent as prompt knowledge. The engine owns packing,
parallel execution, failure accounting, monotonic accumulation, and verification. The
profile content owns the security explanation.

### Categories and Aliases

Diff Review prompts expose the loaded vulnerability ids and allow `other` when none fit.
Repository Review prompts expose the loaded ids, then canonicalize known aliases while keeping
unknown labels distinct during candidate identity so unrelated classes are not merged. Model
labels are normalized to lowercase hyphenated ids before these path-specific rules apply.

## Adding or Changing Knowledge

Use [Knowledge Change Checklist](knowledge-change-checklist.md) for the change type, required
checks, validation, and acceptance decision. The checklist owns execution details. Use
`evals/BACKTEST.md`, relative to the code repository root, for the two arm evaluation procedure
when a behavior change requires it.
