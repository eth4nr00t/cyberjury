# Knowledge Change Checklist

Use this checklist when adding or changing a vulnerability class, language guide, framework
guide, protocol guide, profile `detection.yaml`, prompt, methodology, packing, verification,
review engine code, benchmark metadata, or coverage metadata. Read [Knowledge Design](knowledge-design.md)
for the model and rationale, and [Engine Design](engine-design.md) for shared review behavior.
This checklist defines the standards and acceptance decision for the security knowledge system
and the review behavior that loads, selects, and validates it.

## Status Rules

| Status | Meaning |
| :--- | :--- |
| `pass` | The requirement holds, with concrete evidence. |
| `fail` | The requirement does not hold. Record a finding. |
| `not applicable` | The requirement cannot apply to this change, with a reason. |
| `not measured` | The check applies but could not be completed. Record the blocker and next action. |

A `not measured` status is not a pass. A failed provider, parser, facts backend, verifier, or
backtest is an error, never a clean result.

## Review Procedure

Use the final diff as the scope. Read surrounding code, tests, indexes, and configuration
only when they are needed to judge the change. Mark every item as `pass`, `fail`, `not applicable`,
or `not measured`. Do not silently skip an item.

- Classify each changed file.
- Select the required sections that match the file type.
- Read the changed content and the context needed to verify its contract.
- Run the listed validation for each change type.
- Run the required backtest when the change can affect review behavior.
- Record every failure and every unmeasured check.
- Record evidence for every item. A claim that something was reviewed is not evidence.
- Apply the decision rule in [Decision Rule](#decision-rule).

### Change Types

Classify each changed path by the behavior it owns. For a mixed diff, apply every matching row
and use the union of its required sections. The path patterns below are relative to the selected
profile root. The `Sections` column uses the numbered sections below. Do not invent a type to
avoid a required check.

#### Content Files

| Change type | Identify it by | Sections |
| :--- | :--- | :--- |
| Vulnerability class | `knowledge/vulnerabilities/<id>.md` | `1, 2, 3, 5, 6` |
| Language guide | `knowledge/guides/languages/<language>.md` | `1, 2, 3, 4, 5, 6` |
| Framework guide | `knowledge/guides/frameworks/<language>/<framework>.md` | `1, 2, 3, 4, 5, 6` |
| Protocol guide | `knowledge/guides/protocols/<protocol>.md` | `1, 2, 3, 4, 5, 6` |
| Detection YAML | `detection.yaml` | `1, 2, 4, 5, 6` |

Validation focus:

- **Vulnerability class:** Run schema, index, selection positive and negative coverage, examples,
  and knowledge coverage. Backtest when hints, body, `id`, aliases, impact, or category behavior
  changes.
- **Language guide:** Run guide schema, detection, routing, inheritance, and content checks.
  Backtest is required.
- **Framework guide:** Run guide schema, parent language, framework routing, inheritance, and
  content checks. Backtest is required.
- **Protocol guide:** Run guide schema, protocol detection, content, and example checks. Backtest
  is required.
- **Detection YAML:** Run loader, schema, classification positive and negative coverage, and profile
  tests. Backtest is required.

#### Review Behavior and Evaluation

| Change type | Identify it by | Sections |
| :--- | :--- | :--- |
| Review behavior | Prompt, methodology, packing, verification, or review engine code | `1, 5, 6` |
| Benchmark or coverage metadata | Benchmark manifests, answer keys, coverage data, scorers, or gates | `1, 5, 6` |

Validation focus:

- **Review behavior:** Run rendering, content loading, compatibility, and failure path checks.
  Backtest is required.
- **Benchmark or coverage metadata:** Run manifest schema, knowledge reference, coverage, and
  scorer or gate compatibility checks. Backtest when scoring or coverage behavior changes.

## 1. Scope and Integrity

Use this section to confirm the change stays in the right tree and does not weaken the review
contract.

- [ ] Content and classification changes belong in the selected profile's `knowledge/` or
      related `detection.yaml`. Workflow and evaluation changes remain in their owning
      directories.
- [ ] No language, framework, protocol, or vulnerability-specific rule was added to generic
      Python code.
- [ ] Related indexes, inherited guides, referenced classes, prompts, and tests were checked
      when their contracts may change.
- [ ] The diff contains no proprietary material or unrelated churn.
- [ ] The knowledge describes a reusable security property, not a benchmark route, symbol,
      variable, payload, file path, commit, sink combination, or exact fix.
- [ ] New hints and examples do not copy a motivating case, even after renaming identifiers.
- [ ] No answer key, scorer, benchmark expectation, or gate rule changed to make the change pass.
- [ ] A behavior change was checked on an independent real target. A motivating benchmark is
      regression evidence only, and cannot be the strongest generalization claim. See
      [No Benchmark Overfitting](knowledge-design.md#no-benchmark-overfitting).

## 2. File and Metadata Contract

Use this section to confirm file shape, frontmatter, and guide routing.

### Common Rules

- [ ] The file is in the correct profile directory.
- [ ] Runtime directories contain only loadable knowledge files.
- [ ] The `knowledge/index.md` file is documentation only and is not loaded as a knowledge item.
- [ ] Loaded vulnerability and guide files have valid frontmatter followed by a Markdown body.
      `knowledge/index.md` is the documented frontmatter exception.

### Vulnerability Classes

- [ ] Frontmatter fields are ordered as `id`, `title`, `impact`, `tags`,
      `selection_hints`, and optional `aliases`, matching the schema in
      [Knowledge Design](knowledge-design.md#vulnerability-classes).
- [ ] The `id` matches the file stem, uses lowercase kebab-case, and is stable.
- [ ] The `impact` value is `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- [ ] List values are non-empty strings. Hints are unique after case folding.
- [ ] Aliases are genuine model naming variants and do not collide with ids or other aliases.
- [ ] Taxonomy tags satisfy the owning profile's rules.

### Guides

- [ ] Fields are ordered as `id`, `title`, `kind`, optional `language`, `detect`,
      `entrypoint_files`, `entrypoint_markers`, `logic_layer_files`, and
      `public_api_patterns`.
- [ ] The `id` matches the file stem and is unique within the profile.
- [ ] The `kind` value matches the directory and is `language`, `framework`, or `protocol`.
- [ ] A framework guide references an existing language guide in the same profile.
- [ ] The `detect` value is a non-empty map with supported detection lists only.
- [ ] Routing lists are ordered and contain unique values where signals are intended.

## 3. Security Content and Examples

Use this section to confirm the knowledge body is specific and the examples are executable.

### Vulnerability Classes

- [ ] One H1 matches `title`.
- [ ] The body identifies attacker control, missing or bypassed control, dangerous operation,
      exploit condition, impact, reportable location, and safe boundary.
- [ ] A `Not a Finding` section names facts that make similar flows safe.
- [ ] Validation is not presented as a substitute for a stronger sink control.
- [ ] Sanitization is called safe only for its exact output context.

### Language Coverage

- [ ] For a code-level class, the review record includes a Language Coverage table that lists
      every language guide under the owning profile as `applicable` or `not applicable`.
- [ ] Every `not applicable` entry has a brief technical reason.
- [ ] Each applicable language has a vulnerable and secure pair when the security meaning or
      source pattern is meaningfully different in that language. A representative pair is
      enough when the meaning is unchanged.
- [ ] Code fences use languages supported by the owning profile. Configuration and protocol
      examples use their actual data formats.

### Example Quality

- [ ] Examples are minimal, self-contained, idiomatic, and understandable without hidden state.
- [ ] No ellipses, pseudocode, or undefined placeholders hide the security property.
- [ ] Examples teach the general property and do not reproduce a benchmark call chain,
      identifier set, payload, file layout, or exact remediation shape.
- [ ] Executable classes use runnable code. Configuration and protocol classes use structured
      examples.

## 4. Guide and Detection Content

Use this section to confirm routing and guide content stay aligned.

### Detection and Routing

- [ ] Detection lists contain unique, non-empty values and use the generic path matcher.
- [ ] The `public_api_patterns` values compile as multiline regular expressions.
- [ ] Framework routing adds framework-specific signals and does not repeat inherited language
      routing.

### Guide Content

- [ ] Language guides cover security-relevant language semantics and sensitive operations.
- [ ] Framework guides cover attacker-reachable entrypoints, control locations, and bypasses.
- [ ] Protocol guides cover the applicable actors, assets, trust boundaries, states, transitions,
      bindings, expiry, revocation, and replay behavior.
- [ ] Guides reference vulnerability classes instead of duplicating their full contracts.

### Repository File Detection

Apply this subsection only when `detection.yaml` or file classification behavior changes.

- [ ] Only supported fields are present: `skip_dirs`, `skip_root_dirs`, `source_extensions`,
      `config_extensions`, `manifests`, `compile_roots`, `test_dirs`, `test_name_patterns`,
      `doc_extensions`, and `lockfiles`.
- [ ] Required fields are present. Values are string lists with no duplicates or empty items.
- [ ] Extensions begin with `.` and use lowercase. Directory fields contain segments, not paths.
- [ ] Source and configuration rules retain security-relevant non-source files.
- [ ] Skip and test rules do not suppress production code. Manifests, lockfiles, and compile
      roots reflect actual profile behavior.

## 5. Selection and Integration

Use this section to confirm selection, packing, and output remain compatible.

### Selection and Generality

- [ ] Every new hint is a stable API, syntax form, annotation, protocol token, or equivalent
      reusable signal, not a project-specific symbol or payload.
- [ ] Hints are narrow enough to avoid routine unrelated selection and match real spelling.
- [ ] Each new hint family has representative deterministic positive and negative coverage.
- [ ] Intended knowledge is selected and common unrelated knowledge is not selected.
- [ ] Vulnerable and safe uses are both explained, including the controlling fact that makes a
      similar flow safe.

### Integration Compatibility

- [ ] The vulnerability index matches the class files and ids.
- [ ] Guide references and framework inheritance resolve across the profile.
- [ ] Frontmatter and detection data parse through repository loaders.
- [ ] Prompt rendering uses complete content from the selected profile.
- [ ] Ordering and knowledge packing retain every selected class without truncation.
- [ ] Category aliases, normalization, deduplication, and report output remain compatible.

## 6. Validation and Backtest

Use this section to confirm the change is measured and the backtest is sound.

- [ ] Focused tests for the changed type pass. Use profile and vulnerability tests for classes,
      guide tests for guides, detection tests for `detection.yaml`, and eval tests for coverage
      or benchmark metadata.
- [ ] Examples use an available parser, compiler, formatter, or focused test. An unavailable
      toolchain is recorded as `not measured`.
- [ ] Ruff, formatting, structured-data checks, and `git diff --check` pass when applicable.
- [ ] If behavior changes, baseline and changed arms use identical target, commit, scope,
      context, mode, rounds, model, provider, verification, concurrency, and budget.
- [ ] The two arm procedure follows section `Comparing Two Configurations` in
      `evals/docs/backtest.md`
      from the code repository root. If the code repository is unavailable, the backtest is
      recorded as `not measured` with the repository root supplied by the operator.
- [ ] Behavioral evaluation includes an independent real target and a known safe target or a
      production case whose issue is fixed.
- [ ] The review records recall, misses, reports, extras, false positives, errors, requests,
      tokens, and elapsed time. An unavailable metric is recorded as `not measured`.
- [ ] Every extra report is inspected manually. Improvement only on the motivating benchmark
      is treated as overfitting.

## Review Output

End the review with a short record containing:

```markdown
## Applicability
changed file, change type, required sections, and whether a backtest is required

## Results
section, status, and evidence

## Findings
location, checklist item, problem, and required correction

## Validation
command or evaluation, result, and evidence

## Decision
accepted, rejected, blocked, or accepted with follow-up
```

Add `Language Coverage` only when the changed file is a code level vulnerability class.

## Decision Rule

1. Record `rejected` when any required item is `fail`.
2. Record `blocked` when a required item is `not measured` and the missing evidence prevents a
   reliable decision.
3. Record `accepted with follow-up` only when the remaining work is documented, does not block
   acceptance, and does not support an unmeasured behavior improvement.
4. Record `accepted` only when every required item is `pass` or has a justified `not applicable`
   status and validation is complete.
