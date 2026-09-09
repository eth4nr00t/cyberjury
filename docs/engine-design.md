# Engine Design

This document defines the shared review engine, its invariants, and the boundary between
deterministic orchestration and model judgment across Diff Review and Repository Review.
Use [Knowledge Design](knowledge-design.md) for the security knowledge model and
[Knowledge Change Checklist](knowledge-change-checklist.md) for acceptance checks on
knowledge changes. Use `README.md` for installation, CLI commands,
provider configuration, and user workflow.

## Core Terms

| Term | Meaning |
| :--- | :--- |
| Candidate | A potential issue retained in the working set before final reporting. |
| Convergence | The configured clean round condition where no new candidate identity appears. |
| Degraded | The `ReviewOutcome.degraded` signal for any incomplete outcome. |
| Evidence catalog | Exact source fragments a Finder may request by engine issued id. |
| Facts | Deterministic call, import, storage, or related structure extracted from the target. |
| Finding | A reportable candidate that satisfies location, evidence, and verification requirements. |
| Gate | The Repository Review check that refuses incomplete workspace state. |
| Judgment | One model task over a review unit, role contract, and review brief. |
| Review brief | The profile security kernel and complete behavior rule index. |
| Profile | The selected profile content tree and facts backend used for a review path. |
| Provenance | The roles, units, and evidence that produced or changed a candidate. |
| Review unit | One target surface assignment with optional dependency evidence. |
| Role contract | The Finder, Challenger, or Judge task and required JSON shape assigned to a judgment. |
| SARIF | A machine readable finding report in Static Analysis Results Interchange Format. |

The `degraded` signal is not a separate lifecycle state. It marks an incomplete outcome,
including failed work, missing grounding, pending investigation, incomplete verification, or
missing convergence.

## Core Invariants

### Generic Orchestration

The engine owns review mechanics, not security expertise. It schedules roles, validates
responses, tracks provenance, accumulates findings, handles failures, runs verification, and
decides whether a review is complete. Profile knowledge, prompts, detection signals, and
target specific location rules remain data or adapter responsibilities.

### Recall-Preserving State

The engine treats recall as the first red line. A later stage may remove a candidate only on
a controlling fact it can read from the target or grounded evidence. Relevance ordering changes
reading order, never inclusion. Accumulation is monotonic across completed judgment units and
adversarial rounds, so a later omission does not erase an earlier candidate. Responses that request
more evidence are provisional within their current judgment. Only its terminal response commits
findings. A failed continuation preserves provisional candidates as incomplete work.

### Fail Loud

A failed, rate-limited, blank, malformed, or unparsable model call is incomplete work, not zero
findings. The engine preserves candidates produced before a later role fails, records the failure,
and prevents the outcome from being reported as complete. Pending investigation and incomplete
verification also prevent completion.

## Review Paths

Both paths use the shared engine and verification contract. Each adapter shapes its target and
owns its lifecycle.

| Boundary | Diff Review | Repository Review |
| :--- | :--- | :--- |
| Target | Unified patch | Source tree plus facts |
| Unit | Changed patch surface with grounding | Candidate source range with facts |
| Location | Reviewed post change source line plus exact changed anchor | Reviewed source |
| State | Command outcome | Workspace state |
| Lifecycle | Review command | Scaffold, run, finalize, and gate |
| Verification | Source root required | Target and workspace roots required |
| Proof of concept | Not generated | Profile proof of concept support |

Repository units always cover candidate source ranges. Focused facts and dependency subgraphs add
grounding, but never replace that base coverage. Diff units always cover changed lines. They use
patch local grounding by default and repository dependency grounding when a source root is
available.

The paths differ in target shaping and lifecycle. They share role contracts, accumulation rules,
failure accounting, convergence policy, and verification rules that favor recall.

Profile PoC factories implement the shared contracts in `cyberjury/profiles/base.py`. Every backend
can generate and describe an artifact. An automatically executing backend also exposes managed
generation, repair, and execution through the reproduction capability. Web PoCs remain manual and
EVM PoCs may run only through the local Foundry backend. PoC generation is optional enrichment and
is disabled by default. Repository `--run` and `--finalize` enable it explicitly with `--poc`.
The immutable attempt request records that choice. Default review completion and cost never depend
on an implicit PoC model call. When `--poc` is explicit, a provider or local runner exception fails
the command. The persisted candidate union remains available for retry.

## Review Modes

### Standard Mode

Standard mode uses one Finder reviewer in both CLI paths. One review brief judgment is bound to the
exact unit evidence revision it reviewed. Exact source returned by that judgment becomes unit
evidence. Evidence requests and their followup judgment stay inside the same bounded judgment loop.

The generic revision scheduler can support several planned judgments. When one judgment adds source,
an earlier sibling result becomes stale and is rerun against the new revision. Stage 08 now plans one
review brief, so production review has no sibling knowledge packs and normally executes one stable
judgment per unit. The candidate accumulator remains monotonic across a stale rerun. A later omission
does not delete an earlier candidate.

One navigation session and one bounded exchange budget belong to the whole unit. The engine merges
the final candidate state before applying verification and completion rules.

### Adversarial Mode

Adversarial mode runs Finder, Challenger, and Judge roles in rounds:

- The Finder proposes exploitable findings.
- The Challenger tries to refute findings using controlling facts visible in the target. It also
  searches for missed findings.
- The Judge rules on candidates and can adjust severity or retain a candidate that remains supported.

The review loop merges the finding union after every round. Convergence requires the configured
number of consecutive clean rounds that add no new finding identity and leave no pending work.
Reaching the round cap is not proof of convergence.

```mermaid
flowchart TD
    A[Finder] -- Proposes Findings --> B[Challenger]
    B -- Challenges Candidates --> C[Judge]
    C -- Rules on Candidates --> D[Finding Union]
    D --> E{Clean Rounds With No New Identity?}
    E -- New Identity --> A
    E -- Stable --> F[Converged Outcome]
    A -. Role Failure .-> G[Preserve Earlier Findings and Mark Failed]
    B -. Role Failure .-> G
    C -. Role Failure .-> G
```

### Scheduling Receipt

Every diff or repository run persists `scheduling.json` in its attempt directory. The receipt binds
the schedule from `request.json` to the unit ids executed by that attempt. Each round records the
same planned unit order, new finding identity count, union size, error and pending counts, trailing
clean convergence streak, convergence decision, and duration. The final `stop_reason` distinguishes
single pass completion, convergence, failure, checkpoint failure, round exhaustion, an empty diff,
and a repository resume with no open units.

`ThreadPoolExecutor.map` may run units concurrently, but it returns results in input order. Finding
accumulation and scheduling records therefore use planned unit order rather than worker completion
order. Concurrency may change durations and provider completion order. It does not change unit
ownership, round numbers, union insertion order, or the coded convergence decision for identical
unit results.

Standard mode executes every unit once and does not require convergence. Adversarial mode repeats
the complete open worklist until its clean streak reaches `converge_after` or `max_rounds` is
exhausted. Diff review stops later rounds after a failed round because it has no persistent resume
workflow. Repository review may retry a failed unit in a later round and records a recovery only
after that unit returns a clean result.

The CLI uses the shared three round adversarial default for both review paths. The programmatic
repository API retains a higher 24 round cap for custom multi Finder runs and normally stops earlier
through convergence. Changing that public default requires detection quality measurement.

## Shared Workflow

Both paths follow this sequence:

```mermaid
flowchart TD
    A[Target Input] --> B[Build Review Units]
    B --> C[Navigate Required Source]
    C --> D[Assign Review Brief]
    D --> E[Build Judgment Prompt]
    E --> F[Run Judgment Roles]
    F --> G[Validate Candidate Output]
    G --> H[Accumulate Candidates]
    H --> I[Normalize Categories and Locations]
    I --> J[Verify Candidates]
    J --> L{Review Complete?}
    L -- Incomplete --> M[Incomplete Outcome]
    L -- Complete --> N[Report Findings]
    N --> O[Complete Outcome]
```

## Diff Review Workflow

Diff Review reviews one repository git range. Its adapter:

1. Parses the patch into changed review surfaces and joins surfaces connected by resolved
   dependency edges. Each connected component remains one review unit. Independent components
   are then packed toward the diff size target.
2. Builds grounding for the batch from the git range head worktree. The selected profile facts
   backend adds source evidence from typed dependency subgraphs. An unchanged call inside a changed
   definition remains visible in the graph facts. A missing repository preparation fails before
   model work.
3. Runs bounded source navigation before security judgment. Navigation publishes exact source ids,
   exposes confirmed caller and callee relationships in either direction, and reads only ids chosen
   by the model. Search and relationship results remain clues until their source ids are read. Its
   source only system contract cannot return findings.
4. Requests the diff knowledge inputs defined by
   [Runtime Flow](knowledge-design.md#runtime-flow).
5. Runs one Finder judgment with the complete behavior index in standard mode.
6. Runs Finder, Challenger, and Judge rounds in adversarial mode. The round union is carried
   into the next pass until clean convergence or the configured round limit.
7. Normalizes finding categories and validates two locations inside the originating unit. The report
   location must be a post change line shown in that unit or an exact repository line covered by a
   cited source receipt from that unit. The explicit change anchor must be an exact old or new changed
   line in the same unit. This represents added behavior, removed controls, and cross file effects
   without treating unchanged context as a change or borrowing evidence from another unit. A
   finding with invalid coordinates remains incomplete and makes the review incomplete. No model
   call is allowed to bypass this deterministic location gate.
8. Applies the shared verification contract for normal review commands. Every output format renders
   the retained verified finding state.

Diff Review does not own a persistent scaffold or unit worklist. It returns the outcome from
the command invocation while preserving the same provenance, failure, pending work, and
completion semantics as Repository Review.

## Repository Review Workflow

Repository Review owns a persistent workspace because its lifecycle spans multiple commands:

```mermaid
flowchart TD
    A[Scaffold] -- Creates Workspace --> B[Run]
    B --> C{Run Complete?}
    C -- Resume --> B
    C -- Stop --> D[Incomplete Review]
    C -- Complete --> E{Run Finalize?}
    E -- Finalize --> F[Finalize]
    E -- Skip Finalize --> G[Gate]
    F -- After Finalize --> G[Gate]
    G --> H{Gate Passes?}
    H -- Pass --> I[Complete Report]
    H -- Fail --> D
```

The stages have distinct responsibilities:

- **Scaffold** detects the stack, extracts facts, writes methodology and knowledge artifacts,
  and creates the unit worklist.
- **Run** reviews open units, navigates required source before judgment, resumes from the persisted
  union when requested, records failures and timing, verifies findings, consolidates complete
  coverage, and writes run status.
- **Finalize** parses and canonicalizes candidates, deduplicates them, verifies remaining
  findings, reconciles proofs of concept, and writes confirmed reports.
- **Gate** checks coverage, unit ownership, run completeness, verification state, and calibrated
  candidate state before allowing the review to be reported complete.

The run stage already writes confirmed findings. Finalize is optional for an engine run and
remains available for candidates already stored in a workspace.

The repository runner also accepts multiple injected Finder reviewers for programmatic fan out and
rotates them across rounds. The CLI does not configure this Repository Review extension.

The workspace is provenance and resumability state, not a second source of security knowledge.
Knowledge remains under the selected profile content root.
The `.cyberjury/workspace.json` marker binds the resolved target, selected profile, and source
fingerprint, and a changed identity requires `--fresh`.

## Shared Engine Contracts

The shared engine defines review mechanics. Target adapters define unit construction, prompt
shape, finding identity, location rules, and command lifecycle. The table below names each
responsibility owner.

| Owner | Responsibility |
| :--- | :--- |
| Engine | Plans, roles, failures, rounds, convergence, and outcomes |
| Verification | Skeptic and confirmer orchestration |
| Knowledge | Kernel and catalog loading, review briefs, rule expansion, aliases, and categories |
| Providers | Provider calls, retries, and metering |
| JSON parser | JSON extraction |
| Diff adapters | Diff units, prompts, locations, and command outcome |
| Repository adapters | Workspace, units, run, finalize, and gate lifecycle |

### Adapter Entry Points

The adapters enter the shared engine through a small set of shared contracts:

| Contract | Shared Mechanism | Adapter Provides |
| :--- | :--- | :--- |
| Execution policy | `review_schedule` | Mode and limits |
| Unit fan out | `run_review_units` | Unit list, known findings, and ownership records |
| Cycle loop | `run_review_cycles` | Next cycle and identity |
| Standard judgment | `run_standard_judgments` | Unit prompt and Finder adapter |
| Role round | `run_role_round` | Role prompts and response adapters |
| Candidate union | `FindingAccumulator` | Identity and merge rules |
| Outcome state | `ReviewOutcome` | Verification, report, persistence, and gate state |

Both adapters use these contracts. They supply target specific units, prompts, finding identity,
location rules, and lifecycle persistence while the shared engine retains role semantics, failure
accounting, accumulation, and completion rules.

### Facts and Grounding

Facts backends resolve dependency endpoints before the shared engine sees them. Each edge keeps its
kind, source definition when one exists, target source range, and resolution state. The resolution
is either exact or ambiguous. An internal edge that cannot be resolved remains an unresolved
receipt instead of disappearing. A readable source file that the native analyzer cannot parse, or
that exceeds the configured parse size, becomes a structured facts limitation. Other source files
still contribute facts, and the opaque file is reviewed from its raw source, but the review remains
incomplete until that limitation is removed. Incomplete facts are persisted for diagnosis but are
not stored in the reusable facts cache.

A judgment unit receives only the limitations for source it renders, relationships it presents, or
evidence it publishes for a bounded request. An unrelated repository limitation does not change that
unit. The target outcome retains the union of relevant unit limitations so resume, finalize, and the
repository gate cannot report incomplete grounding as complete.

Backend startup, unavailable native tools, invalid analyzer configuration, and repository wide
compilation failures remain hard extraction failures. Missing source bytes or a missing configured
grammar also fail extraction. Recoverable limitations require source that remains available for raw
review. This gives every profile the same contract without pretending that a Tree-sitter parser gap
and a Slither compilation failure have the same recovery scope.

Each profile implements the same facts pipeline. Its analyzer owns the native tool boundary and
normalizes native output into typed local analysis. Its resolver maps analyzed identities to
repository paths, ranges, and dependency endpoints. Its graph module builds and renders the shared
facts shape. Its backend coordinates those stages and owns the public extraction contract. This
keeps Web and EVM structurally aligned without pretending that Tree-sitter queries and Slither
compilation are the same operation.

The EVM analyzer preserves exact Slither call endpoint identity in typed analyzed calls. Its
resolver maps those identities to repository definition fragments. The Web backend resolves
Tree-sitter calls, named and default imports, and namespace qualified references within the
repository import scope. Repository module identity comes from exact relative imports, Python
package structure and declared source roots, owner scoped JavaScript workspace packages and path
aliases, and owner scoped Go module declarations. A damaged declaration is a facts limitation
rather than an absent module. An unrelated repository path with the same basename is not module evidence.
An import with no local module identity stays outside the repository dependency graph. A confirmed
local module whose target source or symbol is missing remains an unresolved receipt.

Target location and invocation boundary are separate facts. A Solidity high level call can resolve
to repository source and still cross an external message boundary. A runtime target with no static
source location remains a risk fact without becoming a required source dependency. An analyzer or
resolver limitation becomes incomplete grounding only when it prevents locating a target already
known to belong to the review scope. Both profiles lower confirmed source targets, unresolved local
targets, and scoped limitations into the same shared facts contract.

Lexical owner identity keeps `self` and `this` calls inside their owning
type, including closures that preserve the receiver. A nested function that rebinds `this` does not
inherit the class owner. An unqualified call resolves within its configured call scope or through a
symbol imported into the file. Python, JavaScript, and TypeScript expose top level definitions in
file scope and preserve enclosing function scopes for nested definitions. A class member does not
become a bare file binding. Go package functions also resolve across files in the same package
scope. That scope combines the source directory and parsed package declaration rather than matching
a repository wide name. Re-export traversal follows the same symbol through every reachable facade
module and stops at cycles. A member call with no resolvable namespace does not fan out to every
repository method with the same name. When syntax leaves more than one scoped target possible, the
backend retains every candidate and marks the edges ambiguous.

The shared subgraph builder never resolves a target from a bare function name. Diff Review starts from
definitions that contain changed lines. Repository Review starts from definitions in each candidate
file. Traversal continues from the reached definition, not from every function in the reached file.
This keeps unrelated sibling functions out of an attack path.

The planner preserves a directed dependency subgraph instead of flattening relationships into an
unordered set of definitions or enumerating every combinatorial path. Each direct caller of a changed
or candidate definition starts a review surface that keeps the caller and callee together. Existing
outbound traversal from the reviewed definition keeps its configured depth. Full source evidence is
selected by hop within a soft packing target. Final rendering never truncates selected evidence after
recording it as included.
For Diff Review, changed surfaces joined by a resolved dependency edge form one atomic component
before packing. A soft size target may group independent components, but it never splits a known
path between changed entrypoint and changed sink code.

The dependency graph is an internal navigation index, not a block copied wholesale into the
prompt. Targets omitted from the initial source window become an evidence catalog. Each catalog
entry has an opaque stable id, an exact source identity, and a short relationship label. The model
also sees the exact declaration signature, which exposes compact type and inheritance structure
without copying the implementation body. It can select published ids and search verified source by
symbol or exact text. It cannot ask the engine to browse an arbitrary path.

A review role may search verified repository source through a bounded exchange. A search publishes
only the current result page as session local `src-*` ids without choosing among its results. The
short id is a transport handle. The engine retains the exact file and source range as its identity
and reuses one handle when different searches publish the same range. An unambiguous complete symbol
or text result is read in the same exchange when it fits the response budget. Ambiguous results need
an explicit `evidence_requests` read. An off page, unknown, or invented id cannot be read.

The role requests both catalog `ev-*` ids and searched `src-*` ids through one
`evidence_requests` field. One response can contain at most eight queries and one session at most 64
unique queries. The same canonical query cannot repeat in one session. Each evidence exchange has a
48,000 character target and the shared unit budget allows at
most eight followups. An unknown id, repeated query, over budget request, or failed followup marks
the judgment incomplete.

Standard mode stores the unit judgment with its evidence revision. Source requests and their final
judgment remain in one bounded loop. If a programmatic sibling judgment adds source, stale siblings
rerun on the expanded revision. The candidate accumulator remains monotonic, so omission in a later
revision cannot delete an earlier candidate. Adversarial mode keeps the same validated exchange. The
Challenger and Judge receive source selected earlier in their role sequence.

Target coverage and grounding coverage are separate. Target coverage accounts for every changed
line or candidate source range. Grounding coverage accounts for source fragments promised to one
judgment and source returned for an evidence request. A dependency edge is not proof that its
target source was read, so the edge alone never counts as included evidence. Dependency grounding
supplements Repository Review source units and never turns the presence of one parsed definition
into coverage of the whole file.

The composition layers apply the core invariants at different scopes.
`run_grounded_standard_judgments` owns revisioned unit judgments, `run_role_round` owns one role sequence,
`run_review_cycles` owns convergence, and `run_review_units` owns target coverage.
`FindingAccumulator`, `ConvergenceState`, and `ReviewOutcome` carry their combined state into the
completion policy.

## Prompt Construction

Prompts are the boundary between deterministic target evidence, profile security knowledge,
and model judgment. Prompt builders must not replace the knowledge catalog with hardcoded
vulnerability logic.

Source navigation is a shared request contract inside Finder, Challenger, and Judge judgments. A
role returns searches and exact evidence requests beside its candidate response. Code validates and
executes the request, then adds the exact source to the next prompt. Navigation itself never creates
a finding. Diff Review and Repository Review use the same navigator and evidence loop.

### Prompt Inputs

Each adapter composes a prompt from these inputs:

| Input | Source | Purpose |
| :--- | :--- | :--- |
| Role contract | Adapter prompt module | Role task and JSON shape |
| Review policy | Selected profile | High confidence standard and do-not-report rules |
| Categories and rubric | Profile catalog | Category names and severity calibration |
| Target evidence | Target adapter | Diff, source unit, context, guides, or facts |
| Evidence catalog | Shared grounding context | Exact dependency source available by id |
| Review brief | Selected profile | Security kernel and complete behavior index |
| Candidate rule details | Selected profile | Required, refuting, and location evidence for cited rules |
| Prior candidates | Engine accumulator | Findings carried between evidence revisions or rounds |

The target adapter shapes evidence. Shared prompt helpers own reusable judgment wording and the
prompt plan boundary. A prompt assignment is not evidence of a finding. The model must still
provide a concrete exploit path and an exact location.

### Stable and Variable Content

The shared `PromptPlan` separates a reusable `stable_prefix` from a changing `judgment_suffix` where
the target adapter uses that boundary. The prefix contains target evidence and policy. The suffix
contains the review brief, candidate decision details when applicable, and the output shape.

Diff Review builds its prefix from focus, do-not-report guidance, allowed categories, selected
stack guides, the patch with `old:new` line gutters, grounded context, and the severity rubric.
Repository Review builds its prefix from the mandate, rubric, shared context, extracted facts,
allowed categories, and the source unit. Repository adversarial prompts add the review brief to the
stable evidence before appending the role task.

Providers receive the stable prefix as `cache_prefix` when the adapter enables caching. This
is a provider optimization and must not change the evidence, review brief, or completion
state. A cache boundary is valid only when the prefix is genuinely reusable for that target.

### Role Output Contracts

The role system separates discovery from skepticism and adjudication:

- The Finder searches broadly for exploitable issues and returns `findings`. It may also search
  repository source through `source_queries`, then request any published `ev-*` or `src-*` id through
  `evidence_requests`. It requests complete decision rules by rule or category id. A final response
  assesses every rule that role expanded. Any finding returned before a further evidence, source, or
  rule request is provisional and remains owned by the engine. A terminal rule assessment confirms
  or refutes it. Omission alone does not delete it.
- The Challenger returns `rebuttals` for unsupported candidates and `new_findings` for issues
  the Finder missed. A rebuttal needs a controlling safety fact visible in the reviewed target.
- The Judge evaluates both streams and returns surviving `findings`. It may also return
  downgraded, dismissed, unresolved, or investigate items where the target adapter supports
  those fields.

Complete rules shown for an existing candidate support these role outputs. They are not discovery
assessment obligations. The engine tolerates a valid redundant assessment for one of these rules,
but it cannot preserve or delete the candidate. Rules the current role requested from the index
remain mandatory assessment obligations.

Providers receive a strict JSON Schema for every judgment and verification role. OpenAI maps it to
the selected Responses or Chat Completions structured output field. Anthropic maps it to
`output_config.format`. System prompts still require one JSON object with no surrounding prose. The
local parser validates the complete object against that same closed schema, including nested fields,
before target adaptation. Every profile finding names a `decision_rule_id`, and code verifies that
the rule belongs to its normalized category. Target adapters then normalize finding items,
locations, severities, and categories into the target finding type. Unusable output at either level
is a role failure.

Repository model findings do not return a status field with one allowed value. Code assigns
`confirmed` after schema and semantic validation. Judge pending records always return `id` and
`candidate_id` as a string or null. Code removes null values before assigning a stable pending id.

Each model call record names the exact `decision_rule_ids` present in that call. The prompt hash is
the complete model visible input identity. A stable `call_id` hashes the role, trigger, unit, round,
evidence revision, knowledge, provider, model, prompt, and response schema identities. Repeated
logical inputs therefore share a call id even when concurrency changes their observed completion
sequence. The explicit ids let an operator audit which maintained security contracts contributed
to a judgment.

Each model backed attempt writes `model-calls.json` in its attempt directory. The artifact records
call id, role, trigger, unit, scheduler round, evidence revision, review brief hash, rule ids, prompt
and response schema hashes, cache enablement, cache prefix identity, response identity, token usage,
duration, and parse status. Response identity is a character count and hash. Response text is not stored in this
artifact. Judgment calls also record navigation status, query and evidence request counts, delivered
evidence ids, delta characters, delta hash, and a failure reason. A failed model or response parse
marks navigation as not evaluated. A journal receipt binds its call count and content hash.
New attempts cannot complete without this receipt. Historical v1, v2, and v3 attempts remain readable,
and any receipt that is present is validated when the session is reopened.

### Prompt Constraints

Prompt changes preserve [Core Invariants](#core-invariants) and keep the general case as the
objective. Prompt builders use profile data for security focus, reporting exclusions, guides,
decision rules, and severity guidance. They keep model-facing content English and require
an explicit JSON output contract. Knowledge completeness and benchmark integrity are defined in
[Knowledge Design](knowledge-design.md#design-principles).

## Finding Accumulation and Identity

Each adapter supplies a finding identity function and an evidence folding function.
The `FindingAccumulator` preserves insertion order, merges repeated identities, and can aggregate
severity votes. Both facts backends publish exact callsite ranges through the shared relationship
evidence contract. A report line inside one unambiguous outer callsite binds to that callsite id.
Nested lines of one multiline operation then share one source operation identity. Sibling calls on
one line remain unbound because the line cannot distinguish them.

Diff and repository union identity uses source operation, category, and primary decision rule when
that binding exists. It falls back to the adapter's exact location, change anchor, symbol, or endpoint
identity when no operation is unambiguous. Different rules at one operation remain distinct. The
source operation id is internal orchestration state and is persisted in the repository union
checkpoint. It is not a model supplied or public finding field.

Knowledge assignment and candidate rule expansion follow
[Runtime Flow](knowledge-design.md#runtime-flow). The engine binds the review
brief and every unit to Stage 07 grounding in `knowledge.json`.

## Verification Contract

Verification favors recall:

- A skeptic tries to prove a candidate safe.
- A candidate is dropped only when every applicable independent confirmer upholds the refutation.
- A verifier that found a candidate cannot also confirm its deletion. The engine tracks that rule
  with `found_by` provenance.
- With no distinct confirmer, the candidate is retained.
- A verifier failure, malformed verdict, or incomplete source check retains the candidate and
  marks the outcome incomplete. Its `degraded` signal becomes true.

This contract applies to both paths. Adapters translate their finding shape and source root into
the shared verification interface.

## Completion and Failure

An outcome is complete only when all required work is accounted for:

- no failed review units or role calls
- no uncovered changed lines or candidate source ranges
- no pending investigation work
- no missing or unresolved required grounding evidence
- no incomplete verification
- no verification or parsing errors
- convergence when the review plan requires it

Standard mode does not require convergence. Adversarial mode does. Diff Review surfaces a
degraded result and exits nonzero when required work fails or does not converge. Repository Review
persists the same state in `_run.json` and the repository gate refuses an incomplete run.

## Extension Boundaries

Adding a language, framework, protocol, category, or behavior rule should normally be a profile data
change plus tests. A new profile adds its content root and registry entry. Engine changes are
appropriate only when the generic review contract changes, such as a new lifecycle state,
failure rule, shared role contract, or target neutral verification behavior.

The [Knowledge Change Checklist](knowledge-change-checklist.md) applies only to profile content.
Engine and prompt behavior changes follow the repository detection quality rules. Measure them
with `Comparing Two Configurations` in `detection-quality-backtest.md` before making
them the default. Recall decides first. Cost is always recorded but does not reject a change on
its own.

Defaults for unit size, context budgets, review rounds, convergence, concurrency, and verification
live in `cyberjury/review/settings.py`. CLI flags such as `--rounds` override the exposed execution
settings.
