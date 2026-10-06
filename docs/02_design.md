# Template Design Specification — SVC-C2-013 IT Security Policy & ISMS Compliance Q&A Agent

**Template ID:** SVC-C2-013
**Template Name:** ITSecurityPolicyISMSComplianceQAAgent
**Category:** Cat 2 (multi-step domain workflow — retrieval pattern)
**Industry:** SVC

## Position in the framework

| Aspect | Value |
|---|---|
| Agent class | `ITSecurityPolicyISMSComplianceQAAgent` (alias `Graph`) |
| L1 Base (framework base class) | `AgentBaseGraph` — direct framework inheritance |
| Inner graph base | `BaseGraph` — `DomainWorkflowGraph` |
| Pattern | Two-layer nested: fixed outer backbone + a `GraphNode` in the `main` slot wrapping an inner workflow |
| State | flat `TypedDict` composition (never Pydantic — msgpack incompatible); structured fields stored as JSON strings via `to_json()` / `from_json()` |
| Node | `FunctionNode` subclasses; override `execute(self, state) -> dict` only — no extra parameter. Config reaches a node through State (see "Runtime configuration") |
| Graph | composition via `register_nodes()`; the outer `add_edges()` is NOT overridden |

## Purpose

An IT security policy and ISMS compliance Q&A agent for enterprise IT / compliance teams.
Questions about standard clauses, Japanese cybersecurity regulation and organisational
obligations are answered from a seeded corpus of standard and regulation excerpts (ISO/IEC
27001 and 27002, 不正アクセス禁止法, 個人情報保護法, サイバーセキュリティ基本法 context, METI
サイバーセキュリティ経営ガイドライン): validate → retrieve → rerank and filter → grounded answer
with standard/regulation citations → assembled guidance document with an action checklist and
a standing disclaimer. Retrieval and answer assembly are deterministic — keyword and
standard-reference scoring over the corpus and rule-based assembly from the retrieved chunks —
so the same question always returns the same answer and no model is called.

**Buyer signal**: Japan has the world's highest ISMS certification density (7,500+ certified
organizations); the 2024 不正アクセス禁止法 revision adds breach-notification obligations; METI
guidelines are mandatory reading for TSE-listed companies.

## Architecture

### Outer backbone (`AgentBaseGraph`)

```
START → initialize → pre_process → main → {route} → post_process → finalize → END
                                     ↓ (retry, bounded by max_retry)
                                   pre_process
```

| Slot | Class | Responsibility | required_trust_level |
|------|-------|----------------|----------------------|
| initialize | framework default | session_id, trust_level, schema_version | — (framework) |
| pre_process | `PreProcessNode` | trust gate; validate the query; refuse instruction-override payloads (phrased AND token forms, raw AND post-sanitise); validate every caller field against its bound → `validated_input`, `caller_request`. A correctable value stops the run carrying its reason; refused content terminates it (see "Two stop paths") | `VERIFIED_EXTERNAL` |
| main | `ComplianceQAGraphNode` (`GraphNode`) | delegates to the inner `DomainWorkflowGraph`; maps the inner answer fields into outer state | — (delegation) |
| post_process | `PostProcessNode` | the output boundary — disallowed-content scan + document invariant, fail closed; for a run stopped upstream on a correctable value, renders that reason's sentence as the whole body and publishes nothing else | `ANONYMOUS` |
| finalize | framework default | response metadata, total time | — (framework) |

### Inner graph (`DomainWorkflowGraph` — `BaseGraph`, linear)

```
START → input_validate → retrieve → rerank_filter → generate_answer → output_format → END
```

All five inner nodes declare `required_trust_level = TrustLevel.ANONYMOUS`. The external trust
gate lives on the outer backbone; a stricter inner level would deny a real authenticated invoke
at runtime.

| Node | Responsibility | Input State | Output State |
|------|----------------|-------------|--------------|
| `InputValidateNode` | length bounds (a query below the minimum stops the run carrying its reason); standard/regulation reference detection (ISO 27001 Annex A codes, Japan cyber laws, METI guidelines); query-type classification | `validated_input` | `normalized_query` |
| `RetrieveNode` | score the ISMS corpus against the query, detected standards and caller focus terms; keep the best candidates | `normalized_query`, `input_context`, `retrieval_top_k` | `retrieved_chunks` |
| `RerankFilterNode` | relevance-floor precision gate; rerank by score; cap at the effective result count (caller may tighten, never widen) | `retrieved_chunks`, `input_context`, `retrieval_top_k`, `retrieval_score_threshold` | `reranked_chunks` |
| `GenerateAnswerNode` | grounded answer synthesis strictly from the surviving chunks; abstention when none survive | `reranked_chunks`, `normalized_query`, `system_prompt_template` | `generated_answer`, `answer_citations`, `action_checklist` |
| `OutputFormatNode` | assemble the guidance document (focus line, guidance, references, checklist, disclaimer) | `generated_answer`, `answer_citations`, `action_checklist`, `input_context` | `compliance_answer`, `result` |

### Data flow

```
user_input (natural-language compliance question)
    │
    ▼ PreProcessNode (VERIFIED_EXTERNAL trust gate + caller contract)
validated_input, caller_request (JSON), enriched_context (JSON)
    │
    ▼ ComplianceQAGraphNode → DomainWorkflowGraph
    │   (caller_request crosses via the context bridge — see below)
    │   InputValidateNode    → normalized_query (JSON)
    │   RetrieveNode         → retrieved_chunks (JSON)
    │   RerankFilterNode     → reranked_chunks (JSON)
    │   GenerateAnswerNode   → generated_answer, answer_citations, action_checklist
    │   OutputFormatNode     → compliance_answer, result
    ▼ merge_output
compliance_answer, generated_answer, answer_citations, action_checklist → outer state
    │
    ▼ PostProcessNode (output boundary, fail closed)
formatted_output, result
```

## The caller-data contract

Caller data arrives on two channels and both are validated in `PreProcessNode`, which owns the
boundary. A field that breaks its bound never produces an answer. The error names the FIELD and
never echoes the VALUE. The structured channel is a CLOSED contract: a field outside the set
below is rejected, so a hostile field name never rides into the pipeline. How a stopped request
is REPORTED back depends on what stopped it — see "Two stop paths" below.

| Channel | Field | Contract |
|---|---|---|
| `input` | the query | plain text; control characters stripped, whitespace collapsed, 2000 characters maximum (over the cap the run stops carrying the reason, never truncated to a different question) |
| `input_context` | `channel` | inert identifier, `[a-z0-9_]{1,32}` |
| `input_context` | `top_k` | whole number, finite, 1–20 — TIGHTENS the declared result count, never widens it |
| `input_context` | `min_score` | number, finite, 0–1 — RAISES the declared relevance floor, never lowers it |
| `input_context` | `focus_terms` | list of compliance focus terms; 10 entries maximum; each 60 characters or fewer of the term alphabet `[\w &.,()/+-]` |

Absent structured data degrades to the plain query against the declared defaults. There is no
path on which unvalidated caller data reaches the pipeline.

### Two stop paths

A stopped request stops the same way on both paths — no retrieval, no answer, the audit event
unchanged. The paths differ only in how the stop is REPORTED.

| Path | What takes it | How the run ends | What the caller reads |
|---|---|---|---|
| completes carrying a reason | a value the caller can correct: no question at all, a question below the minimum length or over the cap, a structured field outside its bound or outside the closed field set | `status = success`, a reason code held in State | the sentence for that reason, as the whole body |
| terminates | content this agent refuses: an instruction-override payload on either channel, a contact identifier in a focus term | `status = error`, nothing carried forward | no body |

A correctable value completes rather than terminating because terminating ends the calling
surface's turn and surfaces only a status, leaving the reason reachable solely from the audit
trail; completing with a sentence lets the caller fix the value and send the request again on
the same conversation. A refusal is not a value to correct, and reporting it the same way would
read as an invitation to reword the request until it is accepted. The two are therefore
separated STRUCTURALLY — the validator returns the reason code beside its message — so a
refusal can never be reclassified by a change to the wording of a message.

The reason codes and the sentences they select (`src/services/failure_message.py`):

| Reason code | The sentence names |
|---|---|
| `EMPTY_INPUT` | that no question was received, and asks for the question to be sent |
| `QUESTION_TOO_LONG` | that the request is too long and should be shortened |
| `INVALID_REQUEST` | that a value could not be accepted and should be checked against the documented format |

The code itself never leaves the process. It is a State marker that the output boundary reads
to pick the sentence, and the caller envelope carries the sentence as the body and no reason
code — so neither a field path, a gate's wording nor an internal log reaches the caller
(`tests/proof_of_boundary/test_invoke_e2e.py::TestErrorHygiene`).

Once a reason is settled, every stage downstream passes it through untouched instead of working
on input that was already declined: `ComplianceQAGraphNode.execute()` does not run the inner
graph at all, so a second, vaguer reason can never overwrite the specific one, and the inner
domain nodes carry a settled reason through unchanged. A termination is carried across the same
boundary the same way, so the inner pipeline — which has no sight of it and would stop on its
own domain rule — can never turn a refusal into a completed run.

**Why the focus terms travel on the structured channel.** The framework's input gate masks
detected personal data on the query field, and its personal-name heuristic matches any two
consecutive capitalised words — which is the shape of an English control or policy name
("Information Classification", "Incident Management", "Change Management"). A term sent inside
the query arrives as a mask token and retrieval keys off the mask. Moving the terms to a channel
the framework does not scan is only half the fix; the other half is that this template screens
that channel itself.

**What the template's own screen does.** Every focus term is checked against the term alphabet,
then against `framework.security.pii_detector.detect_pii`, then against the instruction-override
screen. A term carrying a contact identifier is REFUSED, not masked — a masked term would
silently change which chunks rank. The screened detector types are `email`, `phone_jp`,
`phone_us`, `ssn_us`, `credit_card` and `my_number_jp`.

The `name` and `name_jp` heuristics are deliberately EXCLUDED from that screen. They match any
two Title Case words, which is precisely what a control name is, so screening on them would
refuse the ordinary terms this channel exists to carry — the same failure the channel was
introduced to avoid. Every other detector type is a shape no control name has and a personal
identifier that has no place in a compliance answer, so a term carrying one is refused outright.

**The instruction-override screen covers both attack forms, on both channels, twice.** The
phrased class ("ignore all previous instructions …") and the chat-template token class
(`<|…|>` specials, `[INST]`/`[/INST]`, `<<SYS>>`/`<</SYS>>`, bare role tags) are both refused.
The screen runs on the text as received AND again after sanitisation, because a
character-stripping sanitiser can assemble a payload the raw text did not contain — stripping a
control character from `ig\x00nore all previous instructions` yields the phrase intact. Refusal
is stated in behaviour (error status, nothing carried forward), never in a gate's wording, and
the template enforces this itself rather than relying on the platform gate: where that gate is
absent or configured off, an unchecked payload would otherwise reach the retrieval path and
return an answer. Both directions are pinned in `tests/unit/test_caller_contract.py` — attack
forms refused, ordinary compliance questions using the same vocabulary unaffected.

## Runtime configuration

Two files, two jobs:

| File | Contents | Read by |
|---|---|---|
| `config/agent.yaml` | the static manifest — identity, category, entry point, trust level, declared requirements. Flat: every key at root level | the agent registry |
| `config/config.yaml` | every runtime parameter — `max_retry`, `timeout_s`, the `retrieval` block (`top_k`, `score_threshold`) and the `llm` block (`system_prompt_template`) | the registry, which passes it as `Graph(config=...)` |

The standalone server reads the same file through `_load_runtime_config()` and constructs the
agent with it, so a registry-loaded agent and a deployed one run on identical settings.

From there a declared value reaches its consumer by one route each:

- `max_retry` — consumed by `AgentBaseGraph` for retry routing.
- the `retrieval` and `llm` blocks — validated once in `declared_settings()` (type, finiteness,
  range), handed to `ComplianceQAGraphNode` at `register_nodes()`, forwarded by
  `_parent_config()` into the inner graph's constructor, and republished by
  `_extra_initial_state()` as the `retrieval_top_k`, `retrieval_score_threshold` and
  `system_prompt_template` State fields, which is where `RetrieveNode`, `RerankFilterNode` and
  `GenerateAnswerNode` read them. `execute(self, state) -> dict` takes no config parameter, so
  State is the only plumbing route.

The module-level defaults in the node files are a FLOOR for a key the declaration omits, not a
mirror of the file. A declared value always wins, which is what makes the declaration
observable: `tests/proof_of_boundary/test_invoke_e2e.py` changes the declared result count on
disk and reads the change back out of the rendered answer. A reader pointing at the wrong file
would return the floor and that test would fail.

An out-of-contract declaration (NaN, Infinity, a string, out of range) is not forwarded and the
consumer keeps its floor. This matters for non-finite values in particular: NaN compares False
against every bound, so forwarding one would silently disable the filter it configures rather
than fail.

## State definition

| Field | Type | Purpose | Layer |
|-------|------|---------|-------|
| `validated_input` | `NotRequired[Optional[str]]` | sanitised, normalised query | outer |
| `caller_request` | `NotRequired[Optional[str]]` (JSON) | the validated caller request | outer |
| `enriched_context` | `NotRequired[Optional[str]]` (JSON) | `{source, channel}` metadata | outer |
| `retrieval_top_k` | `NotRequired[Optional[int]]` | declared result count | inner (seeded) |
| `retrieval_score_threshold` | `NotRequired[Optional[float]]` | declared relevance floor | inner (seeded) |
| `system_prompt_template` | `NotRequired[Optional[str]]` | declared prompt-template path | inner (seeded) |
| `normalized_query` | `NotRequired[Optional[str]]` (JSON) | `{query, detected_standards, query_type}` | inner |
| `retrieved_chunks` | `NotRequired[Optional[str]]` (JSON) | scored candidate chunks | inner |
| `reranked_chunks` | `NotRequired[Optional[str]]` (JSON) | filtered + reranked chunks | inner |
| `generated_answer` | `NotRequired[Optional[str]]` | grounded answer text | inner |
| `answer_citations` | `NotRequired[Optional[str]]` (JSON) | `[{source, standard_ref}]` | inner |
| `action_checklist` | `NotRequired[Optional[str]]` (JSON) | action items | inner |
| `compliance_answer` | `NotRequired[Optional[str]]` | assembled guidance document | inner |
| `result` | `NotRequired[Optional[str]]` | gated caller-facing result | outer |
| `error_code` | `Optional[str]` | the reason marker for a run stopped on a correctable value; read by the output boundary to pick the sentence, never published in the caller envelope | outer + inner |
| `trace_id` / `correlation_id` | `Optional[str]` | framework-managed tracing | both |

**Constraints:** flat `TypedDict` only; structured fields stored as JSON strings by every
producer AND consumer; domain fields `NotRequired`; `formatted_output` is not redeclared (it
stays framework-owned); no credentials or tokens in State; no Pydantic models, dataclasses or
arbitrary Python objects.

### The caller-data bridge

`GraphNode.execute()` invokes the inner graph as `subgraph.invoke(user_input, session_id=...,
ctx=...)` and does not forward the outer state's `input_context`. An inner read of
`state["input_context"]` would therefore always see `{}`. `src/graph/context_bridge.py` closes
that with a `ContextVar`: `extract_input()` stashes the validated request immediately before
the invoke, and the inner `_extra_initial_state()` reads it back. Only values `PreProcessNode`
has already validated are stashed — the bridge is a transport, never a second contract. A
`ContextVar` keeps the hand-off correct per thread, so concurrent invocations cannot see each
other's request.

## Security boundaries

- **Trust gate.** Every node declares `required_trust_level`. `PreProcessNode` requires
  `VERIFIED_EXTERNAL`; the inner domain nodes and the output boundary run at `ANONYMOUS` (trust
  is enforced once, at the entry). The standalone server elevates an authenticated bearer caller
  to `VERIFIED_EXTERNAL` (`INVOKE_AUTH_TOKEN`) and never demotes a trust level established
  upstream.
- **Input screens.** See "The caller-data contract" above — bounds, closed field set,
  instruction-override screen (both forms, both channels, raw and post-sanitise), and the
  structured-channel contact-identifier screen.
- **Output boundary.** `PostProcessNode` runs two independent layers from `execute()`, each with
  its own audit event, and fails closed on either: a disallowed-content scan that recurses into
  dict / list / tuple / set containers (a value nested one level down is exactly what a
  top-level-only scan misses), and the document invariant below. The scan covers
  credential-shaped content (API keys, JWTs, bearer tokens, credential assignments) AND
  specific-vulnerability disclosure (CVE identifiers, exploit/PoC markers) — this template gives
  general guidance only.
- **Error containment.** `ComplianceQAGraphNode.error_strategy = "propagate"`: an inner failure
  re-raises as `SubgraphError`, the framework converts it to an error status, and the backbone
  routes past the answer path — the caller envelope carries `output: null` and the base status
  fields only. A run stopped upstream on a correctable value never reaches the inner graph at
  all, and its envelope carries the reason's sentence as the body and nothing else. Tracebacks,
  reason codes and internal error logs never reach a caller on either path
  (`tests/proof_of_boundary/test_invoke_e2e.py::TestErrorHygiene`).
- **Secrets.** `requires.secrets` and `requires.extras` are both empty, derived from the code:
  this template calls no secrets provider and constructs no model client. `INVOKE_AUTH_TOKEN` is
  a deployment-level caller credential read from the environment in `src/api/server.py` only.
- **Audit.** Every node's `execute()` emits domain events on its decision points:
  `pre_process_validated` / `pre_process_validation_failed`, `input_validate_complete` /
  `input_validate_failed`, `retrieve_complete` / `retrieve_failed`, `rerank_filter_complete`,
  `generate_answer_complete` / `generate_answer_insufficient_context`,
  `output_format_complete` / `output_format_failed`, `post_process_complete`,
  `post_process_degraded` (a run stopped on a correctable value, carrying the reason code), and
  on refusal `post_process_s3_violation` (disallowed content — named for the platform's
  output-gate event family) or `post_process_document_invariant_violation`. Nodes do not emit
  the lifecycle events — `BaseNode.__call__()` owns those.

## Output boundary — the invariant this template enforces

The published contract is that **the rendered document's structure is this template's own**.
`_enforce_document_invariant()` checks it, line-anchored, and refuses the whole answer on any
violation:

| Clause | Rule |
|---|---|
| `title_heading` | exactly one line that is the title heading |
| `section_heading` | `1. Compliance Guidance`, `2. References`, `3. Action Checklist` and `DISCLAIMER` each exactly once, as whole lines |
| `disclaimer` | the standing disclaimer text is present |
| `reference_line` | every `  [n]` reference line carries an index a pipeline citation backs |

Caller text reaches the document only as single-line fragments: the query is
whitespace-collapsed before it is echoed and focus terms are alphabet-locked at the boundary. So
in normal operation the invariant is satisfied by construction, and the check is the independent
backstop that catches a renderer regression or an escape from the render path. The clauses are
line-anchored on purpose — a question that merely MENTIONS `2. References` is an ordinary thing
to ask about a document, and refusing to answer it would be the screen blocking real work.

**No monetary rounding grid applies here.** Agents that emit external financial reports round
every rendered aggregate to a fixed grid at this boundary. This template renders no monetary
aggregate: the answer is quoted corpus text, citation references and the caller's own echoed
query. A numeric snap would be actively wrong for it — passages are quoted from the standards
corpus, and rewriting a figure inside a quoted clause would falsify the guidance the answer is
grounded in, breaking the grounding property the template exists to provide. Both boundary
layers are therefore pure SCANS: they return a verdict and never rewrite the document. That also
means their order carries no risk, since neither can destroy evidence the other needs.
`tests/proof_of_boundary/test_invoke_e2e.py` pins the consequence — decimals, percentages,
ratios, grouped amounts, Annex codes and inert identifiers all arrive byte-identical through a
real invoke, and a personal identifier in the query is masked by the platform's input gate
before the pipeline ever sees it.

## Example query → answer

- Input: `"What does ISO 27001 Annex A A.8.2 require for information classification?"`
- Detected standards: `ISO/IEC 27001`, `ISO 27001 Annex A A.8.2`
- Retrieved (top): `iso27001-a8-2` (Information classification)
- Output: grounded guidance citing `ISO/IEC 27001 — Annex A A.8.2` + action checklist + disclaimer

## Grounding and abstention

The generation step is grounded STRICTLY in the chunks that survive the precision gate. When no
chunk clears the relevance floor, the answer is the explicit insufficient-coverage message
recommending a 専門セキュリティコンサルタント — never an invented requirement. The citation list
is built from the grounding chunks only. A production deployment swaps the deterministic
synthesis for a model call driven by the declared `llm.system_prompt_template`
(`prompts/isms_compliance.j2`); the grounding contract and output keys are identical either way.

## Human-in-the-loop

Not wired: `ComplianceQAGraphNode.propagate_hitl = False` and the inner pipeline is linear with
no interrupt checkpoint. The corresponding boundary test ships as an explicit skip stub that
activates if propagation is ever enabled.

## Import isolation

- The template imports `framework.*` and `shared.*` only — no platform-internal SDK imports
  (`tests/proof_of_boundary/test_import_isolation.py`).

## Design Decision Record

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| L1 base type | AgentBaseGraph | AutonomousBaseGraph | AgentBaseGraph | Fixed sequential RAG pipeline; no reasoning loop required |
| Composition pattern | Cat 1 (flat) | Cat 2 (nested GraphNode) | Cat 2 nested | 5 sequential domain steps behind the fixed backbone |
| Retrieval | Inline in generate | Separate Retrieve + RerankFilter nodes | Separate nodes | Single-responsibility; the precision gate (score_threshold) stays isolated |
| State dict fields | bare dict | JSON-serialised str | JSON-serialised str | msgpack checkpoint safety |
| Focus-term transport | query field | structured channel + bridge | structured channel | the platform input gate masks Title Case runs on the query field; the channel is template-screened instead |
| Caller tuning | clamp out-of-range values | reject out-of-range values | reject | a clamped value silently answers a different question than the caller asked |
| Reporting a stop | one error status for every stop | complete on a correctable value, terminate on refused content | split by kind | an error status ends the caller's turn and leaves the reason only in the audit trail; a refusal reported as correctable reads as an invitation to reword until it gets through |
| Generation | Real model call | Deterministic grounded synthesis | Deterministic | offline-reproducible; the declared prompt template documents the production wiring |
| Hallucination control | Free generation | Ground strictly in reranked_chunks | Grounded only | no-context → recommend 専門セキュリティコンサルタント, never invent requirements |
| Output rounding | fixed monetary grid | byte-identical quoted text | byte-identical | no monetary aggregate is rendered; rewriting quoted clauses would falsify guidance |
