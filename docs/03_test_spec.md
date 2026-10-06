# Test Specification — SVC-C2-013 IT Security Policy & ISMS Compliance Q&A Agent

## 1. Test Strategy

- **Agent:** SVC-C2-013 — IT Security Policy & ISMS Compliance Q&A Agent (Cat 2,
  retrieval pattern, two-layer nested graph: outer `AgentBaseGraph` backbone + inner
  `DomainWorkflowGraph` `BaseGraph`).
- **Coverage target:** ≥ 90% of `src/nodes/` + `src/graph/` branches.
- **Test types:** Unit (per node + graph wiring + the caller-data contract) ·
  Proof-of-Boundary (framework security/serialization contracts) · End-to-end through the
  real ASGI `/invoke` entry with bearer auth.
- **Framework provisioning:** `framework` (agenticstar-agentcore) is supplied by the
  environment; the suite imports the real modules — there are no stub nodes.
- **Audit events:** `emit_trace_event` is patched at the node module level in unit
  tests to avoid audit-backend calls, never via a `sys.modules` stub (which would
  break the real `shared` package the framework loads at import time).

### RAG-specific quality strategy

This is a regulatory-grade compliance corpus (ISO/IEC 27001·27002, 不正アクセス
禁止法, 個人情報保護法, METI サイバーセキュリティ経営ガイドライン). Two retrieval
properties are tested explicitly:

- **Grounding (no hallucination):** every generated answer is synthesised
  *strictly* from the chunks that survive the rerank/filter precision gate
  (`score >= score_threshold`). The answer cites only those chunks; the citation
  list is built from the grounding chunks, never invented.
- **Abstention:** when no chunk clears the precision gate, `GenerateAnswerNode`
  returns the insufficient-coverage answer (recommending a
  専門セキュリティコンサルタント) with an **empty** citation list rather than inventing a
  requirement. This is the hallucination boundary and is asserted directly
  (`test_no_hallucination_abstains_when_no_chunks`), and again end-to-end
  (`test_an_out_of_domain_question_abstains_rather_than_inventing`).

### Test file map

| File | Scope | Tests |
|------|-------|-------|
| `tests/unit/test_nodes.py` | All 5 domain nodes + pre/post_process backbone nodes + outer & inner graph wiring | 59 |
| `tests/unit/test_caller_contract.py` | The caller-data contract, proven by DIRECT `execute()` calls (no framework wrapper): instruction-override screen (phrase + token class, raw + post-sanitise, both channels, both directions), per-field finite/bounded matrix, closed field set, focus-term screening, declared-settings validation | 67 |
| `tests/unit/test_framework_compliance_tc06_tc07.py` | TC-06/TC-07 — the framework security gates cannot be overridden | 2 |
| `tests/proof_of_boundary/test_pb_invoke_order.py` | PB-6 per-node + backbone invoke order (VERIFIED_EXTERNAL) + trust-gate denial/admission + payload alignment | 7 |
| `tests/proof_of_boundary/test_invoke_e2e.py` | PB-E2E — the public path through the real ASGI `/invoke` with bearer auth: auth boundary, real grounded work, declared-config liveness, caller-data effects, validation rejection, rendered-document contract, error hygiene | 47 |
| `tests/proof_of_boundary/test_import_isolation.py` | PB-4 platform-internal import isolation (AST scan) | 1 |
| `tests/proof_of_boundary/test_state_safety.py` | PB-2/PB-5 State msgpack/credential safety (AST scan) | 1 |
| `tests/proof_of_boundary/test_pb7_hitl_interrupt_propagation.py` | PB-7 HITL interrupt-propagation (skip stub — no cross-boundary HITL) | 1 (skip) |

### Canonical valid payload (PB-6 `_VALID_PAYLOAD`)

SVC-C2-013 is a retrieval Q&A agent — the caller input is a natural-language
compliance question (**not** a JSON object). The question below names ISO/IEC
27001 Annex A A.8.2 and the 不正アクセス禁止法 so the deterministic retriever
grounds the answer in real corpus chunks and the pipeline runs end-to-end to a
grounded SUCCESS. It is used by the backbone invoke test and by
`deploy/invoke_payload.json` (the two MUST stay identical — asserted by
`test_invoke_payload_matches_pb6`):

```
Under ISO/IEC 27001 Annex A A.8.2, how must information be classified, and what
breach notification obligations apply under the 不正アクセス禁止法 when an
unauthorized-access incident is detected?
```

Retrieval grounds this question in the ISO/IEC 27001 Annex A chunks and the
不正アクセス禁止法 breach-reporting chunk (score ≥ `score_threshold` = 0.4) ⇒
`generated_answer` is grounded, `answer_citations` non-empty, `status = success`.

## 2. Framework Compliance Tests (Mandatory)

| TC-ID | Test | Expected Result | Where |
|-------|------|----------------|-------|
| TC-01 | State contract: flat `TypedDict`, domain fields `NotRequired`, no Pydantic/dataclass | AST scan: 0 violations | `test_state_safety.py` |
| TC-02 | Empty / whitespace-only input stopped at PreProcessNode | run completes carrying the reason: `status=success`, `error_code=EMPTY_INPUT`, no answer; the internal reason stays in `error_log` | `TestPreProcessNode` |
| TC-03 | No JWT/credential in State | credential-name scan: 0 violations | `test_state_safety.py` |
| TC-04 | `execute(self, state)` contract | signature `(self, state)` asserted | `test_execute_signature_is_state_first` |
| TC-06/07 | The default input/output security gates cannot be overridden by a subclass | `TypeError` at class definition | `test_framework_compliance_tc06_tc07.py` |
| TC-08 | `required_trust_level` enforced in `__call__` before `execute()` | ANONYMOUS caller → refused; VERIFIED_EXTERNAL → admitted | `TestTrustGate` |
| TC-08a | Outer `PreProcessNode` = VERIFIED_EXTERNAL; inner nodes + post_process = ANONYMOUS | trust levels asserted per node | `test_trust_level_*` |
| TC-11 | Output boundary on post_process | credential / specific-vulnerability pattern → redacted + `status=error`; forged structure → redacted + `status=error`; clean → pass | `TestPostProcessNode` |

## 3. Proof-of-Boundary Tests (Mandatory)

| PB-ID | Boundary | Test | Expected Result | Where |
|-------|----------|------|----------------|-------|
| PB-2 | State serialization | AST scan of `src/schemas/state.py` | primitives only; no Pydantic/dataclass | `test_state_safety.py` |
| PB-4 | Import isolation | AST scan of `src/` | 0 platform-internal imports | `test_import_isolation.py` |
| PB-5 | Checkpoint safety | no credential-named fields / prohibited types in State | inspection pass | `test_state_safety.py` |
| PB-6 | Invoke execution order (per node) | `__call__`: trust gate → node_start → input gate → `execute()` → output gate → node_complete | order verified for every `src/nodes/` class | `TestInvokeOrder` |
| PB-6a | Trust gate at NODE level | `PreProcessNode({caller_trust_level: ANONYMOUS})` | `status=error`, error_log "trust gate"; VERIFIED_EXTERNAL admitted | `TestTrustGate` |
| PB-6b | Backbone invoke order | full `Graph().invoke(_VALID_PAYLOAD, ctx=VERIFIED_EXTERNAL)` | `status=success`; node_history = `[Initialize, PreProcess, ComplianceQAGraphNode, PostProcess, Finalize]` | `TestBackboneInvokeOrder` |
| PB-6c | Real external caller | `InvocationContext(caller_trust_level=VERIFIED_EXTERNAL)` — **never** `for_internal()` | inner ANONYMOUS nodes accept the passthrough trust; SUCCESS end-to-end | `TestBackboneInvokeOrder` |
| PB-6d | Payload alignment | `deploy/invoke_payload.json["input"] == _VALID_PAYLOAD` | the deployment's first-invoke evidence exercises the PB-6 payload | `test_invoke_payload_matches_pb6` |
| PB-7 | HITL interrupt propagation | skip stub — `propagate_hitl=False`, no cross-boundary interrupt() checkpoint | skipped with reason (real assertion when HITL wired) | `test_pb7_hitl_interrupt_propagation.py` |
| PB-E2E | The public path | real ASGI `/invoke`, bearer auth | see §4 | `test_invoke_e2e.py` |

## 4. The public path, end to end (`tests/proof_of_boundary/test_invoke_e2e.py`)

Everything below runs through the real ASGI entry (`src/api/server.py`) with bearer auth —
the surface a caller actually reaches. Deterministic; no network beyond the in-process
transport; no model call.

| Group | Proves |
|-------|--------|
| `TestAuthBoundary` | no bearer token → 401 and no answer; a bearer caller is admitted |
| `TestRealWork` | a grounded answer is computed from the seeded corpus (references + disclaimer present); an out-of-domain question abstains rather than inventing |
| `TestDeclaredConfigIsLive` | a value declared in `config/config.yaml` ARRIVES at the inner graph — the declared result count is read back off the rendered answer for three different declarations, and the shipped declaration is the one the answer uses |
| `TestCallerDataChangesTheAnswer` | a Title Case control name sent as a focus term retrieves and is PINNED end-to-end in the rendered answer (`Compliance focus applied: Information Classification`), while the same text sent as the query arrives masked and abstains; `top_k` tightens but never widens; `min_score` raises the floor but never lowers it |
| `TestValidationRejectionThroughInvoke` | both stop paths through the real entry. A correctable value (NaN / Infinity / bool / out-of-range / fractional count / free-text channel / entry-cap / unknown field / markup in a focus term; and no question, an over-cap question, a question below the minimum length) → the run completes, the body is that reason's sentence, no answer; refused content (a contact identifier in a focus term, an override payload as a field NAME or inside an undeclared field, an instruction-override query — phrased, token, `\u`-escaped) → error status, no body; oversized `input_context` → 413 at the adapter |
| `TestRenderedDocumentContract` | the document's structure is the template's own (each heading exactly once); caller markup stays inline and cannot open a section or forge a reference line; decimals, percentages, ratios, grouped amounts, Annex codes and inert identifiers survive byte-identical; a personal identifier in the query never reaches the report |
| `TestErrorHygiene` | a refusal surfaces as an error envelope with no traceback and no internal log fields; a run stopped on a correctable value surfaces the sentence and nothing internal — no field path, no gate wording, no reason code, no internal log |

## 5. Business Logic Tests

| BL-ID | Test | Input | Expected Result | Where |
|-------|------|-------|----------------|-------|
| BL-01 | Happy-path grounded answer | `_VALID_PAYLOAD` | assembled ISMS guidance doc; `ISMS COMPLIANCE` + `ISO/IEC 27001` present | `test_backbone_invoke_succeeds_and_returns_output`, `TestInnerDomainGraph` |
| BL-02 | Standard/regulation detection | question naming ISO 27001 / Annex A A.8.2 / 不正アクセス禁止法 | `detected_standards` includes all three; query_type = `breach_notification` | `TestInputValidateNode` |
| BL-03 | Retrieval scoring & ordering | normalized ISO query | candidates carry `{chunk_id,source,standard_ref,text,score}`, sorted score-desc | `TestRetrieveNode` |
| BL-04 | Rerank precision gate | scores `[0.9,0.5,0.3,0.1]`, threshold 0.4 | only 0.9 + 0.5 survive; reranked score-desc; capped at top_k | `TestRerankFilterNode` |
| BL-05 | Grounded generation | 2 reranked chunks | answer cites the chunk text; `answer_citations` non-empty; checklist built | `test_grounds_answer_in_reranked_chunks` |
| BL-06 | **Abstention (no hallucination)** | **0 reranked chunks** | insufficient-coverage answer + 専門セキュリティコンサルタント; `answer_citations == []` | `test_no_hallucination_abstains_when_no_chunks` |
| BL-07 | Output document assembly | grounded answer + citations + checklist | headings `1. Compliance Guidance` / `2. References` / `3. Action Checklist` / `DISCLAIMER`; `result == compliance_answer` | `TestOutputFormatNode` |
| BL-08 | General-guidance-only gate | answer containing `CVE-2024-12345` / exploit | redacted, `status=error` | `test_gate_redacts_specific_vulnerability_disclosure` |
| BL-09 | Graph key coupling | inner `get_output` ↔ outer `merge_output` | 5 coupled keys mapped; `merge_output` returns changed keys only | `TestOuterGraphComposition`, `TestInnerDomainGraph` |
| BL-10 | Focus-term retrieval | focus term matching a corpus chunk | chunk boosted above the floor; focus line rendered | `TestCallerDataChangesTheAnswer` |

### Negative / boundary cases

| Case | Node | Expected |
|------|------|----------|
| empty / whitespace `user_input` | PreProcessNode | completes: `status=success`, `error_code=EMPTY_INPUT`, `error_log` "empty", no `validated_input` |
| oversized input (> 2000 chars) | PreProcessNode | completes: `status=success`, `error_code=QUESTION_TOO_LONG`, never truncated |
| instruction-override content (phrase or token, raw or sanitiser-assembled) | PreProcessNode | terminates: `status=error`, no `error_code`, nothing carried forward |
| contact identifier in a focus term | PreProcessNode | terminates: `status=error`, nothing carried forward |
| caller field out of contract (type / finiteness / range / alphabet / entry cap / unknown field) | PreProcessNode | completes: `status=success`, `error_code=INVALID_REQUEST`, `error_log` names the field, value never echoed |
| query < 3 chars | InputValidateNode | completes: `status=success`, `error_code=INVALID_REQUEST`, `error_log` "too short" |
| a reason already settled upstream | every downstream node + the `main` slot | carried through untouched; the inner graph does not run and no second reason overwrites it |
| missing `normalized_query` | RetrieveNode | `status=error`, "normalized_query" |
| all candidates below threshold | RerankFilterNode | empty `reranked_chunks`, `status=success` |
| no reranked chunks | GenerateAnswerNode | abstention answer, empty citations, `status=success` |
| missing `generated_answer` | OutputFormatNode | `status=error`, "generated_answer" |
| a run stopped on a correctable value | PostProcessNode | the reason's sentence becomes the whole body; `status=success`, nothing structured published |
| empty `compliance_answer` | PostProcessNode | forwarded as-is, `status=success` (the error path bypasses the node) |
| credential / CVE content in output | PostProcessNode | redacted, `status=error` |
| forged document structure / unbacked reference line | PostProcessNode | redacted, `status=error` |

## 6. Test Execution Summary

- Execution: `python -m pytest tests/`.
- Total: 185 tests — **184 passed, 1 skipped** (PB-7 skip stub, by design).
- Coverage: node + graph modules exercised on success and error paths, the caller-data
  contract proven at node level AND through the real `/invoke` entry, the declared
  configuration proven live end-to-end, and the retrieval grounding and abstention
  boundaries asserted directly.
