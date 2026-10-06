"""AgentCore Platform v1.0"""

# State must be a flat TypedDict — never a Pydantic BaseModel.
# LangGraph checkpoints use msgpack serialization; Pydantic objects
# cause silent corruption.  Extend AgentState with agent-specific
# fields only.  Do NOT add credentials, secrets, or Pydantic models.
#
# SVC-C2-013 — IT Security Policy & ISMS Compliance Q&A Agent
# Two-layer nested Cat 2 RAG graph: outer backbone (AgentBaseGraph) + inner
# domain workflow (BaseGraph).  Fields below cover both layers.
#
# Serialization contract: all dict/list-valued fields are stored as JSON-
# serialized Optional[str].  Use to_json() / from_json() helpers below
# at every producer and consumer node — one contract end-to-end.
# Never type a dict/list field as a bare dict/list; that causes msgpack
# serialization failures.

import json
from typing import Any, NotRequired, Optional

from framework.schemas.agent_state import AgentState


def to_json(value: Any) -> Optional[str]:
    """Serialize a value to a JSON string for State storage."""
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False)


def from_json(value: Optional[str], default: Any = None) -> Any:
    """Deserialize a JSON string from State storage."""
    if value is None:
        return default
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


class State(AgentState):
    """Flat TypedDict for SVC-C2-013 (RAG compliance Q&A).

    All shared fields (user_input, status, session_id, node_history,
    error_log, hitl_*, etc.) are inherited from AgentState.

    dict/list fields use JSON-serialized Optional[str].
    formatted_output is NOT re-declared here — it is inherited from AgentState.
    """

    # ------------------------------------------------------------------
    # Outer layer — set by PreProcessNode (pre_process backbone trust gate)
    # ------------------------------------------------------------------

    # Sanitised + normalised compliance query string.
    # Produced by PreProcessNode; consumed by inner InputValidateNode.
    validated_input: NotRequired[Optional[str]]

    # JSON-serialised validated structured caller request (stored as str).
    # Shape: {"channel"?, "top_k"?, "min_score"?, "focus_terms"?} — every field
    # validated by PreProcessNode before it is written here. Bridged across the
    # subgraph boundary by ComplianceQAGraphNode.extract_input().
    caller_request: NotRequired[Optional[str]]

    # JSON-serialised channel/request metadata dict (stored as str).
    # Shape: {"source": str, "channel": str}
    enriched_context: NotRequired[Optional[str]]

    # ------------------------------------------------------------------
    # Runtime config — seeded by DomainWorkflowGraph._extra_initial_state()
    # from config/config.yaml (validated by the outer graph) so the inner RAG
    # nodes observe the declared knobs. State is the only config route: nodes
    # implement the canonical execute(self, state) contract with no config
    # argument. Built-in node floors apply when these are absent.
    # ------------------------------------------------------------------

    # Retrieval knobs forwarded from retrieval.* (fallbacks for RetrieveNode /
    # RerankFilterNode). NOT credentials — plain numeric tuning knobs.
    retrieval_top_k: NotRequired[Optional[int]]
    retrieval_score_threshold: NotRequired[Optional[float]]

    # Prompt-template path forwarded from llm.*. Surfaced to GenerateAnswerNode
    # for the production model wiring (deterministic grounding; never faked).
    system_prompt_template: NotRequired[Optional[str]]

    # ------------------------------------------------------------------
    # Inner layer — domain nodes (DomainWorkflowGraph)
    # ------------------------------------------------------------------

    # JSON-serialised normalised query (stored as str).
    # Shape: {query (str), detected_standards (list[str]), query_type (str)}
    normalized_query: NotRequired[Optional[str]]

    # JSON-serialised list of candidate KB chunks from RetrieveNode.
    # Each item: {chunk_id, source, standard_ref, text, score}
    retrieved_chunks: NotRequired[Optional[str]]

    # JSON-serialised list of reranked + filtered KB chunks (score >= threshold).
    reranked_chunks: NotRequired[Optional[str]]

    # Grounded compliance answer text produced by GenerateAnswerNode
    # (grounded strictly in reranked_chunks — no hallucination).
    generated_answer: NotRequired[Optional[str]]

    # JSON-serialised list of standard/regulation citations for the answer.
    # Each item: {source, standard_ref}
    answer_citations: NotRequired[Optional[str]]

    # JSON-serialised list of action-checklist items derived from the answer.
    action_checklist: NotRequired[Optional[str]]

    # Final assembled compliance answer document (plain text, with disclaimer).
    # Assembled by inner OutputFormatNode from generated_answer + citations.
    compliance_answer: NotRequired[Optional[str]]

    # ------------------------------------------------------------------
    # Outer layer — set by PostProcessNode (post_process output boundary)
    # ------------------------------------------------------------------

    # Primary result surfaced to the caller.
    # Set to the same content as compliance_answer after the output gate passes.
    # formatted_output (from AgentState) is also set by PostProcessNode.
    result: NotRequired[Optional[str]]

    # ------------------------------------------------------------------
    # Tracing / audit — framework-managed; do NOT write from node code
    # ------------------------------------------------------------------

    trace_id: NotRequired[Optional[str]]
    correlation_id: NotRequired[Optional[str]]
    error_code: Optional[str]
    # node_history inherited from AgentState
