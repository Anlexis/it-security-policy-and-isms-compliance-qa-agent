"""AgentCore Platform v1.0"""

# SVC-C2-013 — RerankFilterNode
# Inner domain node 3 (RAG rerank / filter).
#
# Reranks and filters the RetrieveNode candidates: drop chunks below the
# effective score threshold, sort by score descending, and cap at the effective
# top_k. This is the precision gate for a regulatory-grade compliance corpus —
# only high-confidence chunks reach the grounded generation step.
#
# The caller may TIGHTEN both knobs through the structured channel (top_k,
# min_score) but can never widen the declared values: the effective result
# count is min(declared, caller) and the effective floor is max(declared,
# caller). Both caller values were validated finite and in range by
# PreProcessNode before they reach this node.
#
# Inner node — ANONYMOUS trust: the outer PreProcessNode (VERIFIED_EXTERNAL)
# already enforced caller trust.
# Returns ONLY the state keys this node writes (partial-dict contract).

import logging
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import from_json, to_json

logger = logging.getLogger(__name__)

_DEFAULT_TOP_K = 8
_DEFAULT_SCORE_THRESHOLD = 0.4


class RerankFilterNode(FunctionNode):
    """Rerank + filter retrieved chunks for SVC-C2-013.

    Applies the relevance-floor precision gate, re-sorts by score, and caps
    the survivors at the effective top_k.  The declared knobs come from
    config/config.yaml, seeded into State by the inner graph
    (_extra_initial_state); the caller may tighten them through the validated
    structured request. Built-in floors apply when unseeded (e.g. unit tests).

    Inner node — ANONYMOUS trust (see module docstring).

    Input state keys:
        retrieved_chunks:          str   — JSON list of scored candidate chunks
        input_context:             dict  — bridged caller request (tighten-only)
        retrieval_top_k:           int   — declared result count
        retrieval_score_threshold: float — declared relevance floor

    Output state keys (partial dict):
        reranked_chunks: str  — JSON list of filtered + reranked chunks
        status:          str
        error_log:       list[str]  (only on ERROR)
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> Dict[str, Any]:
        # A reason settled earlier in the run is the real one: pass it through
        # untouched instead of doing work on input that was already declined.
        marker = state.get("error_code")
        if marker:
            return {"status": AgentStatus.SUCCESS.value, "error_code": marker}
        candidates: List[Dict[str, Any]] = from_json(state.get("retrieved_chunks"), [])
        if not isinstance(candidates, list):
            candidates = []

        # Declared knobs reach this node via State only: the inner graph seeds
        # them through _extra_initial_state — the canonical execute(self, state)
        # contract carries no config argument. Fall back state → built-in floor.
        top_k_val = state.get("retrieval_top_k")
        top_k = int(top_k_val) if top_k_val is not None else _DEFAULT_TOP_K
        threshold_val = state.get("retrieval_score_threshold")
        threshold = float(threshold_val) if threshold_val is not None else _DEFAULT_SCORE_THRESHOLD

        # Caller tightening (validated by PreProcessNode, bridged across the
        # subgraph boundary): the caller can narrow the result count and raise
        # the relevance floor, never the reverse.
        input_context = state.get("input_context") or {}
        caller_request: Dict[str, Any] = {}
        if isinstance(input_context, dict):
            caller_request = from_json(input_context.get("caller_request"), {}) or {}
        caller_top_k = caller_request.get("top_k")
        if isinstance(caller_top_k, int) and not isinstance(caller_top_k, bool):
            top_k = min(top_k, caller_top_k)
        caller_min_score = caller_request.get("min_score")
        if isinstance(caller_min_score, (int, float)) and not isinstance(caller_min_score, bool):
            threshold = max(threshold, float(caller_min_score))

        # Filter by threshold, then rerank (score desc), then cap at top_k.
        filtered = [c for c in candidates if float(c.get("score", 0.0)) >= threshold]
        filtered.sort(key=lambda c: float(c.get("score", 0.0)), reverse=True)
        reranked = filtered[:top_k]

        logger.info(
            "RerankFilterNode: candidates=%d kept=%d threshold=%.2f top_k=%d",
            len(candidates),
            len(reranked),
            threshold,
            top_k,
        )
        emit_trace_event(
            "rerank_filter_complete",
            {
                "candidate_count": len(candidates),
                "kept_count": len(reranked),
                "score_threshold": threshold,
                "top_k": top_k,
            },
            state,
        )

        return {
            "reranked_chunks": to_json(reranked),
            "status": AgentStatus.SUCCESS.value,
        }
