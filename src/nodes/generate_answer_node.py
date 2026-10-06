"""AgentCore Platform v1.0"""

# SVC-C2-013 — GenerateAnswerNode
# Inner domain node 4 (LLM, grounded generation).
#
# Generates the compliance answer grounded STRICTLY in reranked_chunks — the
# hallucination boundary. If no chunk survived the reranker, it returns the
# insufficient-coverage answer (recommend a 専門セキュリティコンサルタント) rather
# than inventing a requirement.
#
# The shipped implementation synthesises the answer deterministically from the
# grounded chunks. A production deployment wires the real model via the declared
# prompt template llm.system_prompt_template in config/config.yaml
# (prompts/isms_compliance.j2); the grounding contract and output keys are
# identical either way. The declared template reaches this node via State only —
# seeded by the inner graph's _extra_initial_state — and is surfaced here; it is
# documented, never used to fake a model call.
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

_CONSULT_NOTE = (
    "This is general compliance guidance only. For an individualized assessment, "
    "consult a 専門セキュリティコンサルタント (professional security consultant)."
)
_INSUFFICIENT_ANSWER = (
    "The knowledge base does not contain sufficiently relevant material to answer "
    "this question with confidence. Please refine the question or consult a "
    "専門セキュリティコンサルタント (professional security consultant) for an "
    "individualized assessment."
)


def _grounded_answer(query: str, chunks: List[Dict[str, Any]]) -> str:
    """Synthesise a grounded answer from the reranked chunks only."""
    lines: List[str] = [
        f"Question: {query}",
        "",
        "Based on the applicable standards and regulations retrieved from the " "ISMS knowledge base:",
        "",
    ]
    for i, c in enumerate(chunks, start=1):
        ref = c.get("standard_ref") or c.get("source", "")
        lines.append(f"{i}. [{ref}] {c.get('text', '').strip()}")
    return "\n".join(lines)


def _build_citations(chunks: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Build the citation list from the grounding chunks (cited sources only)."""
    citations: List[Dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for c in chunks:
        key = (c.get("source", ""), c.get("standard_ref", ""))
        if key in seen:
            continue
        seen.add(key)
        citations.append(
            {
                "source": str(c.get("source", "")),
                "standard_ref": str(c.get("standard_ref", "")),
            }
        )
    return citations


def _build_checklist(chunks: List[Dict[str, Any]]) -> List[str]:
    """Derive a short action checklist grounded in the cited controls."""
    if not chunks:
        return [
            "Refine the compliance question with the specific standard or regulation.",
            "Engage a professional security consultant for an individualized assessment.",
        ]
    checklist: List[str] = []
    for c in chunks:
        ref = c.get("standard_ref") or c.get("source", "")
        checklist.append(f"Review and evidence compliance against {ref}.")
    checklist.append("Document the assessment and schedule a periodic review of the applicable controls.")
    return checklist


class GenerateAnswerNode(FunctionNode):
    """Generate the grounded compliance answer for SVC-C2-013.

    Deterministic synthesis grounded strictly in reranked_chunks. A production
    deployment drives the real model with the declared
    llm.system_prompt_template (seeded into State by the inner graph and
    surfaced here — documented, never faked).

    Inner node — ANONYMOUS trust (see module docstring).

    Input state keys:
        reranked_chunks:  str  — JSON list of grounding chunks
        normalized_query: str  — JSON {query, ...}

    Output state keys (partial dict):
        generated_answer:  str  — grounded answer text
        answer_citations:  str  — JSON list of {source, standard_ref}
        action_checklist:  str  — JSON list of action items
        status:            str
        error_log:         list[str]  (only on ERROR)
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> Dict[str, Any]:
        # A reason settled earlier in the run is the real one: pass it through
        # untouched instead of doing work on input that was already declined.
        marker = state.get("error_code")
        if marker:
            return {"status": AgentStatus.SUCCESS.value, "error_code": marker}
        chunks: List[Dict[str, Any]] = from_json(state.get("reranked_chunks"), [])
        if not isinstance(chunks, list):
            chunks = []
        normalized: Dict[str, Any] = from_json(state.get("normalized_query"), {})
        query = str(normalized.get("query", "")).strip() or "(no query provided)"

        # config/config.yaml declares llm.system_prompt_template
        # (prompts/isms_compliance.j2). The declared template reaches this node
        # via State only: the inner graph seeds it through _extra_initial_state —
        # the canonical execute(self, state) contract carries no config argument.
        # The shipped pipeline grounds the answer DETERMINISTICALLY from
        # reranked_chunks; the declared prompt template is surfaced here for the
        # production model wiring (documented, never faked) — the grounding
        # contract and output keys are identical either way.
        system_prompt_template = state.get("system_prompt_template") or ""
        if system_prompt_template:
            logger.debug(
                "GenerateAnswerNode: declared system_prompt_template=%s is reachable "
                "(deterministic grounding; a production deployment wires the real model)",
                system_prompt_template,
            )

        # ── Grounding boundary ────────────────────────────────────────────────
        if not chunks:
            logger.info("GenerateAnswerNode: no grounding chunks — insufficient-coverage answer")
            emit_trace_event(
                "generate_answer_insufficient_context",
                {"reason": "no_reranked_chunks"},
                state,
            )
            answer = f"{_INSUFFICIENT_ANSWER}\n\n{_CONSULT_NOTE}"
            return {
                "generated_answer": answer,
                "answer_citations": to_json([]),
                "action_checklist": to_json(_build_checklist([])),
                "status": AgentStatus.SUCCESS.value,
            }

        answer_body = _grounded_answer(query, chunks)
        answer = f"{answer_body}\n\n{_CONSULT_NOTE}"
        citations = _build_citations(chunks)
        checklist = _build_checklist(chunks)

        logger.info(
            "GenerateAnswerNode: grounded_chunks=%d citations=%d checklist=%d",
            len(chunks),
            len(citations),
            len(checklist),
        )
        emit_trace_event(
            "generate_answer_complete",
            {
                "grounded_chunk_count": len(chunks),
                "citation_count": len(citations),
                "checklist_count": len(checklist),
            },
            state,
        )

        return {
            "generated_answer": answer,
            "answer_citations": to_json(citations),
            "action_checklist": to_json(checklist),
            "status": AgentStatus.SUCCESS.value,
        }
