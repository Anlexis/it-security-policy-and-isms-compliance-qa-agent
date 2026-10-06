"""AgentCore Platform v1.0"""

# SVC-C2-013 — OutputFormatNode (inner domain node 5, last in DomainWorkflowGraph)
# Assembles the final compliance answer document from generated_answer,
# answer_citations and action_checklist, appending the mandatory disclaimer.
# When the caller supplied compliance focus terms, the document states which
# focus was applied. This is the last inner node — it produces the
# compliance_answer string that the outer PostProcessNode gates.
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

from src.schemas.state import from_json

logger = logging.getLogger(__name__)

_SEPARATOR = "=" * 72
_SUBSEP = "-" * 72
_DISCLAIMER = (
    "This response provides general information-security compliance guidance only. "
    "It is not a substitute for a formal audit or individualized professional advice. "
    "No specific vulnerability or exploit detail is disclosed. For an individualized "
    "assessment, consult a 専門セキュリティコンサルタント (professional security consultant)."
)


def _assemble_answer(
    answer: str,
    citations: List[Dict[str, str]],
    checklist: List[str],
    focus_terms: List[str],
) -> str:
    """Assemble the full compliance answer document."""
    lines = [
        _SEPARATOR,
        "IT SECURITY POLICY & ISMS COMPLIANCE — GUIDANCE",
        _SEPARATOR,
    ]
    if focus_terms:
        # Focus terms were validated against the term alphabet (single-line,
        # no markup) by PreProcessNode, so joining them stays one line.
        lines.append(f"Compliance focus applied: {', '.join(focus_terms)}")
    lines += [
        "",
        "1. Compliance Guidance",
        _SUBSEP,
        answer.strip(),
        "",
        "2. References",
        _SUBSEP,
    ]
    if citations:
        for i, c in enumerate(citations, start=1):
            ref = c.get("standard_ref", "")
            src = c.get("source", "")
            label = f"{src} — {ref}" if ref else src
            lines.append(f"  [{i}] {label}")
    else:
        lines.append("  (No specific standard/regulation reference matched.)")
    lines += ["", "3. Action Checklist", _SUBSEP]
    if checklist:
        for i, item in enumerate(checklist, start=1):
            lines.append(f"  {i}. {item}")
    else:
        lines.append("  (No action items generated.)")
    lines += ["", _SEPARATOR, "DISCLAIMER", _SUBSEP, _DISCLAIMER, _SEPARATOR]
    return "\n".join(lines)


class OutputFormatNode(FunctionNode):
    """Assemble the final compliance answer document (inner domain node).

    Reads generated_answer, answer_citations and action_checklist from State,
    renders the full compliance guidance document with the disclaimer, and
    writes it to compliance_answer (and result) for the outer PostProcessNode.

    Inner node — ANONYMOUS trust (see module docstring).

    Input state keys:
        generated_answer: str   — grounded answer text
        answer_citations: str   — JSON list of citations
        action_checklist: str   — JSON list of action items
        input_context:    dict  — bridged caller request (focus terms rendered)

    Output state keys (partial dict):
        compliance_answer: str
        result:            str  (same as compliance_answer — backbone convention)
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
        answer = state.get("generated_answer") or ""
        citations: List[Dict[str, str]] = from_json(state.get("answer_citations"), [])
        checklist: List[str] = from_json(state.get("action_checklist"), [])

        if not str(answer).strip():
            logger.error("OutputFormatNode: generated_answer missing in state")
            emit_trace_event(
                "output_format_failed",
                {"reason": "missing_generated_answer"},
                state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["OutputFormatNode: generated_answer missing in state"],
            }

        if not isinstance(citations, list):
            citations = []
        if not isinstance(checklist, list):
            checklist = []

        input_context = state.get("input_context") or {}
        caller_request: Dict[str, Any] = {}
        if isinstance(input_context, dict):
            caller_request = from_json(input_context.get("caller_request"), {}) or {}
        focus_terms = [str(t) for t in (caller_request.get("focus_terms") or []) if str(t).strip()]

        document = _assemble_answer(str(answer), citations, checklist, focus_terms)

        logger.info(
            "OutputFormatNode: doc_chars=%d citations=%d checklist=%d",
            len(document),
            len(citations),
            len(checklist),
        )
        emit_trace_event(
            "output_format_complete",
            {
                "document_length": len(document),
                "citation_count": len(citations),
                "checklist_count": len(checklist),
            },
            state,
        )

        return {
            "compliance_answer": document,
            "result": document,
            "status": AgentStatus.SUCCESS.value,
        }
