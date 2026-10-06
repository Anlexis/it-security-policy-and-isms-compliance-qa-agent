"""AgentCore Platform v1.0"""

# SVC-C2-013 — PostProcessNode (the output boundary)
#
# Reads the final compliance answer from state (compliance_answer, populated by
# ComplianceQAGraphNode.merge_output() from the inner OutputFormatNode) and
# surfaces it as formatted_output / result only AFTER both boundary layers pass.
#
# TWO INDEPENDENT LAYERS, each with its own audit event, neither relying on the
# other:
#
#   1. Disallowed-content scan — the module-level `_security_gate_output()`
#      below, called from execute(). It RECURSES into dict / list / tuple / set
#      containers rather than inspecting only a top-level string, so a violation
#      nested inside a structured payload is never missed even if a future
#      caller passes one. It matches credential-shaped content (API keys, JWTs,
#      bearer tokens, credential assignments) AND specific-vulnerability
#      disclosure (CVE identifiers, exploit/PoC markers) — this template gives
#      general guidance only and must not disclose specific vulnerabilities.
#
#   2. Document invariant — `_enforce_document_invariant()` below. The rendered
#      document's STRUCTURE is this template's own: the title heading, the three
#      numbered section headings and the disclaimer heading each appear exactly
#      once as whole lines, the disclaimer text is present, and every rendered
#      reference line is backed by a citation the pipeline produced. Caller text
#      reaches the document only as single-line fragments (the query is
#      whitespace-collapsed and focus terms refuse newlines), so a document that
#      no longer satisfies the invariant is not a formatting nit — it is
#      caller-controlled structure that escaped the render path, and it is
#      refused.
#
# This template renders no monetary aggregate, so the fixed rounding grid other
# agents enforce at this boundary does NOT apply here; see docs/02_design.md
# "Output boundary". A numeric snap would in fact be wrong for a compliance Q&A
# agent: passages are quoted from the standards corpus, and rewriting a figure
# inside a quoted clause would falsify the guidance the answer is grounded in.
# Because nothing here rewrites the text, both layers are pure scans and their
# order carries no risk of one destroying evidence the other needs.
#
# The domain output gate is a module-level function (_security_gate_output)
# called from inside execute() — NOT an instance method on the node class
# (an instance hook of that name would be auto-wrapped by the framework and
# fail on the real invoke path).
#
# Returns ONLY the state keys this node writes (partial-dict contract).

import logging
import re
from typing import Any, ClassVar, Dict, List, Optional, Tuple

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import from_json
from src.services.failure_message import EMPTY_INPUT, INPUT_REJECTED, INVALID_VALUE, TOO_LONG

logger = logging.getLogger(__name__)

# Patterns that MUST NOT appear in the compliance answer output.
_DISALLOWED_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("api_key_pattern", re.compile(r"(?:sk|pk|ak)-[A-Za-z0-9]{16,}", re.IGNORECASE)),
    ("jwt_pattern", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9_\-.]{8,}", re.IGNORECASE)),
    (
        "credential_assignment",
        re.compile(
            r"(?:password|passwd|secret|api_key|token|access_key|private_key)" r"\s*[:=]\s*\S{8,}",
            re.IGNORECASE,
        ),
    ),
    # General guidance only — no specific vulnerability disclosure.
    ("specific_vulnerability_disclosure", re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)),
    (
        "exploit_disclosure",
        re.compile(
            r"(?:exploit|proof[\s_-]?of[\s_-]?concept|\bPoC\b)\s+(?:code|payload|script)",
            re.IGNORECASE,
        ),
    ),
]

# The document chrome this template renders (see OutputFormatNode). The
# invariant is stated in terms of these literals so a drift in the renderer is
# caught here rather than shipped.
_TITLE_LINE = "IT SECURITY POLICY & ISMS COMPLIANCE — GUIDANCE"
_SECTION_LINES = ("1. Compliance Guidance", "2. References", "3. Action Checklist", "DISCLAIMER")
_DISCLAIMER_MARKER = "not a substitute for a formal audit"
_NO_REFERENCE_LINE = "  (No specific standard/regulation reference matched.)"
_REFERENCE_LINE_RE = re.compile(r"^  \[(\d+)\] ", re.MULTILINE)


def _count_lines(document: str, line: str) -> int:
    """Count occurrences of an exact LINE (structure is a property of lines —
    a caller may legitimately mention a heading inline)."""
    return sum(1 for candidate in document.splitlines() if candidate == line)


def _enforce_document_invariant(document: str, citations: Optional[List[Dict[str, Any]]] = None) -> Optional[str]:
    """Check the rendered document against this template's stated output contract.

    Returns the name of the first violated clause, or None when the document is
    the shape this template publishes. Purely a scan — nothing is rewritten, so
    the check is order-independent with respect to the disallowed-content layer.

    Clauses:
      title_heading      exactly one line that is this template's title
      section_heading    each numbered section heading and the disclaimer
                         heading exactly once, as whole lines
      disclaimer         the standing disclaimer text is present
      reference_line     every "  [n] " line carries an index a real citation
                         backs (checked only when the citation list is supplied)
    """
    if _count_lines(document, _TITLE_LINE) != 1:
        return "title_heading"
    for section in _SECTION_LINES:
        if _count_lines(document, section) != 1:
            return "section_heading"
    if _DISCLAIMER_MARKER not in document:
        return "disclaimer"
    if citations is not None:
        rendered = {int(n) for n in _REFERENCE_LINE_RE.findall(document)}
        backed = set(range(1, len(citations) + 1))
        if rendered - backed:
            return "reference_line"
        if not citations and _NO_REFERENCE_LINE not in document.splitlines():
            return "reference_line"
    return None


def _security_gate_output(content: Any) -> Optional[str]:
    """Run the disallowed-content scan over the outbound content.

    Recurses into dict / list / tuple / set containers so a violation nested
    inside a structured payload is not missed. This template's own output is a
    flat string today, but a scan that inspects only top-level strings is blind
    to a value carried one level down, so the scan does not assume the shape.

    Returns the first violation name, or None if the output is clean.
    Module-level function (not a node instance method) — an instance hook of
    this name would be auto-wrapped by the framework on the real invoke path.
    """
    if content is None:
        return None
    if isinstance(content, str):
        for name, pattern in _DISALLOWED_PATTERNS:
            if pattern.search(content):
                return name
        return None
    if isinstance(content, dict):
        for value in content.values():
            violation = _security_gate_output(value)
            if violation:
                return violation
        return None
    if isinstance(content, (list, tuple, set)):
        for item in content:
            violation = _security_gate_output(item)
            if violation:
                return violation
        return None
    # Any other scalar (int, float, bool) carries no credential-shaped content.
    return None


# Reason code -> the sentence the caller reads. A code with no entry falls
# back to the generic one rather than leaking the code itself.
_DEGRADED_MESSAGES = {
    "EMPTY_INPUT": EMPTY_INPUT,
    "QUESTION_TOO_LONG": TOO_LONG,
    "INVALID_REQUEST": INVALID_VALUE,
}


class PostProcessNode(FunctionNode):
    """The output boundary: disallowed-content scan + document invariant, fail closed.

    Outer backbone post_process slot.  Declared ANONYMOUS — trust was
    already enforced at PreProcessNode (VERIFIED_EXTERNAL).

    Input state keys:
        compliance_answer: str  — formatted answer from inner OutputFormatNode
                                  (falls back to result if absent)
        answer_citations:  str  — JSON citation list; every rendered reference
                                  line must be backed by one

    Output state keys (partial dict):
        formatted_output: str
        result:           str
        status:           str
        error_log:        list[str]  (only on error)
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> Dict[str, Any]:
        # A run declined upstream has nothing to format. Render the reason as
        # the caller-facing body and carry the marker onward. Nothing the
        # pipeline would have produced exists, so nothing is gated here — and
        # nothing structured is published either.
        marker = state.get("error_code")
        if marker:
            message = _DEGRADED_MESSAGES.get(marker, INPUT_REJECTED)
            emit_trace_event("post_process_degraded", {"reason": marker}, state)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": marker,
                "formatted_output": message,
                "result": message,
            }
        compliance_answer: str = state.get("compliance_answer") or state.get("result") or ""

        if not compliance_answer.strip():
            # No answer was generated — forward as-is (non-fatal; the error
            # path bypasses this node entirely, so an empty answer here means
            # the pipeline legitimately produced nothing to gate).
            logger.warning("PostProcessNode: compliance_answer is empty — nothing to gate")
            return {
                "formatted_output": compliance_answer,
                "status": AgentStatus.SUCCESS.value,
            }

        # ── Layer 1: disallowed-content scan ──────────────────────────────────
        violation = _security_gate_output(compliance_answer)
        if violation:
            logger.error("PostProcessNode: output blocked — disallowed pattern %s", violation)
            emit_trace_event(
                "post_process_s3_violation",
                {"violation": violation},
                state,
            )
            sanitised = (
                f"[COMPLIANCE ANSWER REDACTED: output contained a disallowed pattern "
                f"({violation}). Contact the security compliance team for a reviewed answer.]"
            )
            return {
                "formatted_output": sanitised,
                "result": sanitised,
                "status": AgentStatus.ERROR.value,
                "error_log": [f"PostProcessNode: disallowed pattern detected — {violation}"],
            }

        # ── Layer 2: document-structure invariant ─────────────────────────────
        clause = _enforce_document_invariant(compliance_answer, from_json(state.get("answer_citations"), []) or [])
        if clause:
            logger.error("PostProcessNode: output blocked — document invariant clause %s", clause)
            emit_trace_event(
                "post_process_document_invariant_violation",
                {"clause": clause},
                state,
            )
            sanitised = (
                "[COMPLIANCE ANSWER REDACTED: the rendered document did not satisfy "
                "the published output contract. Contact the security compliance team "
                "for a reviewed answer.]"
            )
            return {
                "formatted_output": sanitised,
                "result": sanitised,
                "status": AgentStatus.ERROR.value,
                "error_log": [f"PostProcessNode: document invariant not satisfied — {clause}"],
            }

        logger.info(
            "PostProcessNode: output gate passed — length=%d",
            len(compliance_answer),
        )
        emit_trace_event(
            "post_process_complete",
            {"output_length": len(compliance_answer)},
            state,
        )

        return {
            "formatted_output": compliance_answer,
            "result": compliance_answer,
            "status": AgentStatus.SUCCESS.value,
        }
