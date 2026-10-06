"""AgentCore Platform v1.0"""

# SVC-C2-013 — InputValidateNode
# Inner domain node 1: domain-level validation of the compliance query.
#
# Distinct from PreProcessNode (trust gate + structural sanitisation):
# this node applies domain-business rules — length bounds, standard/regulation
# reference detection (ISO 27001 Annex A codes, Japan cyber laws, METI
# guidelines) and query-type classification.
#
# Inner node — ANONYMOUS trust: the outer PreProcessNode (VERIFIED_EXTERNAL)
# already enforced caller trust; inner nodes must be ANONYMOUS so the outer
# invocation context passes through the subgraph boundary without rejection.
#
# Returns ONLY the state keys this node writes (partial-dict contract).

import logging
import re
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import to_json
from src.services.failure_message import INPUT_REJECTED
from src.services.progress import emit_progress

logger = logging.getLogger(__name__)

_MIN_QUERY_CHARS = 3
_MAX_QUERY_CHARS = 2000

# ISO 27001 Annex A control codes, e.g. "A.8.2", "A.5.1.1".
_ANNEX_A_RE = re.compile(r"\bA\.\d+(?:\.\d+){0,2}\b")

# Standard / regulation keyword → canonical reference label.
_STANDARD_KEYWORDS: Dict[str, str] = {
    "iso 27001": "ISO/IEC 27001",
    "iso/iec 27001": "ISO/IEC 27001",
    "iso 27002": "ISO/IEC 27002",
    "iso/iec 27002": "ISO/IEC 27002",
    "isms": "ISMS (ISO/IEC 27001)",
    "不正アクセス禁止法": "不正アクセス禁止法",
    "個人情報保護法": "個人情報保護法 (APPI)",
    "サイバーセキュリティ基本法": "サイバーセキュリティ基本法",
    "サイバーセキュリティ経営ガイドライン": "METI サイバーセキュリティ経営ガイドライン",
    "meti": "METI guideline",
    "経済産業省": "METI (経済産業省) guideline",
    "電気通信事業法": "電気通信事業法",
}

# Coarse query-type classification keywords.
_QUERY_TYPE_KEYWORDS: Dict[str, tuple[str, ...]] = {
    "breach_notification": ("breach", "notification", "incident", "報告", "通知", "インシデント"),
    "control_requirement": ("annex", "control", "requirement", "要求", "管理策", "統制"),
    "audit": ("audit", "certification", "監査", "認証"),
}


def _detect_standards(query: str) -> List[str]:
    """Detect standard / regulation references present in the query."""
    detected: List[str] = []
    seen: set[str] = set()
    lowered = query.lower()
    for kw, label in _STANDARD_KEYWORDS.items():
        if kw in lowered and label not in seen:
            seen.add(label)
            detected.append(label)
    for code in _ANNEX_A_RE.findall(query):
        ref = f"ISO 27001 Annex A {code}"
        if ref not in seen:
            seen.add(ref)
            detected.append(ref)
    return detected


def _classify_query(query: str) -> str:
    """Classify the query into a coarse compliance query type."""
    lowered = query.lower()
    for qtype, kws in _QUERY_TYPE_KEYWORDS.items():
        if any(kw in lowered for kw in kws):
            return qtype
    return "general_compliance"


class InputValidateNode(FunctionNode):
    """Domain validation of the compliance query for SVC-C2-013.

    Applies business-rule checks beyond the structural sanitisation in
    PreProcessNode: length bounds, standard/regulation reference detection,
    and query-type classification.

    Inner node — ANONYMOUS trust (see module docstring).

    Input state keys:
        validated_input: str  — sanitised query from PreProcessNode
                                (falls back to user_input for unit-test convenience)

    Output state keys (partial dict):
        normalized_query: str  — JSON: {query, detected_standards, query_type}
        status:           str
        error_code:       str        — set when the run COMPLETES without acting,
                                       because the caller can correct the query
        error_log:        list[str]  — the internal reason, when the run stopped
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> Dict[str, Any]:
        raw = state.get("validated_input") or state.get("user_input", "")
        query = raw.strip() if isinstance(raw, str) else ""

        # ── Length bounds ─────────────────────────────────────────────────────
        if len(query) < _MIN_QUERY_CHARS:
            emit_trace_event(
                "input_validate_failed",
                {"reason": "query_too_short", "length": len(query)},
                state,
            )
            # A value the caller can correct: the run COMPLETES carrying the
            # reason, so the question can be lengthened and sent again on the
            # same conversation rather than ending it with an exception type.
            emit_progress(INPUT_REJECTED)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": "INVALID_REQUEST",
                "error_log": [f"InputValidateNode: query too short (min {_MIN_QUERY_CHARS} chars)"],
            }
        if len(query) > _MAX_QUERY_CHARS:
            query = query[:_MAX_QUERY_CHARS]

        # ── Domain enrichment ─────────────────────────────────────────────────
        detected_standards = _detect_standards(query)
        query_type = _classify_query(query)

        normalized: Dict[str, Any] = {
            "query": query,
            "detected_standards": detected_standards,
            "query_type": query_type,
        }

        logger.info(
            "InputValidateNode: chars=%d standards=%d type=%s",
            len(query),
            len(detected_standards),
            query_type,
        )
        emit_trace_event(
            "input_validate_complete",
            {
                "query_chars": len(query),
                "detected_standards": detected_standards,
                "query_type": query_type,
            },
            state,
        )

        return {
            "normalized_query": to_json(normalized),
            "status": AgentStatus.SUCCESS.value,
        }
