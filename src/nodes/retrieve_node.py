"""AgentCore Platform v1.0"""

# SVC-C2-013 — RetrieveNode
# Inner domain node 2 (RAG retrieval).
#
# Retrieves candidate KB chunks for the normalised compliance query from the
# ISMS corpus (ISO 27001/27002 + Japan cybersecurity regulation + METI
# guidelines).  The shipped implementation is a small deterministic in-module
# corpus with keyword / standard-reference scoring.  A production deployment
# wires a real vector store here; the declared top_k and the output contract
# stay identical.
#
# The caller's validated focus terms (structured channel) take part in scoring:
# a chunk matching a focus term is boosted, which is how a Title Case control
# name — a shape the platform's input gate masks on the query field — still
# reaches retrieval.
#
# Inner node — ANONYMOUS trust: the outer PreProcessNode (VERIFIED_EXTERNAL)
# already enforced caller trust; a stricter inner level would deny the
# passthrough invocation at the subgraph boundary.
# Returns ONLY the state keys this node writes (partial-dict contract).

import logging
import re
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import from_json, to_json

logger = logging.getLogger(__name__)

_DEFAULT_TOP_K = 8
_TOKEN_RE = re.compile(r"[a-z0-9]+|[぀-ヿ一-鿿]+")

# Deterministic v1 ISMS knowledge base. Each entry carries indexed keywords for
# the stub scorer. Production replaces this with a real vector index; the chunk
# shape ({chunk_id, source, standard_ref, text}) is the retrieval contract.
_ISMS_KB: List[Dict[str, Any]] = [
    {
        "chunk_id": "iso27001-a8-2",
        "source": "ISO/IEC 27001:2022",
        "standard_ref": "Annex A A.8.2 (Information classification)",
        "text": (
            "Information shall be classified according to the information security "
            "needs of the organization based on confidentiality, integrity, "
            "availability and relevant interested-party requirements. Classification "
            "levels and handling rules must be defined, documented and reviewed."
        ),
        "keywords": [
            "iso",
            "27001",
            "a.8.2",
            "annex",
            "information",
            "classification",
            "confidentiality",
            "integrity",
            "availability",
            "分類",
            "情報",
        ],
    },
    {
        "chunk_id": "iso27001-a5-1",
        "source": "ISO/IEC 27001:2022",
        "standard_ref": "Annex A A.5.1 (Policies for information security)",
        "text": (
            "Information security policy and topic-specific policies shall be defined, "
            "approved by management, published, communicated to and acknowledged by "
            "relevant personnel, and reviewed at planned intervals."
        ),
        "keywords": [
            "iso",
            "27001",
            "a.5.1",
            "policy",
            "policies",
            "management",
            "review",
            "方針",
            "ポリシー",
            "統制",
            "control",
        ],
    },
    {
        "chunk_id": "iso27002-controls",
        "source": "ISO/IEC 27002:2022",
        "standard_ref": "ISO/IEC 27002 control guidance",
        "text": (
            "ISO/IEC 27002 provides implementation guidance and reference controls "
            "supporting ISO 27001 Annex A, organised into organizational, people, "
            "physical and technological control themes."
        ),
        "keywords": [
            "iso",
            "27002",
            "control",
            "controls",
            "guidance",
            "implementation",
            "annex",
            "requirement",
            "管理策",
            "要求",
        ],
    },
    {
        "chunk_id": "fusei-access-breach",
        "source": "不正アクセス禁止法 (2024改正)",
        "standard_ref": "不正アクセス禁止法 — breach reporting obligations",
        "text": (
            "The 2024 revision of the 不正アクセス禁止法 introduces incident reporting "
            "obligations for unauthorized-access events. Affected organizations must "
            "notify the relevant authority and preserve access logs as evidence."
        ),
        "keywords": [
            "不正アクセス禁止法",
            "breach",
            "notification",
            "報告",
            "通知",
            "incident",
            "インシデント",
            "access",
            "log",
            "ログ",
            "2024",
        ],
    },
    {
        "chunk_id": "meti-cyber-mgmt",
        "source": "METI サイバーセキュリティ経営ガイドライン",
        "standard_ref": "METI サイバーセキュリティ経営ガイドライン Ver. current",
        "text": (
            "The METI Cybersecurity Management Guidelines set out ten important items "
            "management must direct, including recognizing cybersecurity as a "
            "management responsibility, building a security governance framework, and "
            "securing resources and budget for security measures."
        ),
        "keywords": [
            "meti",
            "経済産業省",
            "サイバーセキュリティ経営ガイドライン",
            "management",
            "経営",
            "governance",
            "guideline",
            "ガイドライン",
            "budget",
        ],
    },
    {
        "chunk_id": "appi-personal-data",
        "source": "個人情報保護法 (APPI)",
        "standard_ref": "個人情報保護法 — data breach notification",
        "text": (
            "Under the APPI, a data breach that is likely to harm the rights and "
            "interests of individuals must be reported to the Personal Information "
            "Protection Commission and, in principle, notified to the affected data "
            "subjects without delay."
        ),
        "keywords": [
            "個人情報保護法",
            "appi",
            "personal",
            "data",
            "breach",
            "notification",
            "個人情報",
            "報告",
            "通知",
            "commission",
        ],
    },
    {
        "chunk_id": "iso27001-a5-24-incident",
        "source": "ISO/IEC 27001:2022",
        "standard_ref": "Annex A A.5.24 (Incident management planning)",
        "text": (
            "The organization shall plan and prepare for managing information security "
            "incidents by defining roles, responsibilities and processes for incident "
            "response, reporting, assessment and learning."
        ),
        "keywords": [
            "iso",
            "27001",
            "a.5.24",
            "incident",
            "response",
            "management",
            "reporting",
            "インシデント",
            "対応",
            "annex",
        ],
    },
    {
        "chunk_id": "iso27001-a8-24-crypto",
        "source": "ISO/IEC 27001:2022",
        "standard_ref": "Annex A A.8.24 (Use of cryptography)",
        "text": (
            "Rules for the effective use of cryptography, including cryptographic key "
            "management, shall be defined and implemented to protect the "
            "confidentiality, integrity and authenticity of information."
        ),
        "keywords": [
            "iso",
            "27001",
            "a.8.24",
            "cryptography",
            "encryption",
            "key",
            "暗号",
            "鍵",
            "confidentiality",
            "annex",
        ],
    },
]


def _tokenize(text: str) -> List[str]:
    """Split into lowercase word / CJK tokens for the deterministic scorer."""
    return _TOKEN_RE.findall(text.lower())


def _score_chunk(
    query_tokens: List[str], detected_standards: List[str], focus_term_tokens: List[List[str]], entry: Dict[str, Any]
) -> float:
    """Score a KB entry against the query and focus terms. Normalised to [0.0, 1.0]."""
    kw = set(entry.get("keywords", []))
    overlap = 0.0
    if query_tokens:
        matched = sum(1 for t in query_tokens if t in kw)
        overlap = matched / len(query_tokens)
    # Boost for an explicit standard-reference match against this chunk.
    ref = str(entry.get("standard_ref", "")).lower()
    src = str(entry.get("source", "")).lower()
    ref_boost = 0.0
    for std in detected_standards:
        s = std.lower()
        if s and (s in ref or s in src or ref in s):
            ref_boost = 0.4
            break
    # Boost when a caller focus term matches this chunk. The boost alone clears
    # the shipped relevance floor, so a run whose only domain signal is a focus
    # term (the query's Title Case phrase arrived masked) still retrieves.
    focus_boost = 0.0
    if focus_term_tokens:
        text_tokens = set(_tokenize(str(entry.get("text", "")))) | kw
        for tokens in focus_term_tokens:
            if tokens and all(t in text_tokens for t in tokens):
                focus_boost = 0.5
                break
    return max(0.0, min(1.0, overlap + ref_boost + focus_boost))


class RetrieveNode(FunctionNode):
    """Retrieve candidate ISMS KB chunks for the compliance query.

    v1: deterministic in-module corpus with keyword / standard-ref scoring.
    Production: the manifest-declared retriever settings (config/agent.yaml)
    drive a real vector store.

    Inner node — ANONYMOUS trust (see module docstring).

    Input state keys:
        normalized_query: str   — JSON {query, detected_standards, query_type}
        input_context:    dict  — bridged caller request; focus terms join scoring
        retrieval_top_k:  int   — declared result count, seeded from config

    Output state keys (partial dict):
        retrieved_chunks: str  — JSON list of {chunk_id, source, standard_ref, text, score}
        status:           str
        error_log:        list[str]  (only on ERROR)
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> Dict[str, Any]:
        # A reason settled earlier in the run is the real one: pass it through
        # untouched instead of doing work on input that was already declined.
        marker = state.get("error_code")
        if marker:
            return {"status": AgentStatus.SUCCESS.value, "error_code": marker}
        normalized: Dict[str, Any] = from_json(state.get("normalized_query"), {})
        query = str(normalized.get("query", "")).strip()
        detected_standards = list(normalized.get("detected_standards", []))

        # Caller focus terms, validated by PreProcessNode and bridged across the
        # subgraph boundary (the framework does not forward the caller-data
        # channel into a subgraph).
        input_context = state.get("input_context") or {}
        caller_request: Dict[str, Any] = {}
        if isinstance(input_context, dict):
            caller_request = from_json(input_context.get("caller_request"), {}) or {}
        focus_terms = [str(t) for t in (caller_request.get("focus_terms") or []) if str(t).strip()]
        focus_term_tokens = [_tokenize(term) for term in focus_terms]

        if not query:
            emit_trace_event(
                "retrieve_failed",
                {"reason": "missing_normalized_query"},
                state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["RetrieveNode: normalized_query missing or empty"],
            }

        # Retrieval fan-out: score the whole corpus, keep the best candidates for
        # the reranker (cap at 2x top_k so the reranker still has headroom).
        # top_k reaches this node via State only: the inner graph seeds the
        # declared retrieval settings into state through _extra_initial_state —
        # the canonical execute(self, state) contract carries no config
        # argument. Fall back to the built-in floor when unseeded (e.g. unit
        # tests).
        top_k_val = state.get("retrieval_top_k")
        top_k = int(top_k_val) if top_k_val is not None else _DEFAULT_TOP_K
        fanout = max(top_k * 2, top_k)

        query_tokens = _tokenize(query)
        scored: List[Dict[str, Any]] = []
        for entry in _ISMS_KB:
            score = _score_chunk(query_tokens, detected_standards, focus_term_tokens, entry)
            if score <= 0.0:
                continue
            scored.append(
                {
                    "chunk_id": entry["chunk_id"],
                    "source": entry["source"],
                    "standard_ref": entry["standard_ref"],
                    "text": entry["text"],
                    "score": round(score, 4),
                }
            )

        scored.sort(key=lambda c: c["score"], reverse=True)
        candidates = scored[:fanout]

        logger.info(
            "RetrieveNode: query_tokens=%d focus_terms=%d candidates=%d top_k=%d",
            len(query_tokens),
            len(focus_terms),
            len(candidates),
            top_k,
        )
        emit_trace_event(
            "retrieve_complete",
            {
                "candidate_count": len(candidates),
                "focus_terms": len(focus_terms),
                "top_k": top_k,
                "top_score": candidates[0]["score"] if candidates else 0.0,
            },
            state,
        )

        return {
            "retrieved_chunks": to_json(candidates),
            "status": AgentStatus.SUCCESS.value,
        }
