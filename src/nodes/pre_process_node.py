"""AgentCore Platform v1.0"""

# SVC-C2-013 — PreProcessNode (outer pre_process slot; the external-facing gate)
#
# Responsibilities:
#   - Enforce VERIFIED_EXTERNAL trust (required_trust_level — the trust gate)
#   - Reject empty / non-string / over-long input early, fail fast
#   - Refuse instruction-override payloads in the query text — both the phrased
#     form ("ignore all previous instructions") and the chat-template control-token
#     form ("<|im_start|>", "[INST]", "<<SYS>>") — checking the text BOTH as
#     received and again after sanitisation, because a sanitiser that strips
#     characters can assemble a token that was not present in the raw text
#   - Validate every caller-supplied field against explicit bounds and fail CLOSED
#     on any violation, naming the FIELD and never echoing the VALUE
#   - Publish the validated query and the validated compliance request for the
#     pipeline
#
# Caller data arrives on two channels and both are validated here:
#
#   input          the compliance question — a plain natural-language string
#   input_context  the structured channel. Fields:
#                    channel      inert slug, [a-z0-9_]{1,32}
#                    top_k        finite whole number, 1..20 — TIGHTENS the
#                                 result count (never widens the declared value)
#                    min_score    finite number, 0..1 — TIGHTENS the relevance
#                                 floor (never lowers the declared value)
#                    focus_terms  list of compliance focus terms (control names,
#                                 policy areas), entry-capped; each boosts
#                                 matching corpus chunks and is rendered into
#                                 the answer
#                  Any OTHER field is refused — the contract is closed.
#
# The structured channel carries the focus terms because the query field is one
# the framework's input gate rewrites: its personal-name heuristic matches any
# two consecutive capitalised words, which is exactly the shape of an ISMS
# control or policy name ("Information Classification", "Incident Management",
# "Change Management"), so a term carried in the query would arrive as a mask
# token and retrieval would key off the mask. Moving the terms off that field is
# only half the fix — the fields that travel on the structured channel are
# screened HERE instead, and a contact identifier in one of them is refused
# rather than masked.
#
# When no structured request is submitted the run degrades to the plain query
# and the declared defaults. There is no path on which unvalidated caller data
# reaches the pipeline.
#
# A stopped request stops the same way either way — no retrieval, no answer, the
# audit event unchanged — and the two paths differ only in how the stop is
# REPORTED:
#
#   completes with a reason code   a value the caller can correct (no question,
#                                  an over-long question, a field outside its
#                                  bound). The run ends carrying the code, the
#                                  output boundary renders the matching
#                                  sentence, and the caller can fix the value
#                                  and send the request again on the same
#                                  conversation.
#   terminates                     content this agent refuses: instruction
#                                  override on either channel, and a contact
#                                  identifier in a focus term. A refusal
#                                  reported as a correctable value would read as
#                                  an invitation to reword until it is accepted.
#
# The two are separated STRUCTURALLY — the validator returns the reason code
# beside its message — so a refusal can never be reclassified by a change to
# the wording of a message.
#
# Returns ONLY the state keys this node writes (partial-dict contract).

import logging
import math
import re
from typing import Any, ClassVar, Dict, List, Optional, Tuple

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import TrustLevel
from framework.security.pii_detector import detect_pii
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import to_json
from src.services.failure_message import EMPTY_INPUT, INPUT_REJECTED, TOO_LONG
from src.services.progress import emit_progress

logger = logging.getLogger(__name__)

# How a stopped run is reported back. Both stops do the same thing to the
# request — no processing, no answer, the audit event unchanged — and they
# differ only in what the caller is told.
#
# _REFUSED terminates the run: the content is not a value to correct, and
# reporting it as one would read as an invitation to reword the request until
# it gets through.
#
# Any other value is a reason code the run COMPLETES with, so the caller reads
# what to fix and can send a corrected request on the same conversation.
#
# The two are told apart STRUCTURALLY — the code travels beside the message as
# its own return value, never inferred by matching on the message text.
_REFUSED = ""
_CORRECTABLE = "INVALID_REQUEST"

# Maximum accepted query length (chars) after normalisation. An ISMS Q&A query
# is a natural-language question, not a document upload; an over-long query is
# refused rather than silently truncated to a different question.
_MAX_QUERY_CHARS = 2000

# Structured-channel bounds.
_MAX_FOCUS_TERMS = 10
_MAX_FOCUS_TERM_CHARS = 60
_TOP_K_MIN, _TOP_K_MAX = 1, 20
_MIN_SCORE_MIN, _MIN_SCORE_MAX = 0.0, 1.0

# The closed field set of the structured channel. Anything else is refused, so a
# hostile field NAME can never ride into the pipeline.
_ALLOWED_CONTEXT_FIELDS = frozenset({"channel", "top_k", "min_score", "focus_terms"})

# Fields the hosting runtime puts on the structured channel itself. They are not
# part of the caller contract and this agent reads none of them, but judging them
# as undeclared CALLER fields refuses every invocation served that way — and the
# caller cannot correct it, having never added the field. They are dropped before
# the channel is read, so the request is judged on what the caller actually sent.
#
# Sound precisely because no constraint is attached to them: nothing is promised
# about a field that is never read, so there is nothing for the caller to be
# misled about — which is the whole reason an undeclared CALLER field is refused
# instead of ignored. For the same reason they are left out of the screen below:
# a value that is never read reaches neither the rendered answer nor a log, so
# screening it would only refuse ordinary requests without closing any path.
_RUNTIME_CONTEXT_FIELDS = frozenset({"conversation_history"})

# Caller strings that select behaviour are inert identifiers — lowercase
# alphanumerics and underscore, bounded length. Free text in such a field is
# caller-controlled output and log injection.
_SLUG_RE = re.compile(r"^[a-z0-9_]{1,32}$")

# Focus terms are the only caller free text that reaches the rendered answer, so
# they are locked to a term alphabet: word characters in any script — a Japanese
# regulation name is accepted as readily as an English control name — plus
# space, ampersand and the punctuation control names use ("Access Control",
# "Annex A.8.2", "Incident Response (Reporting)"). Everything else — quotes,
# brackets, hashes, asterisks, backticks, angle brackets, pipes, backslashes,
# colons, control characters and every newline — is refused, so a term can
# neither carry markup nor break the line structure of the document it is
# rendered into.
_FOCUS_TERM_RE = re.compile(r"^[\w &.,()/+-]+$")

_SPACES_RE = re.compile(r" +")
_WHITESPACE_RE = re.compile(r"\s+")

# Control characters (tab and newline excepted — those collapse to a space) are
# stripped from the query before it is measured and normalised.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Instruction-override phrasings: text addressed to the MODEL rather than a
# compliance question addressed to this agent. The platform input gate refuses
# high-confidence payloads too, but this template must not depend on that —
# where that gate is absent or configured off, an unchecked payload would reach
# the retrieval path and an answer would be returned. Refusal is stated in terms
# of BEHAVIOUR (error status, no answer carried forward), never a gate's wording.
#
# Deliberately narrow: each alternative requires the imperative override shape,
# so a genuine compliance question that happens to use these words is unaffected
# ("How do we override the standard incident escalation timeline?", "What
# instructions must the ISMS policy give employees?" both pass — see the probes
# in tests/unit/test_caller_contract.py).
_INJECTION_PHRASE_RE = re.compile(
    r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+"
    r"(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions)"
    r"|disregard\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+"
    r"(?:instruction|instructions|prompt|prompts|rule|rules)"
    r"|forget\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+"
    r"(?:instruction|instructions|prompt|prompts)"
    r"|(?:reveal|show|print|repeat|output|disclose)\s+(?:me\s+)?(?:your|the)\s+"
    r"(?:system\s+prompt|system\s+message|instructions|initial\s+prompt)"
    r"|you\s+are\s+now\s+(?:a|an)\s"
    r"|act\s+as\s+(?:if\s+you\s+are\s+)?(?:a\s+|an\s+)?(?:developer|admin|root)\s+mode"
    r"|ignore\s+all\s+rules"
    r"|override\s+(?:your|the)\s+(?:instruction|instructions|rules|safety)",
    re.IGNORECASE,
)

# Chat-template control tokens: the token form of the same attack. A phrase
# screen alone misses these entirely — "<|im_start|>system ..." carries no
# imperative English at all. The classes covered: <|...|> specials (im_start,
# im_end, endoftext, ...), [INST] / [/INST], <<SYS>> / <</SYS>>, and bare
# chat-role tags (<system>, </assistant>, ...).
_INJECTION_TOKEN_RE = re.compile(
    r"<\|[^|>]{0,80}\|>" r"|\[/?INST\]" r"|<</?SYS>>" r"|<\s*/?(?:system|assistant)\s*>",
    re.IGNORECASE,
)


def _injection_hit(text: str) -> bool:
    """True when the text carries instruction-override content, phrased or tokenised."""
    return bool(_INJECTION_PHRASE_RE.search(text) or _INJECTION_TOKEN_RE.search(text))


# Contact identifiers have no place in a compliance focus term, and the term
# alphabet alone does not exclude them (it permits digits, spaces, dots and
# hyphens). Only high-precision detector types are screened:
#   - the personal-name heuristics are excluded, because they match any two
#     Title Case words, which is what a control name IS ("Information
#     Classification", "Change Management") — screening on them would refuse
#     ordinary terms, the very failure this channel exists to avoid;
#   - every remaining type is a shape no control name has, and each is a
#     personal identifier that must not enter a compliance answer, so a term
#     carrying one is refused outright rather than masked.
_SCREENED_PII_TYPES = frozenset({"email", "phone_jp", "phone_us", "ssn_us", "credit_card", "my_number_jp"})


def _finite_in_range(value: Any, field: str, lo: float, hi: float) -> Tuple[Optional[float], Optional[str]]:
    """Validate one caller-supplied number. Returns (value, error).

    Fail CLOSED. Bools, strings and other non-numerics are refused, and so are
    NaN and +/-Infinity: those parse through float() and arrive intact in a raw
    JSON body, and every comparison against NaN is False — so a NaN relevance
    floor would pass every bound check and then admit every chunk, disabling the
    filter the caller asked to tighten. The rejected value is never echoed.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None, f"PreProcessNode: {field} must be a number between {lo:g} and {hi:g}"
    parsed = float(value)
    if not math.isfinite(parsed) or not lo <= parsed <= hi:
        return None, f"PreProcessNode: {field} must be a number between {lo:g} and {hi:g}"
    return parsed, None


def _validate_slug(value: Any, field: str) -> Tuple[Optional[str], Optional[str]]:
    """Validate one inert caller identifier. Returns (value, error). Fail CLOSED."""
    if not isinstance(value, str) or not _SLUG_RE.fullmatch(value):
        return None, f"PreProcessNode: {field} must be 1-32 characters of a-z, 0-9 and underscore"
    return value, None


def _injection_in_request(input_context: Dict[str, Any]) -> bool:
    """Screen the WHOLE structured channel for instruction-override content.

    Runs BEFORE the closed-contract check, not after it. A field the contract
    does not know is rejected as an unsupported field — a value the caller can
    correct — so an override payload carried in an undeclared key, or in that
    key's NAME, would be reported as something to fix and could be reworded
    rather than refused. Screening first makes the refusal the verdict that
    wins, whatever field the payload chose to ride in on.

    Every key and every string value is screened, including the strings inside
    a list, because the declared list field (focus_terms) is rendered into the
    answer and an undeclared one is not inspected anywhere else.
    """
    for key, value in input_context.items():
        if isinstance(key, str) and _injection_hit(key):
            return True
        for candidate in value if isinstance(value, list) else [value]:
            if isinstance(candidate, str) and _injection_hit(candidate):
                return True
    return False


def _validate_focus_term(value: Any, index: int) -> Tuple[Optional[str], Optional[str], str]:
    """Validate one caller focus term. Returns (normalised_value, error, code).

    Fail CLOSED: only a string of the term alphabet within the length limit is
    accepted. The rejected value is never echoed — the error names the field
    position and restates the contract.

    The alphabet is checked on the value AS SUPPLIED, before space runs are
    collapsed. Normalising first would silently repair a term carrying a newline
    or a tab into an acceptable one, and caller-controlled line structure is
    exactly what this contract exists to keep out of the rendered answer.

    The two REFUSED screens run before the alphabet check, not after it. Both
    an override payload and a contact identifier can carry a character the
    alphabet already excludes, and an alphabet verdict reached first would
    report either of them as a value to reformat and send again.
    """
    field = f"focus_terms[{index}]"
    contract = (
        f"PreProcessNode: {field} must be {_MAX_FOCUS_TERM_CHARS} characters or "
        "fewer of letters, digits, space and . , ( ) / & + -"
    )
    if not isinstance(value, str):
        return None, contract, _CORRECTABLE
    collapsed = _SPACES_RE.sub(" ", value).strip()
    # The structured channel gets the same instruction-override screen the query
    # gets — checked on the term as supplied AND as normalised. A term is short
    # and alphabet-restricted, but a phrased override fits inside both bounds,
    # and terms are rendered into the answer — so a screen applied only to the
    # query would leave the structured channel as an open path to the same
    # content.
    if _injection_hit(value) or _injection_hit(collapsed):
        return None, f"PreProcessNode: {field} refused - instruction-override content", _REFUSED
    # A contact identifier is refused, not corrected: the run terminates rather
    # than inviting the caller to resubmit the same personal data in a shape the
    # screen misses.
    if [f for f in detect_pii(value) if f.get("type") in _SCREENED_PII_TYPES]:
        return None, f"PreProcessNode: {field} must not contain contact identifiers", _REFUSED
    if not _FOCUS_TERM_RE.fullmatch(value):
        return None, contract, _CORRECTABLE
    if not collapsed or len(collapsed) > _MAX_FOCUS_TERM_CHARS:
        return None, contract, _CORRECTABLE
    return collapsed, None, _CORRECTABLE


def _validate_request(input_context: Any) -> Tuple[Dict[str, Any], Optional[str], str]:
    """Validate the structured caller request. Returns (record, error, code).

    An absent or empty channel degrades to the baseline request — the plain
    query against the declared defaults. Any field that IS supplied must satisfy
    its bound; there is no partial acceptance and no clamping. Fields outside
    the closed contract are refused (without echoing the unexpected name).

    `code` says how the rejection is reported: `_REFUSED` for content this agent
    refuses outright, a reason code for a value the caller can correct.
    """
    record: Dict[str, Any] = {}
    if input_context in (None, {}):
        return record, None, _CORRECTABLE
    if not isinstance(input_context, dict):
        return {}, "PreProcessNode: input_context must be an object", _CORRECTABLE

    # What the CALLER supplied. A channel carrying only the runtime's own fields
    # is a channel the caller put nothing on, and degrades to the baseline
    # request exactly as an absent one does.
    input_context = {name: value for name, value in input_context.items() if name not in _RUNTIME_CONTEXT_FIELDS}
    if not input_context:
        return record, None, _CORRECTABLE

    # The instruction-override screen runs FIRST — before the closed-contract
    # check below, which would otherwise dispose of an undeclared field (and the
    # payload inside it) as a correctable value.
    if _injection_in_request(input_context):
        return {}, "PreProcessNode: input_context refused - instruction-override content", _REFUSED

    unknown = set(input_context) - _ALLOWED_CONTEXT_FIELDS
    if unknown:
        return (
            {},
            (
                "PreProcessNode: input_context contains an unsupported field "
                "(supported: channel, top_k, min_score, focus_terms)"
            ),
            _CORRECTABLE,
        )

    if "channel" in input_context:
        channel, error = _validate_slug(input_context.get("channel"), "channel")
        if error:
            return {}, error, _CORRECTABLE
        record["channel"] = channel

    if "top_k" in input_context:
        top_k, error = _finite_in_range(input_context.get("top_k"), "top_k", _TOP_K_MIN, _TOP_K_MAX)
        if error:
            return {}, error, _CORRECTABLE
        assert top_k is not None  # _finite_in_range returns a value whenever error is None
        if top_k != int(top_k):
            return (
                {},
                f"PreProcessNode: top_k must be a whole number between {_TOP_K_MIN} and {_TOP_K_MAX}",
                _CORRECTABLE,
            )
        record["top_k"] = int(top_k)

    if "min_score" in input_context:
        min_score, error = _finite_in_range(input_context.get("min_score"), "min_score", _MIN_SCORE_MIN, _MIN_SCORE_MAX)
        if error:
            return {}, error, _CORRECTABLE
        record["min_score"] = min_score

    if "focus_terms" in input_context:
        raw_terms = input_context.get("focus_terms")
        if not isinstance(raw_terms, list):
            return {}, "PreProcessNode: focus_terms must be a list", _CORRECTABLE
        if len(raw_terms) > _MAX_FOCUS_TERMS:
            return {}, f"PreProcessNode: focus_terms must hold {_MAX_FOCUS_TERMS} entries or fewer", _CORRECTABLE
        terms: List[str] = []
        for index, raw_term in enumerate(raw_terms):
            term, error, code = _validate_focus_term(raw_term, index)
            if error:
                return {}, error, code
            if term is not None:
                terms.append(term)
        record["focus_terms"] = terms

    return record, None, _CORRECTABLE


class PreProcessNode(FunctionNode):
    """Trust gate, caller-data contract and instruction-override screen.

    Rejects empty / invalid input before the inner workflow runs, refuses a
    caller field that breaks its bound, refuses instruction-override content on
    both channels, and publishes the validated request.

    Input state keys:
        user_input:    str   — caller-supplied natural-language compliance question
        input_context: dict  — structured caller request (validated here)

    Output state keys (partial dict):
        validated_input:  str        — sanitised, normalised query string
        caller_request:   str        — JSON of the validated structured request
        enriched_context: str        — JSON-serialised channel metadata
        status:           str        — success or error
        error_code:       str        — set when the run COMPLETES without acting,
                                       because the caller can correct the value
                                       and send the request again
        error_log:        list[str]  — the internal reason, on either stop path
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: AgentState) -> Dict[str, Any]:
        user_input = state.get("user_input", "")
        input_context = state.get("input_context", {})  # read-only

        # ── Emptiness check ───────────────────────────────────────────────────
        if not user_input or not isinstance(user_input, str) or not user_input.strip():
            logger.warning("PreProcessNode: user_input is empty or missing")
            emit_trace_event(
                "pre_process_validation_failed",
                {"reason": "empty_input"},
                state,
            )
            emit_progress(EMPTY_INPUT)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": "EMPTY_INPUT",
                "error_log": ["PreProcessNode: user_input is empty or missing"],
            }

        # ── Instruction-override screen, raw form ─────────────────────────────
        # Checked BEFORE sanitisation as well as after: the two screens see
        # different texts once any character has been stripped or collapsed.
        #
        # This one TERMINATES. The emptiness check above completes carrying a
        # reason because the caller can correct the value; instruction-override
        # content is not a value to correct, and reporting it the same way would
        # read as an invitation to reword the request until it is accepted.
        if _injection_hit(user_input):
            emit_trace_event(
                "pre_process_validation_failed",
                {"reason": "instruction_override"},
                state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["PreProcessNode: query refused - instruction-override content"],
            }

        # ── Sanitise + normalise ──────────────────────────────────────────────
        # Strip control characters, collapse whitespace, and bound the length.
        # This normalisation is the input boundary: the downstream RAG pipeline
        # only ever sees the cleaned query.
        normalised = _WHITESPACE_RE.sub(" ", _CONTROL_CHARS_RE.sub("", user_input)).strip()
        if not normalised:
            emit_progress(EMPTY_INPUT)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": "EMPTY_INPUT",
                "error_log": ["PreProcessNode: user_input carries no query text"],
            }
        if len(normalised) > _MAX_QUERY_CHARS:
            emit_trace_event(
                "pre_process_validation_failed",
                {"reason": "query_too_long", "query_chars": len(normalised)},
                state,
            )
            emit_progress(TOO_LONG)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": "QUESTION_TOO_LONG",
                "error_log": [f"PreProcessNode: query must be {_MAX_QUERY_CHARS} characters or fewer"],
            }

        # ── Instruction-override screen, post-sanitise form ───────────────────
        # A character-stripping sanitiser can ASSEMBLE a control token that the
        # raw text did not contain ("<|im\x00_start|>" -> "<|im_start|>"), so the
        # screen runs again on exactly the text the pipeline would receive.
        if _injection_hit(normalised):
            emit_trace_event(
                "pre_process_validation_failed",
                {"reason": "instruction_override_post_sanitise"},
                state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["PreProcessNode: query refused - instruction-override content"],
            }

        # ── Structured caller request ─────────────────────────────────────────
        # Two stop paths, told apart by the CODE the validator returns beside
        # the message — never by reading the message. A refusal (an override
        # payload on the structured channel, a contact identifier in a focus
        # term) terminates; every other rejected field is a value the caller can
        # correct, so the run completes carrying the reason.
        record, error, code = _validate_request(input_context)
        if error:
            emit_trace_event(
                "pre_process_validation_failed",
                {"reason": "caller_request_rejected" if code else "caller_request_refused"},
                state,
            )
            if code:
                emit_progress(INPUT_REJECTED)
                return {"status": AgentStatus.SUCCESS.value, "error_code": code, "error_log": [error]}
            return {"status": AgentStatus.ERROR.value, "error_log": [error]}

        logger.info(
            "PreProcessNode: validated query chars=%d focus_terms=%d",
            len(normalised),
            len(record.get("focus_terms") or []),
        )
        emit_trace_event(
            "pre_process_validated",
            {
                "query_chars": len(normalised),
                "focus_terms": len(record.get("focus_terms") or []),
                "has_top_k": "top_k" in record,
                "has_min_score": "min_score" in record,
            },
            state,
        )

        return {
            "validated_input": normalised,
            "caller_request": to_json(record),
            "enriched_context": to_json(
                {
                    "source": "ITSecurityPolicyISMSComplianceQAAgent",
                    "channel": record.get("channel", "unknown"),
                }
            ),
            "status": AgentStatus.SUCCESS.value,
        }
