"""AgentCore Platform v1.0"""

# SVC-C2-013 — Outer graph (AgentBaseGraph; Cat 2 two-layer nested architecture)
#
# Architecture (Cat 2):
#
#   Outer backbone (fixed — do NOT override add_edges()):
#     START → initialize → pre_process → main → {route} → post_process → finalize → END
#                                             ↓ (retry)
#                                          pre_process
#
#   `main` slot is a GraphNode subclass (ComplianceQAGraphNode) that delegates
#   the full domain RAG workflow to DomainWorkflowGraph (inner BaseGraph).
#
#   Domain complexity is fully encapsulated inside the inner graph. The outer
#   backbone is never modified.
#
# Directory layout:
#   src/graph/graph.py                 ← outer graph (this file)
#   src/graph/domain_workflow_graph.py ← inner graph (multi-step topology)
#   src/graph/context_bridge.py        ← caller-request hand-off (outer → inner)
#
# Runtime configuration:
#   config/agent.yaml is the static registration manifest — identity only, no
#   tuning. config/config.yaml holds every runtime parameter. The registry loads
#   that file and passes it as Graph(config=...); the standalone server does the
#   same through _runtime_config(), so a registry-loaded agent and a deployed
#   one see identical settings. Every declared value is validated once in
#   declared_settings() and then travels to its consumer — there is no second
#   copy of the defaults on disk.

import math
from pathlib import Path
from typing import Any, ClassVar, Dict, Optional, cast

from framework.graph.agent_base_graph import AgentBaseGraph
from framework.nodes.graph_node import GraphNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from src.graph.context_bridge import set_caller_input_context
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.schemas.state import State

# Runtime parameters: src/graph/graph.py -> parents[2] = repo root.
_RUNTIME_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.yaml"

# Built-in retrieval / generation tuning, used only for keys config/config.yaml
# does not declare or declares out of contract. These are the pipeline's floor,
# not a mirror of the file: a value present in the file always wins, which is
# what makes the declaration observable end to end.
_BUILTIN_SETTINGS: Dict[str, Any] = {
    "top_k": 8,
    "score_threshold": 0.4,
    "system_prompt_template": "prompts/isms_compliance.j2",
}

# Bounds every declared retrieval setting is checked against.
_TOP_K_MIN, _TOP_K_MAX = 1, 20
_SCORE_MIN, _SCORE_MAX = 0.0, 1.0


def _runtime_config() -> Dict[str, Any]:
    """Read the runtime parameters from config/config.yaml.

    This is the file the registry loads and passes as Graph(config=...); the
    standalone server (src/api/server.py) reads it here so both deployments run
    on the same declaration. Returns an empty dict — never raises — when the
    file is absent, unreadable, not valid YAML, or not a mapping; the graph then
    runs on its built-in floor. PyYAML is imported lazily because it is a
    framework runtime dependency rather than a module-load coupling of this
    template.
    """
    try:
        import yaml

        loaded = yaml.safe_load(_RUNTIME_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(loaded, dict):
        return {}
    return cast(Dict[str, Any], loaded)


def _config_number(value: Any, lo: float, hi: float) -> Optional[float]:
    """Validate one declared numeric setting: a real number, finite, within [lo, hi].

    Bools, strings, other non-numerics, NaN/Infinity and out-of-range values all
    return None, and the consumer keeps its built-in floor. Rejecting non-finite
    values matters even for a declared setting: NaN compares False against every
    bound, so a NaN relevance threshold would silently disable the filter it
    configures rather than fail.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    parsed = float(value)
    if not math.isfinite(parsed) or not lo <= parsed <= hi:
        return None
    return parsed


def declared_settings(config: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and flatten the declared runtime settings for the domain nodes.

    `config` is what the graph was constructed with — the contents of
    config/config.yaml. Each value is checked for type, finiteness and range; an
    absent or out-of-contract key falls back to the built-in floor rather than
    propagating a value no consumer could use.
    """
    retrieval = config.get("retrieval")
    retrieval = retrieval if isinstance(retrieval, dict) else {}
    llm = config.get("llm")
    llm = llm if isinstance(llm, dict) else {}

    settings: Dict[str, Any] = dict(_BUILTIN_SETTINGS)

    top_k = _config_number(retrieval.get("top_k"), _TOP_K_MIN, _TOP_K_MAX)
    if top_k is not None:
        settings["top_k"] = int(top_k)

    threshold = _config_number(retrieval.get("score_threshold"), _SCORE_MIN, _SCORE_MAX)
    if threshold is not None:
        settings["score_threshold"] = threshold

    template = llm.get("system_prompt_template")
    if isinstance(template, str) and template.strip():
        settings["system_prompt_template"] = template.strip()

    return settings


class ComplianceQAGraphNode(GraphNode):
    """GraphNode subclass assigned to the `main` slot of ITSecurityPolicyISMSComplianceQAAgent.

    Wraps DomainWorkflowGraph (inner Cat 2 RAG BaseGraph).
    Called by AgentBaseGraph backbone after pre_process and before post_process.

    Contracts:
      get_subgraph()  — build the inner graph carrying the declared settings
      extract_input() — hand the inner graph the validated query, and bridge the
                        validated caller request across the boundary
      merge_output()  — map sub_result fields into outer state delta (changed keys only)
      error_strategy  — "propagate": re-raise inner errors as SubgraphError (fail-fast)
    """

    error_strategy: ClassVar[str] = "propagate"
    propagate_hitl: ClassVar[bool] = False

    def __init__(self, settings: Optional[Dict[str, Any]] = None) -> None:
        """Bind the validated runtime settings forwarded by the outer graph."""
        super().__init__()
        self._settings: Dict[str, Any] = dict(settings or _BUILTIN_SETTINGS)

    def _parent_config(self) -> Dict[str, Any]:
        """Forward the validated runtime settings to the inner graph.

        The values come from the outer graph's own config — config/config.yaml
        as loaded by the registry (or the standalone server) — validated once in
        declared_settings(). The inner graph republishes them into inner state
        (DomainWorkflowGraph._extra_initial_state()) so RetrieveNode,
        RerankFilterNode and GenerateAnswerNode read live declared values rather
        than a dead declaration. State is the only route to the RAG nodes, which
        implement the canonical ``execute(self, state)`` contract with no config
        argument.
        """
        return {
            "configurable": {
                "retrieval": {
                    "top_k": self._settings["top_k"],
                    "score_threshold": self._settings["score_threshold"],
                },
                "llm": {
                    "system_prompt_template": self._settings["system_prompt_template"],
                },
            }
        }

    def get_subgraph(self) -> Any:
        """Instantiate and return the inner domain workflow graph.

        DomainWorkflowGraph is imported lazily (inside the method) to avoid
        circular-import risk at module load time and to match the Cat 2 pattern.
        """
        from src.graph.domain_workflow_graph import DomainWorkflowGraph

        return DomainWorkflowGraph(config=self._parent_config())

    def execute(self, state: AgentState) -> Dict[str, Any]:
        """Skip the inner graph when the request was already settled upstream.

        The backbone edge pre_process -> main is unconditional, so this slot runs
        whatever pre_process decided. Two settled outcomes must not reach the
        inner graph:

        A request declined by pre_process has no validated input to act on, so
        running the inner graph would only produce a second, vaguer reason for
        the same rejection — and overwrite the specific one already settled.

        A request REFUSED by pre_process terminated, and the inner pipeline has
        no sight of that: it would receive an empty query, stop on its own
        domain rule, and report that stop as a correctable value — turning a
        refusal into a completed run. The refusal is carried through unchanged
        instead.
        """
        marker = state.get("error_code")
        if marker:
            return {"status": AgentStatus.SUCCESS.value, "error_code": marker}
        if state.get("status") == AgentStatus.ERROR.value:
            return {"status": AgentStatus.ERROR.value}
        result: Dict[str, Any] = super().execute(state)
        return result

    def extract_input(self, state: AgentState) -> str:
        """Return the string input passed into inner_graph.invoke(), and bridge
        the caller request.

        GraphNode.extract_input() returns a STRING the framework writes into the
        inner state under `user_input`. That field is one the framework's input
        gate rewrites, and its personal-name heuristic matches any two
        consecutive capitalised words — precisely the shape of an ISMS control
        or policy name ("Information Classification", "Change Management").
        Carrying the caller's focus terms there would replace them with a mask
        token and retrieval would key off the mask instead of the term. Only the
        query travels on `user_input`; the structured request crosses on the
        caller-data channel, which carries values through untouched.

        This is also the last hook that sees the outer state before the inner
        invoke, and the framework does not forward the caller-data channel into
        a subgraph (see src/graph/context_bridge.py), so the validated request
        is stashed here for the inner side to pick up.
        """
        set_caller_input_context({"caller_request": state.get("caller_request") or "{}"})
        return cast(str, state.get("validated_input") or state.get("user_input") or "")

    def merge_output(self, state: AgentState, sub_result: Dict[str, Any]) -> Dict[str, Any]:
        """Map inner graph sub_result back into the outer state delta.

        sub_result is the dict returned by DomainWorkflowGraph.get_output().
        Returns ONLY changed keys — never the full state.

        Key coupling (designed together with DomainWorkflowGraph.get_output()):
          Inner get_output() emits  → "compliance_answer", "generated_answer",
                                       "answer_citations", "action_checklist", "status"
          This merge_output() reads → sub_result.get(...) for each of these keys.

        PostProcessNode (outer post_process) reads compliance_answer from state
        to apply the output gate and set formatted_output.
        """
        return {
            # Outer reason wins: a reason settled before the inner run is the real
            # one, and a plain sub_result.get() would erase it.
            "error_code": state.get("error_code") or sub_result.get("error_code", ""),
            "compliance_answer": sub_result.get("compliance_answer"),
            "generated_answer": sub_result.get("generated_answer"),
            "answer_citations": sub_result.get("answer_citations"),
            "action_checklist": sub_result.get("action_checklist"),
            "status": sub_result.get("status"),
        }


class ITSecurityPolicyISMSComplianceQAAgent(AgentBaseGraph):
    """Outer graph for SVC-C2-013 (Cat 2 — RAGAgent).

    Inherits AgentBaseGraph directly. Domain logic is fully encapsulated in
    ComplianceQAGraphNode (main slot), which delegates to DomainWorkflowGraph
    (inner BaseGraph).

    Backbone (fixed):
        START → initialize → pre_process → main → post_process → finalize → END

    register_nodes() is the ONLY override:
      - super().register_nodes() fills: initialize, finalize (framework defaults)
      - pre_process:  PreProcessNode      (VERIFIED_EXTERNAL — trust gate +
                                           caller-data contract)
      - main:         ComplianceQAGraphNode (delegates to DomainWorkflowGraph,
                                           carrying the validated settings)
      - post_process: PostProcessNode     (output boundary — fail closed)

    Runtime configuration: the registry loads config/config.yaml and passes it
    as Graph(config=...); the standalone server does the same via
    _runtime_config(). AgentBaseGraph consumes max_retry from that config for
    retry routing, and the validated retrieval/generation settings reach the
    inner graph through ComplianceQAGraphNode — so every declared value is live
    in both deployments.

    get_output() is deliberately NOT overridden. SVC-C2-013 is a RAG Q&A agent:
    the single caller-facing deliverable is the assembled compliance-answer
    document (with its embedded References and Action Checklist sections).
    PostProcessNode applies the output gate and writes it to formatted_output /
    result, and the framework's FinalizeNode surfaces that gated value in the
    base ``output`` envelope — so ``agent.invoke()`` already returns the answer
    to the caller. Because the answer is fully in base ``output`` and that value
    is already gated (fail-closed), a get_output() override would be redundant
    and could risk re-surfacing the pre-gate ``compliance_answer`` — so it is
    intentionally omitted.

    add_edges() is NOT overridden — backbone wiring belongs to the framework.

    Class name MUST match the class path declared in config/agent.yaml exactly.
    server.py imports this as `Graph` via the alias below.
    """

    @property
    def name(self) -> str:
        """Agent identifier registered with AgentRegistry."""
        return "ITSecurityPolicyISMSComplianceQAAgent"

    @property
    def state_schema(self) -> type:
        return State

    def register_nodes(self) -> None:
        """Fill all 5 backbone slots.

        super().register_nodes() MUST be called first — it injects the
        framework's default InitializeNode (sets schema_version, session_id,
        trust_level) and FinalizeNode (builds response_metadata, total_time_ms).

        The declared settings are validated once here and handed to the main
        slot, so config/config.yaml is the single source for the inner pipeline.
        """
        super().register_nodes()  # fills: initialize, finalize

        self._nodes["pre_process"] = PreProcessNode()
        self._nodes["main"] = ComplianceQAGraphNode(settings=declared_settings(self.config))
        self._nodes["post_process"] = PostProcessNode()

    # add_edges() is NOT overridden — backbone wiring belongs to the framework.


# Alias for backward compat (server.py imports Graph).
# Class name ITSecurityPolicyISMSComplianceQAAgent matches config/agent.yaml class: field.
Graph = ITSecurityPolicyISMSComplianceQAAgent
