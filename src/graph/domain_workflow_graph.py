"""AgentCore Platform v1.0"""

# SVC-C2-013 — DomainWorkflowGraph (inner BaseGraph)
#
# This is the INNER graph for the Cat 2 two-layer nested architecture.
# It encapsulates the ISMS compliance RAG Q&A pipeline:
#
#   START
#     → input_validate    (InputValidateNode)
#     → retrieve          (RetrieveNode)
#     → rerank_filter     (RerankFilterNode)
#     → generate_answer   (GenerateAnswerNode — grounded)
#     → output_format     (OutputFormatNode)
#     → END
#
# Called by ComplianceQAGraphNode.get_subgraph() (graph.py).
# get_output() shapes the sub_result dict consumed by merge_output() there.
#
# Rules enforced:
#   ✅ Inherits BaseGraph (fully custom topology — no forced backbone)
#   ✅ Implements all 7 BaseGraph ABC methods
#   ✅ register_nodes() does NOT call super() (abstract in BaseGraph)
#   ✅ Does NOT register initialize / finalize (outer backbone concerns)
#   ✅ All inner nodes declare required_trust_level = TrustLevel.ANONYMOUS
#   ✅ _extra_initial_state() seeds the declared runtime settings AND the
#      caller request (bridged — the framework does not forward the caller-data
#      channel into a subgraph)
#   ✅ get_output() designed together with ComplianceQAGraphNode.merge_output()
#   ✅ All inner node ctors are empty-parens (no constructor arguments)
#   ❌ No platform-internal SDK imports
#   ❌ Not placed under src/subagents/

from typing import Any, Dict

from langgraph.graph import END, START

from framework.graph.base_graph import BaseGraph
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from src.graph.context_bridge import get_caller_input_context
from src.nodes.generate_answer_node import GenerateAnswerNode
from src.nodes.input_validate_node import InputValidateNode
from src.nodes.output_format_node import OutputFormatNode
from src.nodes.rerank_filter_node import RerankFilterNode
from src.nodes.retrieve_node import RetrieveNode
from src.schemas.state import State


class DomainWorkflowGraph(BaseGraph):
    """Inner domain workflow graph for SVC-C2-013.

    Inherits BaseGraph directly for a fully custom node topology.
    Called by ComplianceQAGraphNode.get_subgraph() in graph.py, which passes the
    validated runtime settings (`_parent_config()`) into the ctor.

    Pipeline (linear RAG):
        START
          → input_validate   (InputValidateNode)
          → retrieve         (RetrieveNode)
          → rerank_filter    (RerankFilterNode)
          → generate_answer  (GenerateAnswerNode — grounded)
          → output_format    (OutputFormatNode)
          → END

    All nodes are FunctionNode subclasses with ANONYMOUS trust_level.
    initialize / finalize are outer backbone concerns — not registered here.
    """

    # ── Identity ──────────────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "svc_c2_013_isms_compliance_qa_workflow"

    @property
    def state_schema(self) -> type:
        return State

    # ── Config validation ─────────────────────────────────────────────────────

    def _validate_config(self) -> None:
        """Validate inner graph config before compilation.

        The forwarded `configurable` block (retrieval + generation settings) is
        validated by the outer graph before it is forwarded, and each domain
        node falls back to its own floor for a key that is absent, so there is
        nothing left to reject at this boundary.
        """
        return None

    # ── Runtime config + caller-request seeding ───────────────────────────────

    def _extra_initial_state(self) -> Dict[str, Any]:
        """Seed the declared runtime settings and the caller request into inner state.

        Two hand-offs happen here.

        Declared settings: ComplianceQAGraphNode._parent_config() forwards the
        validated retrieval / generation settings under config["configurable"];
        this hook copies them into the inner state (retrieval_top_k,
        retrieval_score_threshold, system_prompt_template) so RetrieveNode,
        RerankFilterNode and GenerateAnswerNode observe them end-to-end. This is
        the ONLY config-plumbing route into a domain node — the canonical
        ``execute(self, state)`` contract carries no config argument. Absent /
        invalid values are omitted and each node falls back to its own floor.

        Caller request: the framework does not forward the caller-data channel
        into a subgraph, so the outer GraphNode stashes the validated request
        immediately before the invoke and it is restored here (see
        src/graph/context_bridge.py). Only values PreProcessNode already
        validated arrive this way.
        """
        configurable = (self.config or {}).get("configurable", {}) or {}
        seed: Dict[str, Any] = {"input_context": get_caller_input_context()}

        retrieval = configurable.get("retrieval", {}) or {}
        if isinstance(retrieval, dict):
            top_k = retrieval.get("top_k")
            if top_k is not None:
                try:
                    seed["retrieval_top_k"] = int(top_k)
                except (TypeError, ValueError):
                    pass
            threshold = retrieval.get("score_threshold")
            if threshold is not None:
                try:
                    seed["retrieval_score_threshold"] = float(threshold)
                except (TypeError, ValueError):
                    pass

        llm = configurable.get("llm", {}) or {}
        if isinstance(llm, dict):
            tmpl = llm.get("system_prompt_template")
            if tmpl is not None:
                seed["system_prompt_template"] = str(tmpl)

        return seed

    # ── Node registration ─────────────────────────────────────────────────────

    def register_nodes(self) -> None:
        """Register all 5 domain nodes.

        No super() call — BaseGraph.register_nodes() is abstract.
        Do NOT register initialize or finalize; those are outer backbone
        concerns handled by AgentBaseGraph in graph.py.
        Every key registered here is referenced in add_edges().
        All nodes are instantiated with empty parens — the node contract takes
        no constructor arguments; config reaches nodes through State only (see
        _extra_initial_state() above).
        """
        self._nodes["input_validate"] = InputValidateNode()
        self._nodes["retrieve"] = RetrieveNode()
        self._nodes["rerank_filter"] = RerankFilterNode()
        self._nodes["generate_answer"] = GenerateAnswerNode()
        self._nodes["output_format"] = OutputFormatNode()

    # ── Edge wiring ───────────────────────────────────────────────────────────

    def add_edges(self) -> None:
        """Wire the linear ISMS compliance RAG topology.

        Linear flow:
            input_validate → retrieve → rerank_filter → generate_answer
            → output_format → END.

        No conditional branching — all paths through the RAG pipeline are
        linear.  route() satisfies the ABC but is not used at runtime.
        """
        self._sg.add_edge(START, "input_validate")
        self._sg.add_edge("input_validate", "retrieve")
        self._sg.add_edge("retrieve", "rerank_filter")
        self._sg.add_edge("rerank_filter", "generate_answer")
        self._sg.add_edge("generate_answer", "output_format")
        self._sg.add_edge("output_format", END)

    # ── Routing ───────────────────────────────────────────────────────────────

    def route(self, state: AgentState) -> str:
        """Conditional routing — required by BaseGraph ABC.

        Linear topology; add_conditional_edges() is not used, so this method
        is never called at runtime.  Returns END on error so an unexpected
        invocation does not re-enter a processing node.
        """
        if state.get("status") == AgentStatus.ERROR.value:
            return END
        return "output_format"

    # ── Output shape ──────────────────────────────────────────────────────────

    def get_output(self, state: AgentState) -> Dict[str, Any]:
        """Shape the output dict returned to the outer graph as sub_result.

        This dict is received by ComplianceQAGraphNode.merge_output()
        in graph.py as the `sub_result` argument.  Both methods are designed
        together to guarantee field-name consistency:

            Inner get_output() emits:   "compliance_answer", "generated_answer",
                                        "answer_citations", "action_checklist", "status"
            Outer merge_output() reads: sub_result.get(...) for each key above.
        """
        return {
            # the reason must leave the subgraph or the outer graph cannot report it
            "error_code": state.get("error_code"),
            "compliance_answer": state.get("compliance_answer"),
            "generated_answer": state.get("generated_answer"),
            "answer_citations": state.get("answer_citations"),
            "action_checklist": state.get("action_checklist"),
            "status": state.get("status"),
            "node_history": state.get("node_history", []),
            "correlation_id": state.get("correlation_id"),
        }
