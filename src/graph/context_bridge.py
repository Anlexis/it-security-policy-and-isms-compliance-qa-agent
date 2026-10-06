"""AgentCore Platform v1.0"""

# src/graph/context_bridge.py — carries the caller's validated compliance request
# across the outer -> inner graph boundary.
#
# Why this exists: GraphNode.execute() invokes the inner graph as
# `subgraph.invoke(user_input, session_id=..., ctx=...)` and does NOT forward the
# outer state's input_context. An inner-node read of state["input_context"] would
# therefore always see {} through the full nested graph. The sanctioned subclass
# hooks bridge it:
#
#   ComplianceQAGraphNode.extract_input(state)   [runs BEFORE subgraph.invoke]
#       -> set_caller_input_context({...validated request...})
#   DomainWorkflowGraph._extra_initial_state()   [runs INSIDE subgraph.invoke]
#       -> returns {"input_context": get_caller_input_context()}
#
# Only values PreProcessNode has already validated are stashed here — the bridge
# is a transport, never a second contract.
#
# A ContextVar keeps the hand-off correct per thread/task, so concurrent
# invocations in one process cannot see each other's caller request.

from contextvars import ContextVar
from typing import Any, Dict, Optional

_CALLER_INPUT_CONTEXT: ContextVar[Optional[Dict[str, Any]]] = ContextVar(
    "isms_compliance_qa_caller_input_context", default=None
)


def set_caller_input_context(input_context: Optional[Dict[str, Any]]) -> None:
    """Stash the outer graph's caller request for the imminent inner-graph invoke."""
    _CALLER_INPUT_CONTEXT.set(dict(input_context) if input_context else {})


def get_caller_input_context() -> Dict[str, Any]:
    """Read (without consuming) the stashed request; {} when none was set."""
    return _CALLER_INPUT_CONTEXT.get() or {}
