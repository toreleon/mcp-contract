"""LLM-assist protocol for PIE (spec §4.5).

An `LLMAssist` reads a tool's name/description/schema and *suggests*
capability classes. Suggestions are advisory only: `infer_policy` clamps
every suggestion to `needs_review`, drops suggestions for classes the rules
already flagged, and tags all suggestion evidence with ``source="llm"``.
Rules win every conflict; the LLM can never widen a grant.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from mcp_contract.models import Capability, ToolIR


@runtime_checkable
class LLMAssist(Protocol):
    """Anything that can propose capability classes for one tool."""

    def suggest(self, tool: ToolIR) -> list[Capability]: ...


class NullLLM:
    """Default assist: suggests nothing, so rules alone decide."""

    def suggest(self, tool: ToolIR) -> list[Capability]:
        return []
