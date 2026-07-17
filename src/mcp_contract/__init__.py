"""mcp-contract: treat MCP tool manifests as enforceable contracts.

Infer least-privilege sandbox policies from manifests (PIE), run servers on
pluggable sandbox backends (RAL), and monitor runtime behavior for drift
from the declared contract (BCM).
"""
from mcp_contract.models import (
    BehaviorEvent,
    Capability,
    CapabilityId,
    CapabilityStatus,
    EventClass,
    EventKind,
    Evidence,
    Manifest,
    Mode,
    Policy,
    Severity,
    ToolIR,
    ViolationReport,
)

__version__ = "0.1.0"

__all__ = [
    "BehaviorEvent",
    "Capability",
    "CapabilityId",
    "CapabilityStatus",
    "EventClass",
    "EventKind",
    "Evidence",
    "Manifest",
    "Mode",
    "Policy",
    "Severity",
    "ToolIR",
    "ViolationReport",
    "__version__",
]
