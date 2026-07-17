"""Egress proxy — hostname-level network enforcement.

Sanctioned egress flows through :class:`EgressProxy`, a threaded, deny-by-
default forward proxy: it resolves the hostname (from the ``CONNECT`` target
or absolute-form URL), enforces the allowlist derived by :func:`egress_plan`
(reusing ``bcm.diff.host_matches``), and emits hostname-level ``net.connect``
:class:`~mcp_contract.models.BehaviorEvent`\\ s. A denied host is never
connected upstream.
"""
from __future__ import annotations

from mcp_contract.proxy.plan import EgressPlan, egress_plan
from mcp_contract.proxy.server import EgressProxy

__all__ = ["EgressPlan", "EgressProxy", "egress_plan"]
