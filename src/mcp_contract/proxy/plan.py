"""Translate a neutral :class:`Policy` into a network egress plan.

The plan is the deny-by-default distillation of a policy's ``net.http`` grant
that the egress proxy enforces. Only an ``inferred`` (granted) ``net.http``
capability can open egress; ``needs_review`` and ``denied`` never do.
"""
from __future__ import annotations

from dataclasses import dataclass

from mcp_contract.models import CapabilityId, Policy


@dataclass
class EgressPlan:
    """What egress the proxy should permit.

    - ``mode == "deny"``: block every host (fail closed).
    - ``mode == "allowlist"``: permit only hosts matching ``hosts`` (via
      ``bcm.diff.host_matches`` — exact, ``"*"`` global, ``"*.suffix"``).
    - ``mode == "open"``: permit every host (the operator explicitly widened
      the grant with ``"*"``; still observed/logged).

    ``hosts`` carries the allowlist patterns and is ``[]`` for ``deny`` and
    ``open``.
    """

    mode: str
    hosts: list[str]


def egress_plan(policy: Policy) -> EgressPlan:
    """Derive the :class:`EgressPlan` for ``policy`` (deny-by-default).

    Rules:
    - ``net.http`` not granted (``None``) -> ``deny`` (nothing to open).
    - granted but with empty values -> ``deny`` (empty = grant nothing;
      matches BCM bucket-1 semantics — fail closed).
    - granted with a ``"*"`` value -> ``open`` (allow all, still observe).
    - granted with concrete host patterns (no ``"*"``) -> ``allowlist`` over
      the de-duplicated, sorted patterns.
    """
    cap = policy.granted(CapabilityId.NET_HTTP)
    if cap is None or not cap.values:
        return EgressPlan("deny", [])
    if "*" in cap.values:
        return EgressPlan("open", [])
    return EgressPlan("allowlist", sorted(set(cap.values)))
