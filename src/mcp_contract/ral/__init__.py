"""Runtime Adapter Layer: sandbox backends behind one interface."""
from __future__ import annotations

from typing import Any

from mcp_contract.ral.base import (
    BackendCaps,
    RuntimeAdapter,
    ServerHandle,
    ServerSpec,
    SupportLevel,
)

__all__ = [
    "BackendCaps",
    "RuntimeAdapter",
    "ServerHandle",
    "ServerSpec",
    "SupportLevel",
    "get_adapter",
]


def get_adapter(name: str, **kwargs: Any) -> RuntimeAdapter:
    """Look up a backend adapter by name (lazy imports keep deps optional)."""
    if name == "docker":
        from mcp_contract.ral.docker import DockerAdapter

        return DockerAdapter(**kwargs)
    if name == "mock":
        from mcp_contract.ral.mock import MockAdapter

        return MockAdapter(**kwargs)
    raise ValueError(f"unknown backend: {name!r} (available: docker, mock)")
