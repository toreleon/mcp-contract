"""A real MCP client (official `mcp` SDK, stdio transport) — NO LLM.

It performs the JSON-RPC handshake a model host would (`initialize` ->
`tools/list` / `tools/call`) so the demo drives real MCP servers the same way
Claude Desktop would, but with scripted calls instead of a model.

Usage:
  python demo/mcp_client.py list  -- <server cmd...>
  python demo/mcp_client.py call <tool> <json-args> -- <server cmd...>

Everything before `--` is the operation; everything after is the server launch
command. The current environment (incl. HTTP_PROXY/HTTPS_PROXY) is passed
through to the server subprocess so the demo can route its egress through the
mcp-contract proxy.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _split_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" not in argv:
        raise SystemExit("usage: mcp_client.py <op...> -- <server cmd...>")
    i = argv.index("--")
    return argv[:i], argv[i + 1 :]


async def _run(op: list[str], server_cmd: list[str]) -> int:
    params = StdioServerParameters(
        command=server_cmd[0],
        args=server_cmd[1:],
        env=dict(os.environ),  # inherit HTTP_PROXY etc. (full env, not minimal)
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            if op[0] == "list":
                tools = await session.list_tools()
                out = {
                    "tools": [
                        {
                            "name": t.name,
                            "description": t.description or "",
                            "inputSchema": t.inputSchema,
                        }
                        for t in tools.tools
                    ]
                }
                print(json.dumps(out, indent=2))
                return 0
            if op[0] == "call":
                tool = op[1]
                args = json.loads(op[2]) if len(op) > 2 else {}
                try:
                    result = await session.call_tool(tool, args)
                except Exception as exc:  # tool/transport error (e.g. blocked egress)
                    print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
                    return 1
                blocks = []
                for c in result.content:
                    blocks.append(getattr(c, "text", None) or str(c))
                print(json.dumps({
                    "isError": bool(getattr(result, "isError", False)),
                    "content": blocks,
                }, indent=2))
                return 0
            raise SystemExit(f"unknown op: {op[0]!r}")


def main() -> int:
    op, server_cmd = _split_argv(sys.argv[1:])
    if not op or not server_cmd:
        raise SystemExit("usage: mcp_client.py <op...> -- <server cmd...>")
    return asyncio.run(_run(op, server_cmd))


if __name__ == "__main__":
    raise SystemExit(main())
