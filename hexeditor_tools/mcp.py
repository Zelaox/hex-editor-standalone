"""MCP stdio transport over the same application-owned catalog as the CLI."""
from __future__ import annotations

import asyncio
import json
import sys

from src.project import project_root
from hexeditor_tools.cli import bootstrap_lab_runtime, load_tool_catalog, _build_arguments, run_tool


def tool_input_schema(parameters: dict) -> dict:
    properties = {}
    required = []
    for name, spec in parameters.items():
        properties[name] = {key: value for key, value in spec.items() if key != 'required'}
        if spec.get('required'):
            required.append(name)
    return {'type': 'object', 'properties': properties, 'required': required, 'additionalProperties': False}


def create_server():
    import mcp.types as types
    from mcp.server import Server

    root = bootstrap_lab_runtime(project_root())
    catalog = load_tool_catalog(root)
    server = Server('hex-editor', version='1.0.0')

    @server.list_tools()
    async def list_tools():
        return [types.Tool(name=name, description=entry['description'],
                           inputSchema=tool_input_schema(entry['parameters']))
                for name, entry in sorted(catalog.items())]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        try:
            if name not in catalog:
                raise ValueError(f'Unknown or disabled tool: {name}')
            arguments = _build_arguments(catalog[name]['parameters'], json_payload=arguments, cli_pairs=[])
            result = await asyncio.to_thread(run_tool, root, name, arguments)
            return types.CallToolResult(content=[types.TextContent(type='text', text=json.dumps(result, default=str))],
                                        isError=result.get('ok') is False)
        except Exception as exc:
            return types.CallToolResult(content=[types.TextContent(type='text', text=json.dumps({'ok': False, 'error': str(exc)}))], isError=True)

    return server


async def serve():
    from mcp.server.stdio import stdio_server
    server = create_server()
    async with stdio_server() as (reader, writer):
        await server.run(reader, writer, server.create_initialization_options())


def main():
    asyncio.run(serve())


if __name__ == '__main__':
    main()
