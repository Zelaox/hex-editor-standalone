"""Exercise real CLI, MCP stdio and application-owned desktop delivery."""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def environment(tmp_path):
    config = tmp_path / 'workspace.local.json'
    config.write_text(json.dumps({'allowed_roots': [str(ROOT), str(tmp_path)]}), encoding='utf-8')
    env = {key: value for key, value in os.environ.items() if key not in ('PYTHONPATH', 'HEX_EDITOR_ROOT')}
    # Any host env (AI Lab, UVE, etc.) may set AI_LAB_ROOT; standalone must ignore it.
    env.update(HEX_EDITOR_WORKSPACE_CONFIG=str(config), AI_LAB_ROOT=str(tmp_path / 'absent-lab'),
               QT_QPA_PLATFORM='offscreen', PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1')
    return env


def test_every_registered_tool_is_enabled_and_matches_its_function():
    from hexeditor_tools.catalog import _definitions
    from hexeditor_tools.cli import load_tool_catalog
    from hexeditor_tools.mcp import tool_input_schema
    catalog = load_tool_catalog(ROOT)
    assert set(catalog) == set(_definitions())
    for entry in catalog.values():
        Draft202012Validator.check_schema(tool_input_schema(entry['parameters']))
        actual = inspect.signature(entry['function']).parameters
        assert set(entry['parameters']) <= set(actual)
        required = {key for key, value in actual.items() if value.default is inspect.Parameter.empty}
        assert required <= set(entry['parameters'])


def test_cli_from_foreign_directory_without_lab(tmp_path):
    env = environment(tmp_path)
    source = tmp_path / 'synthetic.bin'
    source.write_bytes(b'standalone\x00\x01\xff')
    def run(*args):
        return subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/hex_tool_cli.py'), *args],
                              cwd=tmp_path, env=env, text=True, encoding='utf-8', capture_output=True, timeout=30)
    listed = run('list')
    assert listed.returncode == 0, listed.stderr
    assert json.loads(listed.stdout)['tool_count'] == 79
    result = run('run', 'binary_file_info', '--param', 'path=' + str(source))
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['source']['sha256'] == hashlib.sha256(source.read_bytes()).hexdigest()
    denied = run('run', 'binary_read_range', '--args-json', json.dumps({'path': str(source), 'unexpected': 1}))
    assert denied.returncode != 0
    assert source.read_bytes() == b'standalone\x00\x01\xff'


def test_real_mcp_stdio_roundtrip_and_rejections(tmp_path):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from hexeditor_tools.cli import load_tool_catalog

    source = tmp_path / 'synthetic.bin'
    source.write_bytes(b'bounded MCP test\x00\xff')
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    env = environment(tmp_path)
    async def run():
        params = StdioServerParameters(command=sys.executable, args=['-B', str(ROOT / 'scripts/hex_mcp_server.py')],
                                       cwd=str(tmp_path), env=env)
        async with stdio_client(params) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                listing = await session.list_tools()
                assert {tool.name for tool in listing.tools} == set(load_tool_catalog(ROOT))
                result = await session.call_tool('binary_file_info', {'path': str(source)})
                assert not result.isError
                assert json.loads(result.content[0].text)['source']['sha256'] == before
                invalid = await session.call_tool('binary_file_info', {'path': str(source), 'unexpected': 1})
                assert invalid.isError
                unknown = await session.call_tool('not_registered', {})
                assert unknown.isError
                outside = await session.call_tool('binary_file_info', {'path': str(tmp_path.parent / 'outside.bin')})
                assert outside.isError
    asyncio.run(run())
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before


def test_owned_gui_process_applies_live_open_command(tmp_path, monkeypatch):
    from hexeditor_tools.desktop import HexEditorDesktopManager
    env = environment(tmp_path)
    for key, value in env.items():
        if key in ('HEX_EDITOR_WORKSPACE_CONFIG', 'QT_QPA_PLATFORM', 'PYTHONUTF8'):
            monkeypatch.setenv(key, value)
    manager = HexEditorDesktopManager(ROOT)
    manager.runtime_root = tmp_path / 'desktop'
    manager.inbox = manager.runtime_root / 'inbox'
    manager.outbox = manager.runtime_root / 'outbox'
    manager.state_path = manager.runtime_root / 'state.json'
    manager.inbox.mkdir(parents=True)
    manager.outbox.mkdir()
    source = tmp_path / 'gui-synthetic.bin'
    source.write_bytes(b'GUI\x00standalone\xff')
    result = manager.launch()
    assert result['delivery'] == 'process_started'
    process = manager._process
    try:
        command = manager.enqueue_command('open', path=str(source))
        ack = manager.outbox / (command['command_id'] + '.json')
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline and not ack.exists() and process.poll() is None:
            time.sleep(0.1)
        assert ack.is_file(), f'GUI did not acknowledge command; exit={process.poll()}'
        receipt = json.loads(ack.read_text(encoding='utf-8'))
        assert receipt['ok'] and receipt['detail'] == 'file_opened'
        assert Path(receipt['path']) == source
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=10)
