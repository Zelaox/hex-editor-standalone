"""Synthetic, application-local fixtures; private investigations are never loaded."""
from pathlib import Path

import pytest


@pytest.fixture
def archive_spec(tmp_path, monkeypatch):
    from scripts.archive_evidence_file import archive_file
    from src.services import ptx_source_archive

    policy = dict(ptx_source_archive.load_source_archive_policy())
    policy['archive_root'] = str(tmp_path / 'archive')
    policy['registry_path'] = str(tmp_path / 'archive/registry.json')
    source = tmp_path / 'synthetic-session.ptx'
    source.write_bytes(b'PTX0' + bytes(range(256)) * 4 + b'synthetic session')
    result = archive_file(source_path=source, policy=policy, workspace_root=tmp_path,
                          reason='user_requested_archive', dry_run=False)
    monkeypatch.setattr(ptx_source_archive, 'load_source_archive_policy', lambda *args, **kwargs: policy)
    return {'kind': 'archive', 'archive_id': result['manifest']['archive_id']}
