"""A dangling recovery link must never silently reopen expired selection."""
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_selfhost_windows_selection import fixture
import selfhost_windows_selection as selection
import selfhost_windows_recovery_journal as recovery


def test_incomplete_recovery_link_seals_predecessor(monkeypatch):
    with fixture(monkeypatch) as (root,phase,tx,outcome,path,cfg):
        selection.adopt(path)
        journal=selection.directory(cfg)
        before={p.name:p.read_bytes() for p in journal.iterdir()}
        target=root/('.'+cfg['project']+'.generation-recovery-'+'a'*32)
        marker={'schema':recovery.SCHEMA,'project':cfg['project'],'engine_id':cfg['engine_id'],
            'source_dir':str(journal),'target_dir':str(target),
            'source_sha256':{name:selection.digest(raw) for name,raw in before.items()},
            'attempt_dir':str(root/('windows-renewal-'+'b'*32)),'config_sha256':'c'*64,
            'generation_sequence':1,'evidence_sha256':{'intent.json':'d'*64},'candidate_only':True}
        (journal/recovery.INTENT).write_bytes(selection.packed(marker))
        with pytest.raises(ValueError):
            with selection.selected_inputs(path):pytest.fail('Incomplete recovery link fell back')
        assert not target.exists()
        assert all((journal/name).read_bytes()==raw for name,raw in before.items())
