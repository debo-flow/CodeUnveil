import pytest
import os
import io
import zipfile
from workspace_engine import WorkspaceEngine, ConfigManager, HistoryManager, WorkspaceDB, FILES_DIR

def setup_module(module):
    # Ensure clean DB state for tests
    WorkspaceDB.init_db()
    for t in ["workspaces", "projects", "history", "sessions"]:
        WorkspaceDB.write(t, {})

def test_workspace_and_project_creation():
    engine = WorkspaceEngine()
    ws_id = engine.create_workspace("Test WS")
    
    assert ws_id in engine.get_workspaces()
    
    p_id = engine.create_project(ws_id, "Test Project", profile_id="deep")
    proj = engine.get_project(p_id)
    
    assert proj["name"] == "Test Project"
    assert proj["profile_id"] == "deep"
    assert os.path.exists(os.path.join(FILES_DIR, p_id))

def test_configuration_inheritance():
    engine = WorkspaceEngine()
    ws_id = engine.create_workspace("Config WS")
    p_id = engine.create_project(ws_id, "Config Project", profile_id="fast") # Fast defaults to apply_dce = False
    
    # Base effective config from 'fast' profile
    eff1 = ConfigManager.get_effective_config(p_id)
    assert eff1["apply_dce"] is False
    assert eff1["max_workers"] == 2
    
    # Project override
    projs = WorkspaceDB.read("projects")
    projs[p_id]["config"] = {"apply_dce": True}
    WorkspaceDB.write("projects", projs)
    
    eff2 = ConfigManager.get_effective_config(p_id)
    assert eff2["apply_dce"] is True # Overridden by project level
    assert eff2["max_workers"] == 2  # Inherited from profile

def test_history_logging():
    engine = WorkspaceEngine()
    ws_id = engine.create_workspace("Hist WS")
    p_id = engine.create_project(ws_id, "Hist Project")
    
    # Project creation logs an event
    history = HistoryManager.get_project_history(p_id)
    assert len(history) == 1
    assert history[0]["event_type"] == "PROJECT_CREATED"

def test_safe_file_management_and_export():
    engine = WorkspaceEngine()
    ws_id = engine.create_workspace("File WS")
    p_id = engine.create_project(ws_id, "File Project")
    
    # Add File
    engine.add_file_to_project(p_id, "../unsafe.js", "console.log(1);") # Path traversal attempt
    
    proj = engine.get_project(p_id)
    assert "unsafe.js" in proj["files"] # Automatically sanitized to basename
    
    # Check history
    history = HistoryManager.get_project_history(p_id)
    assert any(h["event_type"] == "FILE_ADDED" for h in history)
    
    # Export Zip
    zip_bytes = engine.export_project(p_id)
    assert zip_bytes is not None
    
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        names = z.namelist()
        assert "codeunveil_meta.json" in names
        assert "src/unsafe.js" in names
