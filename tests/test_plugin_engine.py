import pytest
import os
from plugin_engine import PluginRegistry, PluginMetadata, PluginPermissions, DetectionPlugin, PLUGIN_DIR
from api_server import LocalAPIServer

def test_plugin_metadata_and_permissions():
    meta = PluginMetadata(
        plugin_id="test.01", name="Test Plugin", version="1.0",
        description="Desc", author="Auth", category="Test",
        permissions=[PluginPermissions.READ_AST]
    )
    
    assert meta.plugin_id == "test.01"
    assert PluginPermissions.READ_AST in meta.permissions

def test_plugin_lifecycle_and_trust():
    registry = PluginRegistry.get_instance()
    
    # Simulate a discovered plugin
    class DummyPlugin(DetectionPlugin):
        metadata = PluginMetadata("dummy.01", "Dummy", "1", "D", "A", "Det", [])
        
    registry.discovered_plugins["dummy.01"] = {
        "class": DummyPlugin,
        "metadata": DummyPlugin.metadata,
        "path": "dummy.py"
    }
    registry.state["dummy.01"] = {"enabled": False, "approved": False}
    
    # Try enabling without approval (should fail)
    success, msg = registry.enable_plugin("dummy.01")
    assert success is False
    assert "approved" in msg.lower()
    
    # Approve and enable
    registry.approve_plugin("dummy.01")
    success, msg = registry.enable_plugin("dummy.01")
    assert success is True
    assert "dummy.01" in registry.active_instances
    
    # Check shutdown
    registry.disable_plugin("dummy.01")
    assert "dummy.01" not in registry.active_instances

def test_local_api_lifecycle():
    # Only test threading state to avoid actual port binding collisions in CI
    running_initially = LocalAPIServer.is_running()
    assert running_initially is False
    
    success, msg = LocalAPIServer.start(port=8085)
    assert success is True
    assert LocalAPIServer.is_running() is True
    
    # Prevent double start
    success2, _ = LocalAPIServer.start()
    assert success2 is False
    
    LocalAPIServer.stop()
    assert LocalAPIServer.is_running() is False
