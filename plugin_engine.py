import os
import sys
import json
import importlib.util
import traceback
from typing import Dict, Any, List, Optional
from workspace_engine import WorkspaceDB

# ---------------------------------------------------------
# PLUGIN SDK & PERMISSIONS
# ---------------------------------------------------------
class PluginPermissions:
    READ_AST = "read_ast"
    READ_SEMANTICS = "read_semantics"
    WRITE_TRANSFORM = "write_transform"
    REGISTER_RULES = "register_rules"

class PluginMetadata:
    def __init__(self, plugin_id: str, name: str, version: str, description: str, author: str, 
                 category: str, permissions: List[str]):
        self.plugin_id = plugin_id
        self.name = name
        self.version = version
        self.description = description
        self.author = author
        self.category = category
        self.permissions = permissions
        
    def to_dict(self):
        return vars(self)

class BasePlugin:
    """Base SDK interface for all CodeUnveil plugins."""
    metadata: PluginMetadata = None
    
    def initialize(self, context: Dict[str, Any]) -> bool:
        """Called during plugin startup."""
        return True
        
    def shutdown(self):
        """Called during application shutdown."""
        pass

class DetectionPlugin(BasePlugin):
    """SDK for registering custom security and obfuscation rules."""
    def get_custom_rules(self) -> List[Any]:
        # Returns List[SecurityRule] mapped for security_engine.py
        return []

class TransformationPlugin(BasePlugin):
    """SDK for registering custom AST or Code transformations."""
    def transform(self, code: str, ast_data: Dict[str, Any]) -> str:
        return code

class AnalysisPlugin(BasePlugin):
    """SDK for extending static analysis metrics."""
    def analyze(self, code: str, ast_data: Dict[str, Any]) -> Dict[str, Any]:
        return {}

# ---------------------------------------------------------
# PLUGIN DISCOVERY & REGISTRY
# ---------------------------------------------------------
PLUGIN_DIR = "plugins"
os.makedirs(PLUGIN_DIR, exist_ok=True)

class PluginRegistry:
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = PluginRegistry()
        return cls._instance

    def __init__(self):
        self.discovered_plugins: Dict[str, Dict[str, Any]] = {}  # id -> { class, metadata, path }
        self.active_instances: Dict[str, BasePlugin] = {}
        self._load_state()
        self.discover_plugins()

    def _load_state(self):
        self.state = WorkspaceDB.read("plugins") or {}

    def _save_state(self):
        WorkspaceDB.write("plugins", self.state)

    def get_template(self, template_type: str) -> str:
        if template_type == "Detection":
            return '''from plugin_engine import DetectionPlugin, PluginMetadata, PluginPermissions
from security_rules import SecurityRule

class CustomDetection(DetectionPlugin):
    metadata = PluginMetadata(
        plugin_id="custom.det.01", name="Custom Malware Detector", version="1.0.0",
        description="Detects suspicious hex payloads.", author="Analyst",
        category="Detection", permissions=[PluginPermissions.REGISTER_RULES]
    )
    
    def get_custom_rules(self):
        return [
            SecurityRule(
                "CUST_01", "Suspicious Variable Pattern", "Obfuscation", "Medium",
                "Flags variables starting with _0xdead", "Rename variable safely.",
                lambda n: getattr(n, 'type', '') == 'Identifier' and n.name.startswith('_0xdead'),
                "High"
            )
        ]
'''
        return '''from plugin_engine import TransformationPlugin, PluginMetadata, PluginPermissions

class CustomTransform(TransformationPlugin):
    metadata = PluginMetadata(
        plugin_id="custom.trans.01", name="Basic String Replacer", version="1.0.0",
        description="Replaces 'eval' with 'console.log'", author="Analyst",
        category="Transformation", permissions=[PluginPermissions.WRITE_TRANSFORM]
    )
    
    def transform(self, code, ast_data):
        return code.replace("eval(", "console.log(")
'''

    def discover_plugins(self):
        """Scans the plugins directory and safely extracts metadata without instantiating blindly."""
        for filename in os.listdir(PLUGIN_DIR):
            if filename.endswith(".py"):
                filepath = os.path.join(PLUGIN_DIR, filename)
                try:
                    spec = importlib.util.spec_from_file_location(filename[:-3], filepath)
                    mod = importlib.util.module_from_spec(spec)
                    sys.modules[spec.name] = mod
                    spec.loader.exec_module(mod)
                    
                    for attr_name in dir(mod):
                        attr = getattr(mod, attr_name)
                        if isinstance(attr, type) and issubclass(attr, BasePlugin) and attr is not BasePlugin:
                            if hasattr(attr, 'metadata') and attr.metadata:
                                pid = attr.metadata.plugin_id
                                self.discovered_plugins[pid] = {
                                    "class": attr,
                                    "metadata": attr.metadata,
                                    "path": filepath
                                }
                                # Ensure state tracks it
                                if pid not in self.state:
                                    self.state[pid] = {"enabled": False, "approved": False}
                except Exception as e:
                    print(f"Failed to load plugin {filename}: {str(e)}")
        self._save_state()

    def enable_plugin(self, plugin_id: str) -> Tuple[bool, str]:
        if plugin_id not in self.discovered_plugins:
            return False, "Plugin not found."
            
        if not self.state.get(plugin_id, {}).get("approved", False):
            return False, "Plugin must be explicitly trusted/approved by the user before enabling."
            
        try:
            p_info = self.discovered_plugins[plugin_id]
            instance = p_info["class"]()
            
            # Lifecycle: Initialize
            if not instance.initialize({"env": "CodeUnveil_M23"}):
                return False, "Plugin initialization hook failed."
                
            self.active_instances[plugin_id] = instance
            self.state[plugin_id]["enabled"] = True
            self._save_state()
            return True, "Plugin enabled successfully."
        except Exception as e:
            return False, f"Plugin Crash during initialization: {str(e)}"

    def disable_plugin(self, plugin_id: str):
        if plugin_id in self.active_instances:
            try:
                self.active_instances[plugin_id].shutdown()
            except Exception: pass
            del self.active_instances[plugin_id]
        if plugin_id in self.state:
            self.state[plugin_id]["enabled"] = False
            self._save_state()

    def approve_plugin(self, plugin_id: str):
        if plugin_id in self.state:
            self.state[plugin_id]["approved"] = True
            self._save_state()

    def delete_plugin(self, plugin_id: str):
        self.disable_plugin(plugin_id)
        if plugin_id in self.discovered_plugins:
            try:
                os.remove(self.discovered_plugins[plugin_id]["path"])
            except Exception: pass
            del self.discovered_plugins[plugin_id]
        if plugin_id in self.state:
            del self.state[plugin_id]
            self._save_state()

    def get_active_plugins_by_type(self, plugin_type: type) -> List[BasePlugin]:
        return [p for p in self.active_instances.values() if isinstance(p, plugin_type)]
