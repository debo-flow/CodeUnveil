import os
import zipfile
import io
import json
import esprima
from typing import Dict, Any, List, Set, Tuple

class ProjectAnalyzer:
    """Advanced JavaScript Dependency Analysis & Module Intelligence Engine."""

    def __init__(self, max_files=1000, max_file_size=5 * 1024 * 1024):
        self.max_files = max_files
        self.max_file_size = max_file_size
        self.reset()

    def reset(self):
        self.files = {}          # filepath -> content
        self.modules = {}        # filepath -> { imports: [], exports: [], type: '' }
        self.package_json = {}   
        self.dependency_graph = {} # filepath -> list of resolved filepaths
        self.circular_chains = []
        self.external_deps = set()
        self.stats = {
            "total_files": 0,
            "js_files": 0,
            "external_deps": 0,
            "circular_dependencies": 0,
            "isolated_modules": 0
        }

    def analyze_zip(self, zip_bytes: bytes) -> Dict[str, Any]:
        """Safely extracts a ZIP in memory and analyzes the project architecture."""
        self.reset()
        
        if not zip_bytes:
            return {"status": "error", "message": "Empty ZIP file provided."}

        try:
            self._secure_memory_extract(zip_bytes)
            
            if "package.json" in self.files:
                try:
                    self.package_json = json.loads(self.files["package.json"])
                except Exception:
                    pass

            # 1. Parse all JS files for Imports & Exports
            for path, content in self.files.items():
                if path.endswith(('.js', '.mjs', '.cjs', '.jsx')):
                    self.stats["js_files"] += 1
                    self._analyze_module(path, content)

            # 2. Resolve Imports to build Dependency Graph
            self._build_dependency_graph()

            # 3. Detect Circular Dependencies (DFS)
            self._detect_cycles()

            # 4. Detect Isolated/Unused Modules
            self._analyze_architecture()

            return {
                "status": "success",
                "stats": self.stats,
                "modules": self.modules,
                "package_json": self.package_json,
                "dependency_graph": self.dependency_graph,
                "circular_chains": self.circular_chains,
                "external_deps": list(self.external_deps),
                "dot_graph": self._generate_dot()
            }
        except Exception as e:
            return {"status": "error", "message": f"Project Engine Error: {str(e)}"}

    def _secure_memory_extract(self, zip_bytes: bytes):
        """Extracts files to a flat/nested in-memory dictionary. Prevents Path Traversal naturally."""
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            file_count = 0
            for info in z.infolist():
                if info.is_dir(): continue
                if info.file_size > self.max_file_size: continue
                
                # Normalize paths and strip absolute or upward traversal dots
                safe_name = info.filename.lstrip("/")
                if ".." in safe_name: continue
                
                ext = os.path.splitext(safe_name)[1].lower()
                if ext in ['.js', '.mjs', '.cjs', '.jsx', '.json']:
                    try:
                        self.files[safe_name] = z.read(info).decode('utf-8', errors='replace')
                        file_count += 1
                        self.stats["total_files"] += 1
                    except Exception:
                        pass
                
                if file_count >= self.max_files:
                    break # Impose extraction limit

    def _analyze_module(self, filepath: str, content: str):
        """Parses AST to map ES6 and CommonJS import/export declarations."""
        module_data = {"imports": [], "exports": [], "type": "CommonJS"}
        
        try:
            # Try parsing as ES Module first to capture ImportDeclaration
            tree = esprima.parseModule(content, {"tolerant": True})
            module_data["type"] = "ES6"
        except Exception:
            try:
                tree = esprima.parseScript(content, {"tolerant": True})
            except Exception:
                self.modules[filepath] = module_data
                return

        def walk(node):
            if not node or not hasattr(node, 'type'): return
            
            # Imports
            if node.type == 'ImportDeclaration':
                src = getattr(node.source, 'value', '')
                specifiers = [getattr(s.local, 'name', '') for s in getattr(node, 'specifiers', []) if getattr(s, 'local', None)]
                module_data["imports"].append({"source": src, "type": "static", "specifiers": specifiers})
            elif node.type == 'CallExpression' and getattr(node.callee, 'type', '') == 'Identifier' and node.callee.name == 'require':
                if getattr(node, 'arguments', []) and getattr(node.arguments[0], 'type', '') == 'Literal':
                    module_data["imports"].append({"source": node.arguments[0].value, "type": "require", "specifiers": []})
            elif node.type == 'CallExpression' and getattr(node.callee, 'type', '') == 'Import':
                if getattr(node, 'arguments', []) and getattr(node.arguments[0], 'type', '') == 'Literal':
                    module_data["imports"].append({"source": node.arguments[0].value, "type": "dynamic", "specifiers": []})
                    
            # Exports
            elif node.type == 'ExportDefaultDeclaration':
                module_data["exports"].append({"name": "default", "type": "default"})
            elif node.type == 'ExportNamedDeclaration':
                if getattr(node, 'declaration', None) and getattr(node.declaration, 'id', None):
                    module_data["exports"].append({"name": node.declaration.id.name, "type": "named"})
                for spec in getattr(node, 'specifiers', []):
                    module_data["exports"].append({"name": getattr(spec.exported, 'name', ''), "type": "named"})
                if getattr(node, 'source', None):
                    module_data["imports"].append({"source": node.source.value, "type": "re-export", "specifiers": []})
            elif node.type == 'ExportAllDeclaration':
                if getattr(node, 'source', None):
                    module_data["imports"].append({"source": node.source.value, "type": "export-all", "specifiers": []})
            elif node.type == 'AssignmentExpression':
                # module.exports = ...
                if getattr(node.left, 'type', '') == 'MemberExpression' and getattr(node.left.object, 'name', '') == 'module' and getattr(node.left.property, 'name', '') == 'exports':
                    module_data["exports"].append({"name": "default_cjs", "type": "module.exports"})
                # exports.foo = ...
                elif getattr(node.left, 'type', '') == 'MemberExpression' and getattr(node.left.object, 'name', '') == 'exports':
                    module_data["exports"].append({"name": getattr(node.left.property, 'name', ''), "type": "exports.named"})

            for key, val in vars(node).items():
                if key in ['type', 'loc', 'range', 'parent']: continue
                if isinstance(val, list):
                    for item in val: walk(item)
                elif hasattr(val, 'type'): walk(val)
                
        walk(tree)
        self.modules[filepath] = module_data

    def _resolve_import(self, base_path: str, import_path: str) -> str:
        """Resolves an import string to a physical file path in the memory zip."""
        if not import_path.startswith('.'):
            return "EXTERNAL"
            
        # Posix style normalization
        base_dir = os.path.dirname(base_path)
        target = os.path.normpath(os.path.join(base_dir, import_path)).replace("\\", "/")
        
        candidates = [
            target,
            target + ".js",
            target + ".mjs",
            target + ".cjs",
            target + ".jsx",
            target + "/index.js",
            target + "/index.mjs"
        ]
        
        for c in candidates:
            if c in self.files:
                return c
        return "UNRESOLVED"

    def _build_dependency_graph(self):
        for filepath, data in self.modules.items():
            self.dependency_graph[filepath] = []
            for imp in data["imports"]:
                src = imp["source"]
                if not isinstance(src, str): continue
                
                resolved = self._resolve_import(filepath, src)
                if resolved == "EXTERNAL":
                    self.external_deps.add(src)
                else:
                    imp["resolved_path"] = resolved
                    if resolved != "UNRESOLVED" and resolved not in self.dependency_graph[filepath]:
                        self.dependency_graph[filepath].append(resolved)
                        
        self.stats["external_deps"] = len(self.external_deps)

    def _detect_cycles(self):
        """Directed Depth-First Search for Circular Dependency Identification."""
        visited = set()
        stack = []
        
        def dfs(node):
            if node in stack:
                cycle_idx = stack.index(node)
                cycle = stack[cycle_idx:] + [node]
                self.circular_chains.append(cycle)
                return
            if node in visited:
                return
                
            visited.add(node)
            stack.append(node)
            for neighbor in self.dependency_graph.get(node, []):
                dfs(neighbor)
            stack.pop()

        for node in self.dependency_graph:
            dfs(node)
            
        self.stats["circular_dependencies"] = len(self.circular_chains)

    def _analyze_architecture(self):
        # Find files with no incoming edges (potential entry points or dead modules)
        incoming = {node: 0 for node in self.dependency_graph}
        for node, edges in self.dependency_graph.items():
            for e in edges:
                if e in incoming: incoming[e] += 1
                
        isolated = sum(1 for v in incoming.values() if v == 0)
        self.stats["isolated_modules"] = isolated

    def _generate_dot(self) -> str:
        dot = [
            'digraph ProjectDeps {',
            '  rankdir=LR;',
            '  node [shape=box, style=filled, color="#2B2B2B", fontcolor="#E0E0E0", fontname="Courier New"];',
            '  edge [color="#666666"];',
            '  bgcolor="#0E1117";'
        ]
        
        for file in self.dependency_graph:
            dot.append(f'  "{file}" [label="{os.path.basename(file)}"];')
            
        for file, edges in self.dependency_graph.items():
            for edge in edges:
                dot.append(f'  "{file}" -> "{edge}";')
                
        for ext in self.external_deps:
            dot.append(f'  "{ext}" [label="{ext}\\n(External)", shape=ellipse, fillcolor="#FF9800"];')
            for file, data in self.modules.items():
                for imp in data["imports"]:
                    if imp.get("source") == ext:
                        dot.append(f'  "{file}" -> "{ext}" [style=dashed];')
        dot.append('}')
        return "\n".join(dot)
