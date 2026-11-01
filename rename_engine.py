import esprima
import json
import re
from typing import Dict, Any, List, Tuple

class RenameScope:
    def __init__(self, parent=None, scope_type="block"):
        self.parent = parent
        self.scope_type = scope_type
        # Maps identifier name -> Dict of info
        self.bindings = {}
        self.children = []
        if self.parent:
            self.parent.children.append(self)

    def declare(self, name: str, node: Any, kind: str, unique_id: str):
        if name not in self.bindings:
            self.bindings[name] = {
                "id": unique_id,
                "original_name": name,
                "kind": kind,
                "decl_range": node.range,
                "ref_ranges": [],
                "is_suspicious": self._is_suspicious(name),
                "scope_type": self.scope_type
            }

    def add_reference(self, name: str, range_: List[int]) -> bool:
        if name in self.bindings:
            self.bindings[name]["ref_ranges"].append(range_)
            return True
        elif self.parent:
            return self.parent.add_reference(name, range_)
        return False # Global or undeclared

    def _is_suspicious(self, name: str) -> bool:
        if len(name) <= 2 and name not in ['i', 'j', 'x', 'y', 'e']: return True
        if name.startswith('_0x') or name.startswith('0x'): return True
        if name.count('_') >= 3: return True
        # Match random looking strings of mixed casing (heuristic)
        if len(name) > 6 and re.match(r'^[a-zA-Z0-9]+$', name) and not re.search(r'[aeiouyAEIOUY]', name): return True
        return False

    def is_name_taken(self, name: str) -> bool:
        if name in self.bindings: return True
        if self.parent and self.parent.is_name_taken(name): return True
        return False

class RenameAnalyzer:
    """Advanced Identifier Analysis and Intelligent Renaming Engine."""

    def __init__(self):
        self.reset()
        self.keywords = {"break","case","catch","class","const","continue","debugger","default","delete","do","else","export","extends","finally","for","function","if","import","in","instanceof","new","return","super","switch","this","throw","try","typeof","var","void","while","with","yield","let","await"}

    def reset(self):
        self.source_code = ""
        self.global_scope = RenameScope(scope_type="global")
        self.current_scope = self.global_scope
        self.all_identifiers = []
        self._id_counter = 0
        self.counters = {"var": 1, "func": 1, "param": 1, "class": 1}

    def _get_uid(self) -> str:
        self._id_counter += 1
        return f"ident_{self._id_counter}"

    def _add_parents(self, node: Any, parent: Any = None):
        if not node or not hasattr(node, 'type'): return
        node.parent = parent
        for key, val in vars(node).items():
            if key in ['type', 'loc', 'range', 'parent']: continue
            if isinstance(val, list):
                for item in val: self._add_parents(item, node)
            elif hasattr(val, 'type'):
                self._add_parents(val, node)

    def analyze(self, source_code: str) -> Dict[str, Any]:
        """Parses the code to extract variable declarations and map usages."""
        self.reset()
        if not source_code or not source_code.strip():
            return {"status": "error", "message": "Empty input"}
        self.source_code = source_code
        
        try:
            tree = esprima.parseScript(source_code, {"range": True, "tolerant": True})
            self._add_parents(tree)
            
            # Phase 1: Hoisting and Scope Building
            self._walk_and_build(tree)
            
            # Phase 2: Generate Safe Suggestions
            self._flatten_and_suggest(self.global_scope)

            # Gather stats
            suspicious_count = sum(1 for i in self.all_identifiers if i['is_suspicious'])
            
            return {
                "status": "success",
                "identifiers": self.all_identifiers,
                "stats": {
                    "total_identifiers": len(self.all_identifiers),
                    "suspicious_identifiers": suspicious_count,
                    "functions": sum(1 for i in self.all_identifiers if i['kind'] == 'function'),
                    "variables": sum(1 for i in self.all_identifiers if i['kind'] in ['var', 'let', 'const'])
                }
            }
        except Exception as e:
            return {"status": "error", "message": f"Rename Engine Error: {str(e)}"}

    def _walk_and_build(self, node: Any):
        if not node or not hasattr(node, 'type'): return

        is_scope = node.type in ['BlockStatement', 'Program']
        is_func = node.type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']

        if is_func:
            self.current_scope = RenameScope(parent=self.current_scope, scope_type="function")
            for p in getattr(node, 'params', []):
                self._extract_declarations(p, 'param', self.current_scope)
        elif is_scope:
            self.current_scope = RenameScope(parent=self.current_scope, scope_type="block")

        # Handle Declarations
        if node.type == 'VariableDeclarator':
            kind = getattr(node.parent, 'kind', 'var')
            target_scope = self.current_scope
            if kind == 'var':
                while target_scope.parent and target_scope.scope_type != 'function':
                    target_scope = target_scope.parent
            self._extract_declarations(node.id, kind, target_scope)
            
        elif node.type == 'FunctionDeclaration' and getattr(node, 'id', None):
            target_scope = self.current_scope
            while target_scope.parent and target_scope.scope_type != 'function' and target_scope.scope_type != 'global':
                target_scope = target_scope.parent
            self._extract_declarations(node.id, 'function', target_scope)
            
        elif node.type == 'ClassDeclaration' and getattr(node, 'id', None):
            self._extract_declarations(node.id, 'class', self.current_scope)

        # Handle References
        elif node.type == 'Identifier':
            if not self._is_declaration(node) and not self._is_static_property(node):
                self.current_scope.add_reference(node.name, node.range)

        # Recurse
        for key, val in vars(node).items():
            if key in ['type', 'loc', 'range', 'parent']: continue
            # Prevent walking into ID components manually if we handled them
            if node.type in ['VariableDeclarator', 'FunctionDeclaration', 'ClassDeclaration'] and key == 'id': continue
            if node.type == 'Property' and key == 'key' and not getattr(node, 'computed', False): continue
            if node.type == 'MemberExpression' and key == 'property' and not getattr(node, 'computed', False): continue
            
            if isinstance(val, list):
                for item in val: self._walk_and_build(item)
            elif hasattr(val, 'type'):
                self._walk_and_build(val)

        if is_func or is_scope:
            self.current_scope = self.current_scope.parent

    def _extract_declarations(self, pattern: Any, kind: str, scope: RenameScope):
        if not pattern or not hasattr(pattern, 'type'): return
        if pattern.type == 'Identifier':
            scope.declare(pattern.name, pattern, kind, self._get_uid())
        elif pattern.type == 'ArrayPattern':
            for elem in getattr(pattern, 'elements', []):
                if elem: self._extract_declarations(elem, kind, scope)
        elif pattern.type == 'ObjectPattern':
            for prop in getattr(pattern, 'properties', []):
                if prop.type == 'Property': self._extract_declarations(prop.value, kind, scope)
                elif prop.type == 'RestElement': self._extract_declarations(prop.argument, kind, scope)
        elif pattern.type == 'AssignmentPattern':
            self._extract_declarations(pattern.left, kind, scope)
        elif pattern.type == 'RestElement':
            self._extract_declarations(pattern.argument, kind, scope)

    def _is_declaration(self, node: Any) -> bool:
        p = getattr(node, 'parent', None)
        if not p: return False
        if p.type in ['VariableDeclarator', 'FunctionDeclaration', 'ClassDeclaration'] and getattr(p, 'id', None) == node: return True
        if p.type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'] and node in getattr(p, 'params', []): return True
        # For destructuring, checking if parent is a Pattern that we already traverse in _extract_declarations
        if 'Pattern' in p.type or (p.type == 'Property' and getattr(p.parent, 'type', '') == 'ObjectPattern'): return True
        if p.type == 'RestElement': return True
        return False

    def _is_static_property(self, node: Any) -> bool:
        p = getattr(node, 'parent', None)
        if not p: return False
        if p.type == 'MemberExpression' and getattr(p, 'property', None) == node and not getattr(p, 'computed', False): return True
        if p.type == 'Property' and getattr(p, 'key', None) == node and not getattr(p, 'computed', False): return True
        if p.type == 'MethodDefinition' and getattr(p, 'key', None) == node and not getattr(p, 'computed', False): return True
        return False

    def _flatten_and_suggest(self, scope: RenameScope):
        """Generates names iteratively while avoiding collisions in the scope chain."""
        for name, info in scope.bindings.items():
            if info["is_suspicious"]:
                prefix = {"function": "func", "param": "param", "class": "class_name"}.get(info["kind"], "var")
                
                # Find a safe name
                while True:
                    suggestion = f"{prefix}_{self.counters.get(info['kind'], self.counters['var'])}"
                    self.counters[info['kind']] = self.counters.get(info['kind'], self.counters['var']) + 1
                    if not scope.is_name_taken(suggestion) and suggestion not in self.keywords:
                        break
                info["suggestion"] = suggestion
            else:
                info["suggestion"] = info["original_name"]
            
            self.all_identifiers.append(info)
            
        for child in scope.children:
            self._flatten_and_suggest(child)

    def transform(self, source_code: str, approved_renames: List[Dict[str, Any]]) -> str:
        """Applies renaming replacements strictly on the AST bounds."""
        replacements = []
        for r in approved_renames:
            new_name = r.get("suggestion", "")
            if not new_name or new_name == r["original_name"]: continue
            
            # Decl range
            dr = r["decl_range"]
            replacements.append((dr[0], dr[1], new_name))
            
            # Ref ranges
            for rr in r.get("ref_ranges", []):
                replacements.append((rr[0], rr[1], new_name))
                
        # Sort right-to-left
        replacements.sort(key=lambda x: x[0], reverse=True)
        
        res = list(source_code)
        for rep in replacements:
            start, end, text = rep
            res[start:end] = list(text)
            
        return "".join(res)
