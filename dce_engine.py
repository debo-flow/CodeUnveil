import esprima
import json
from typing import Dict, Any, List, Tuple

class Scope:
    def __init__(self, parent=None, scope_type="block"):
        self.parent = parent
        self.scope_type = scope_type
        self.declarations = {}
        self.used = set()

    def declare(self, name: str, node: Any, kind: str):
        self.declarations[name] = {"node": node, "kind": kind}

    def mark_used(self, name: str):
        self.used.add(name)
        if self.parent:
            self.parent.mark_used(name)

class ScopeManager:
    def __init__(self):
        self.current = Scope(scope_type="global")
        self.all_unused = []

    def enter(self, scope_type: str):
        self.current = Scope(parent=self.current, scope_type=scope_type)

    def exit(self):
        for name, info in self.current.declarations.items():
            if name not in self.current.used:
                self.all_unused.append({
                    "name": name, 
                    "node": info["node"], 
                    "kind": info["kind"]
                })
        self.current = self.current.parent

    def declare(self, name: str, node: Any, kind: str):
        # Handle JS 'var' and 'function' hoisting to function/global scope
        if kind in ['var', 'function']:
            target = self.current
            while target.parent and target.scope_type != 'function':
                target = target.parent
            target.declare(name, node, kind)
        else:
            # let, const, and params are block-scoped
            self.current.declare(name, node, kind)

    def mark_used(self, name: str):
        curr = self.current
        while curr:
            if name in curr.declarations:
                curr.used.add(name)
                break
            curr.used.add(name)
            curr = curr.parent

class DCEAnalyzer:
    """Advanced Dead Code Detection & Elimination Engine."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.source_code = ""
        self.scopes = ScopeManager()
        self.unreachable_nodes = []
        self.stats = {
            "unreachable_statements": 0,
            "unused_variables": 0,
            "unused_functions": 0,
            "unused_parameters": 0,
            "safely_removable": 0
        }
        self.replacements = [] # (start, end, new_str, reason)

    def _add_parents(self, node: Any, parent: Any = None):
        """Annotates AST with parent pointers to allow safe deletion analysis."""
        if not node or not hasattr(node, 'type'): return
        node.parent = parent
        for key, val in vars(node).items():
            if key in ['type', 'loc', 'range', 'parent']: continue
            if isinstance(val, list):
                for item in val: self._add_parents(item, node)
            elif hasattr(val, 'type'):
                self._add_parents(val, node)

    def analyze(self, source_code: str) -> Dict[str, Any]:
        """Performs advanced scope and unreachable branch analysis."""
        self.reset()
        if not source_code or not source_code.strip():
            return {"status": "error", "message": "Empty input"}
            
        self.source_code = source_code
        try:
            tree = esprima.parseScript(source_code, {"range": True, "tolerant": True})
            self._add_parents(tree)
            self._walk(tree)
            
            # Post-processing stats
            for un in self.scopes.all_unused:
                if un["kind"] == 'function': self.stats["unused_functions"] += 1
                elif un["kind"] == 'param': self.stats["unused_parameters"] += 1
                else: self.stats["unused_variables"] += 1
                
            self.stats["unreachable_statements"] = len(self.unreachable_nodes)
            self._prepare_removals()

            return {
                "status": "success",
                "stats": self.stats,
                "unused": [{"name": u["name"], "kind": u["kind"]} for u in self.scopes.all_unused],
                "unreachable_count": len(self.unreachable_nodes)
            }
        except Exception as e:
            return {"status": "error", "message": f"DCE Engine Error: {str(e)}"}

    def _walk(self, node: Any):
        if not node or not hasattr(node, 'type'): return

        is_scope = node.type in ['BlockStatement', 'Program']
        is_func = node.type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']

        if is_func:
            self.scopes.enter("function")
            for p in getattr(node, 'params', []):
                if p.type == 'Identifier':
                    self.scopes.declare(p.name, p, 'param')
        elif is_scope:
            self.scopes.enter("block")

        # 1. Register Declarations
        if node.type == 'VariableDeclarator' and node.id.type == 'Identifier':
            kind = getattr(node.parent, 'kind', 'var')
            self.scopes.declare(node.id.name, node, kind)
        elif node.type == 'FunctionDeclaration' and getattr(node, 'id', None) and node.id.type == 'Identifier':
            self.scopes.declare(node.id.name, node, 'function')
        
        # 2. Register References (Excluding declaration IDs and non-computed object keys)
        elif node.type == 'Identifier':
            self.scopes.mark_used(node.name)

        # 3. Detect Constant Condition Unreachable Branches
        if node.type == 'IfStatement' and getattr(node.test, 'type', '') == 'Literal':
            val = node.test.value
            is_truthy = val in [True, 1] or (isinstance(val, str) and len(val) > 0)
            is_falsy = val in [False, 0, None, ""]
            
            if is_falsy and hasattr(node.consequent, 'range'):
                self.unreachable_nodes.append(node.consequent)
            elif is_truthy and getattr(node, 'alternate', None) and hasattr(node.alternate, 'range'):
                self.unreachable_nodes.append(node.alternate)

        # Iterate children
        for key, val in vars(node).items():
            if key in ['type', 'loc', 'range', 'parent']: continue
            
            # Avoid falsely marking declarations or static properties as variable usage
            if node.type in ['VariableDeclarator', 'FunctionDeclaration'] and key == 'id': continue
            if node.type == 'MemberExpression' and not getattr(node, 'computed', False) and key == 'property': continue
            if node.type == 'Property' and not getattr(node, 'computed', False) and key == 'key': continue

            if isinstance(val, list):
                for idx, item in enumerate(val):
                    if hasattr(item, 'type'):
                        self._walk(item)
                        # 4. Detect Unreachable Code after Return/Throw/Break
                        if item.type in ['ReturnStatement', 'ThrowStatement', 'BreakStatement', 'ContinueStatement']:
                            for dead_item in val[idx+1:]:
                                if hasattr(dead_item, 'range'):
                                    self.unreachable_nodes.append(dead_item)
                            break # Stop processing dead code array
            elif hasattr(val, 'type'):
                self._walk(val)

        if is_func or is_scope:
            self.scopes.exit()

    def _prepare_removals(self):
        """Prepares non-overlapping string replacements for proven dead code."""
        # 1. Unreachable blocks and statements
        for node in self.unreachable_nodes:
            self.replacements.append((node.range[0], node.range[1], "", "Unreachable Statement Block"))
            self.stats["safely_removable"] += 1

        # 2. Unused Declarations (Strictly if it's the only declarator to avoid dangling commas)
        for u in self.scopes.all_unused:
            node = u["node"]
            if u["kind"] in ['var', 'let', 'const']:
                if hasattr(node, 'parent') and len(getattr(node.parent, 'declarations', [])) == 1:
                    self.replacements.append((node.parent.range[0], node.parent.range[1], "", f"Unused variable '{u['name']}'"))
                    self.stats["safely_removable"] += 1
            elif u["kind"] == 'function':
                self.replacements.append((node.range[0], node.range[1], "", f"Unused function '{u['name']}'"))
                self.stats["safely_removable"] += 1

    def transform(self) -> str:
        """Applies destructive Dead Code Elimination right-to-left."""
        unique_replacements = list(set(self.replacements))
        filtered = []
        for r in unique_replacements:
            is_inside = False
            for other in unique_replacements:
                if r == other: continue
                # if 'r' is enveloped by 'other', it will be deleted automatically when 'other' is deleted.
                if other[0] <= r[0] and other[1] >= r[1] and (other[1]-other[0] > r[1]-r[0]):
                    is_inside = True
                    break
            if not is_inside:
                filtered.append(r)
                
        filtered.sort(key=lambda x: x[0], reverse=True)
        
        res = list(self.source_code)
        for rep in filtered:
            start, end, new_str, _ = rep
            res[start:end] = list(new_str)
            
        return "".join(res)
