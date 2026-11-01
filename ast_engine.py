import esprima
import json
from typing import Dict, Any

class ASTAnalyzer:
    def __init__(self):
        self.reset_metrics()

    def reset_metrics(self):
        self.stats = {
            "total_nodes": 0, "functions": 0, "variables": 0, "constants": 0,
            "loops": 0, "conditionals": 0, "function_calls": 0,
            "string_literals": 0, "numeric_literals": 0, "arrays": 0, "objects": 0
        }
        self.complexity = {
            "max_nesting_depth": 0, "cyclomatic_complexity": 1,
            "suspicious_wrappers": 0, "computed_property_access": 0,
            "unusual_variable_names": 0, "large_string_collections": 0,
            "switch_in_loop": 0, "debugger_statements": 0, 
            "unary_booleans": 0, "empty_blocks": 0
        }
        self.raw_ast = None
        self.ast_dict = None
        
    def _ast_to_dict(self, node: Any) -> Any:
        if isinstance(node, list):
            return [self._ast_to_dict(n) for n in node]
        if hasattr(node, 'type'):
            res = {'type': node.type}
            for k, v in vars(node).items():
                if k in ['type', 'loc', 'range']: continue
                if isinstance(v, (list, dict)) or hasattr(v, 'type'):
                    res[k] = self._ast_to_dict(v)
                else: res[k] = v
            return res
        return node

    def _is_unusual_name(self, name: str) -> bool:
        if not name: return False
        if len(name) <= 2 or name.startswith("_0x"): return True
        return False

    def _walk_ast(self, node: Any, depth: int = 0, in_loop: bool = False):
        if not node: return
        if isinstance(node, list):
            for item in node: self._walk_ast(item, depth, in_loop)
            return
        if not hasattr(node, 'type'): return

        self.stats["total_nodes"] += 1
        self.complexity["max_nesting_depth"] = max(self.complexity["max_nesting_depth"], depth)
        ntype = node.type
        current_in_loop = in_loop

        if ntype in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']:
            self.stats["functions"] += 1
            if depth > 0 and getattr(node, 'id', None) is None: self.complexity["suspicious_wrappers"] += 1
        elif ntype == 'VariableDeclaration':
            kind = getattr(node, 'kind', 'var')
            for decl in getattr(node, 'declarations', []):
                if kind == 'const': self.stats["constants"] += 1
                else: self.stats["variables"] += 1
                if hasattr(decl, 'id') and hasattr(decl.id, 'name'):
                    if self._is_unusual_name(decl.id.name): self.complexity["unusual_variable_names"] += 1
        elif ntype in ['ForStatement', 'WhileStatement', 'DoWhileStatement', 'ForInStatement', 'ForOfStatement']:
            self.stats["loops"] += 1
            self.complexity["cyclomatic_complexity"] += 1
            current_in_loop = True
        elif ntype == 'SwitchStatement':
            if current_in_loop: self.complexity["switch_in_loop"] += 1
            self.stats["conditionals"] += 1
        elif ntype in ['IfStatement', 'ConditionalExpression', 'LogicalExpression']:
            if ntype != 'LogicalExpression': self.stats["conditionals"] += 1
            self.complexity["cyclomatic_complexity"] += 1
        elif ntype == 'CallExpression':
            self.stats["function_calls"] += 1
        elif ntype == 'Literal':
            val = getattr(node, 'value', None)
            if isinstance(val, str): self.stats["string_literals"] += 1
            elif isinstance(val, (int, float)): self.stats["numeric_literals"] += 1
        elif ntype == 'ArrayExpression':
            self.stats["arrays"] += 1
            elements = getattr(node, 'elements', [])
            if len(elements) > 10 and all(getattr(el, 'type', '') == 'Literal' and isinstance(getattr(el, 'value', None), str) for el in elements):
                self.complexity["large_string_collections"] += 1
        elif ntype == 'ObjectExpression':
            self.stats["objects"] += 1
        elif ntype == 'MemberExpression':
            if getattr(node, 'computed', False): self.complexity["computed_property_access"] += 1
        elif ntype == 'DebuggerStatement':
            self.complexity["debugger_statements"] += 1
        elif ntype == 'BlockStatement':
            if not getattr(node, 'body', []): self.complexity["empty_blocks"] += 1
        elif ntype == 'UnaryExpression':
            if getattr(node, 'operator', '') == '!': self.complexity["unary_booleans"] += 1

        for key, value in vars(node).items():
            if key in ['type', 'loc', 'range']: continue
            if isinstance(value, list) or hasattr(value, 'type'):
                self._walk_ast(value, depth + 1, current_in_loop)

    def analyze(self, code: str) -> Dict[str, Any]:
        self.reset_metrics()
        if not code or not code.strip(): raise ValueError("Input code is empty.")
        if len(code) > 1024 * 1024: raise ValueError("File exceeds 1MB limit.")
        try:
            self.raw_ast = esprima.parseScript(code, {"loc": False, "range": True, "tolerant": True})
            self.ast_dict = self._ast_to_dict(self.raw_ast)
            self._walk_ast(self.raw_ast, depth=0, in_loop=False)
            return {"status": "success", "stats": self.stats, "complexity": self.complexity, "ast_tree": self.ast_dict}
        except esprima.Error as e:
            return {"status": "error", "message": f"AST Parsing Error: {str(e)}"}
