import esprima
import json
import math
from typing import Dict, Any, List, Tuple

class UNRESOLVED: pass

class ExprScope:
    def __init__(self, parent=None):
        self.parent = parent
        self.constants = {}

    def get(self, name: str) -> Any:
        if name in self.constants: return self.constants[name]
        if self.parent: return self.parent.get(name)
        return UNRESOLVED

class ExprAnalyzer:
    """Advanced JavaScript Expression Simplification & Constant Folding Engine."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.source_code = ""
        self.mutated_vars = set()
        self.replacements = []
        self.stats = {
            "total_expressions": 0,
            "constant_folds": 0,
            "constant_propagations": 0,
            "simplifications": 0
        }

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
        self.reset()
        if not source_code or not source_code.strip():
            return {"status": "error", "message": "Empty input"}
        self.source_code = source_code
        
        try:
            tree = esprima.parseScript(source_code, {"range": True, "tolerant": True})
            self._add_parents(tree)
            
            # Pass 1: Identify strictly mutated variables to block unsafe propagation
            self._find_mutations(tree)
            
            # Pass 2: Post-order scope tracking & constant folding
            self._walk_and_fold(tree, ExprScope(parent=None))

            return {
                "status": "success",
                "replacements": self.replacements,
                "stats": self.stats
            }
        except Exception as e:
            return {"status": "error", "message": f"Expr Engine Error: {str(e)}"}

    def _find_mutations(self, node: Any):
        if not node or not hasattr(node, 'type'): return
        if node.type in ['AssignmentExpression', 'UpdateExpression']:
            target = getattr(node, 'left', getattr(node, 'argument', None))
            if target and target.type == 'Identifier':
                self.mutated_vars.add(target.name)
        # Deep object mutations e.g., obj.x = 1 tracking to root obj
        if node.type == 'AssignmentExpression' and node.left.type == 'MemberExpression':
            if node.left.object.type == 'Identifier':
                self.mutated_vars.add(node.left.object.name)
                
        for key, val in vars(node).items():
            if key in ['type', 'loc', 'range', 'parent']: continue
            if isinstance(val, list):
                for i in val: self._find_mutations(i)
            elif hasattr(val, 'type'):
                self._find_mutations(val)

    def _walk_and_fold(self, node: Any, scope: ExprScope):
        if not node or not hasattr(node, 'type'): return

        is_scope = node.type in ['BlockStatement', 'Program', 'FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']
        if is_scope: scope = ExprScope(parent=scope)

        # 1. Pre-order: Register Constants
        if node.type == 'VariableDeclarator' and node.id.type == 'Identifier':
            if getattr(node.init, 'type', '') == 'Literal' and node.id.name not in self.mutated_vars:
                scope.constants[node.id.name] = node.init.value

        # 2. Recurse (Post-Order evaluation)
        for key, val in vars(node).items():
            if key in ['type', 'loc', 'range', 'parent']: continue
            if isinstance(val, list):
                for item in val: self._walk_and_fold(item, scope)
            elif hasattr(val, 'type'):
                self._walk_and_fold(val, scope)

        # 3. Process node post-order
        if node.type in ['BinaryExpression', 'LogicalExpression', 'UnaryExpression']:
            self.stats["total_expressions"] += 1

        node._m11_val = UNRESOLVED
        node._m11_const = False
        node._m11_str = self.source_code[node.range[0]:node.range[1]] if hasattr(node, 'range') else ""

        if node.type == 'Literal':
            node._m11_val = node.value
            node._m11_const = True
            node._m11_str = self._js_format(node.value)

        elif node.type == 'Identifier':
            val = scope.get(node.name)
            if val is not UNRESOLVED and node.name not in self.mutated_vars:
                node._m11_val = val
                node._m11_const = True
                node._m11_str = self._js_format(val)
                if not self._is_lvalue(node) and not self._is_static_property(node):
                    self._queue(node, node._m11_str, "Constant Propagation")
                    self.stats["constant_propagations"] += 1

        elif node.type == 'UnaryExpression':
            a_const = getattr(node.argument, '_m11_const', False)
            a_val = getattr(node.argument, '_m11_val', UNRESOLVED)
            if a_const:
                res = self._eval_unary(node.operator, a_val)
                if res is not UNRESOLVED:
                    node._m11_val = res
                    node._m11_const = True
                    node._m11_str = self._js_format(res)
                    self._queue(node, node._m11_str, "Unary Constant Fold")
                    self.stats["constant_folds"] += 1

        elif node.type in ['BinaryExpression', 'LogicalExpression']:
            l_const = getattr(node.left, '_m11_const', False)
            r_const = getattr(node.right, '_m11_const', False)
            l_val = getattr(node.left, '_m11_val', UNRESOLVED)
            r_val = getattr(node.right, '_m11_val', UNRESOLVED)
            
            # Constant Fold
            if l_const and r_const:
                res = self._eval_binary(node.operator, l_val, r_val)
                if res is not UNRESOLVED:
                    node._m11_val = res
                    node._m11_const = True
                    node._m11_str = self._js_format(res)
                    self._queue(node, node._m11_str, "Binary Constant Fold")
                    self.stats["constant_folds"] += 1
            else:
                # Expression Simplification (Arithmetic & Logical Redundancy)
                l_str = getattr(node.left, '_m11_str', '')
                r_str = getattr(node.right, '_m11_str', '')
                res_str = self._simplify_redundancy(node.operator, l_const, l_val, l_str, r_const, r_val, r_str)
                if res_str:
                    self._queue(node, res_str, "Expression Simplification")
                    node._m11_str = res_str
                    self.stats["simplifications"] += 1

    def _queue(self, node, resolved_str, type_str):
        raw = self.source_code[node.range[0]:node.range[1]]
        self.replacements.append({
            "type": type_str,
            "original": raw,
            "resolved": resolved_str,
            "range": node.range
        })

    def _simplify_redundancy(self, op, lc, lv, ls, rc, rv, rs) -> str:
        # Arithmetic logic
        if op in ['+', '-'] and rc and rv == 0: return ls
        if op == '+' and lc and lv == 0: return rs
        if op in ['*', '/'] and rc and rv == 1: return ls
        if op == '*' and lc and lv == 1: return rs
        
        # Logical short-circuiting
        if op == '&&' and lc: return rs if self._truthy(lv) else self._js_format(lv)
        if op == '||' and lc: return self._js_format(lv) if self._truthy(lv) else rs
        if op == '??' and lc: return rs if lv is None else self._js_format(lv)
        return None

    def _is_lvalue(self, node: Any) -> bool:
        p = getattr(node, 'parent', None)
        if not p: return False
        if p.type in ['AssignmentExpression', 'UpdateExpression'] and getattr(p, 'left', getattr(p, 'argument', None)) == node: return True
        if p.type == 'VariableDeclarator' and p.id == node: return True
        if p.type in ['FunctionDeclaration', 'FunctionExpression'] and getattr(p, 'id', None) == node: return True
        return False

    def _is_static_property(self, node: Any) -> bool:
        p = getattr(node, 'parent', None)
        if not p: return False
        if p.type == 'Property' and p.key == node and not getattr(p, 'computed', False): return True
        if p.type == 'MemberExpression' and p.property == node and not getattr(p, 'computed', False): return True
        return False

    def _truthy(self, val: Any) -> bool:
        if val in [False, 0, 0.0, "", None]: return False
        if isinstance(val, float) and math.isnan(val): return False
        return True

    def _to_int32(self, val):
        try:
            v = int(float(val))
            return (v & 0xFFFFFFFF) - (0x100000000 if (v & 0x80000000) else 0)
        except: return 0

    def _to_uint32(self, val):
        try:
            return int(float(val)) & 0xFFFFFFFF
        except: return 0

    def _js_format(self, val: Any) -> str:
        if val is None: return "null"
        if isinstance(val, bool): return "true" if val else "false"
        if isinstance(val, (int, float)):
            if math.isnan(val): return "NaN"
            if math.isinf(val): return "Infinity" if val > 0 else "-Infinity"
            if isinstance(val, float) and val.is_integer(): return str(int(val))
            return str(val)
        if isinstance(val, str):
            return json.dumps(val)
        return str(val)

    def _eval_unary(self, op, arg):
        try:
            if op == '!': return not self._truthy(arg)
            elif op == '-': return -float(arg)
            elif op == '+': return float(arg)
            elif op == '~': return ~self._to_int32(arg)
            elif op == 'typeof':
                if arg is None: return "object"
                if isinstance(arg, bool): return "boolean"
                if isinstance(arg, (int, float)): return "number"
                if isinstance(arg, str): return "string"
        except: pass
        return UNRESOLVED

    def _eval_binary(self, op, left, right):
        try:
            if op == '+':
                if isinstance(left, str) or isinstance(right, str): return str(left) + str(right)
                return float(left) + float(right)
            elif op == '-': return float(left) - float(right)
            elif op == '*': return float(left) * float(right)
            elif op == '/':
                fr, fl = float(right), float(left)
                if fr == 0:
                    if fl == 0: return float('nan')
                    return float('inf') if fl > 0 else float('-inf')
                return fl / fr
            elif op == '%':
                return float('nan') if float(right) == 0 else float(left) % float(right)
            elif op == '==': return left == right
            elif op == '===': return type(left) == type(right) and left == right
            elif op == '!=': return left != right
            elif op == '!==': return type(left) != type(right) or left != right
            elif op == '<': return float(left) < float(right)
            elif op == '<=': return float(left) <= float(right)
            elif op == '>': return float(left) > float(right)
            elif op == '>=': return float(left) >= float(right)
            elif op == '|': return self._to_int32(left) | self._to_int32(right)
            elif op == '&': return self._to_int32(left) & self._to_int32(right)
            elif op == '^': return self._to_int32(left) ^ self._to_int32(right)
            elif op == '<<': return self._to_int32(left) << (self._to_uint32(right) & 0x1F)
            elif op == '>>': return self._to_int32(left) >> (self._to_uint32(right) & 0x1F)
            elif op == '>>>': return self._to_uint32(left) >> (self._to_uint32(right) & 0x1F)
        except: pass
        return UNRESOLVED

    def transform(self, source_code: str, approved: List[Dict[str, Any]]) -> str:
        replacements = []
        for l in approved:
            if not l.get("apply", False): continue
            rng = l["range"]
            replacements.append((rng[0], rng[1], str(l["resolved_value"])))
            
        # Prioritize largest overarching nodes to prevent partial inner string injections
        replacements.sort(key=lambda x: (x[0], x[1]), reverse=True)
        
        res = list(source_code)
        last_idx = float('inf')
        for start, end, text in replacements:
            if end <= last_idx:
                res[start:end] = list(text)
                last_idx = start
                
        return "".join(res)
