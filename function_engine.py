import esprima
import json
from typing import Dict, Any, List, Tuple

class FunctionAnalyzer:
    """Advanced JavaScript Function Analysis & Wrapper Deobfuscation Engine."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.source_code = ""
        self.functions = {}       # func_id -> info
        self.call_edges = []      # (caller_name, callee_name)
        self.iifes = []           # list of IIFE info dicts
        self.replacements = []    # Safe inlining queues
        self.stats = {
            "total_functions": 0,
            "named_functions": 0,
            "anonymous_functions": 0,
            "arrow_functions": 0,
            "iifes": 0,
            "wrappers_detected": 0
        }
        self._func_counter = 0

    def _get_uid(self) -> str:
        self._func_counter += 1
        return f"func_{self._func_counter}"

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
            
            # Pass 1: Map all functions & Classify
            self._walk_functions(tree)
            
            # Pass 2: Map Call Graph & queue simplifications
            self._walk_calls(tree)

            return {
                "status": "success",
                "functions": self.functions,
                "iifes": self.iifes,
                "call_graph_dot": self._generate_dot(),
                "simplifications": self.replacements,
                "stats": self.stats
            }
        except Exception as e:
            return {"status": "error", "message": f"Function Engine Error: {str(e)}"}

    def _walk_functions(self, node: Any, current_func_name: str = "global"):
        if not node or not hasattr(node, 'type'): return

        is_func = node.type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']
        next_func_name = current_func_name

        if is_func:
            self.stats["total_functions"] += 1
            if node.type == 'ArrowFunctionExpression': self.stats["arrow_functions"] += 1
            
            name = getattr(node.id, 'name', None) if getattr(node, 'id', None) else None
            is_anonymous = name is None
            
            if is_anonymous: 
                self.stats["anonymous_functions"] += 1
                name = self._get_uid() # assign internal name for tracking
            else:
                self.stats["named_functions"] += 1
                
            next_func_name = name
            
            # IIFE Detection
            is_iife = False
            if hasattr(node, 'parent') and node.parent.type == 'CallExpression' and node.parent.callee == node:
                is_iife = True
                self.stats["iifes"] += 1
                self.iifes.append({
                    "name": name,
                    "range": node.parent.range,
                    "params": len(getattr(node, 'params', [])),
                    "args": len(getattr(node.parent, 'arguments', []))
                })

            # Body Classification (Wrapper detection)
            classification = "Utility/Standard"
            simplification_target = None
            
            body = getattr(node, 'body', None)
            if body:
                if body.type == 'BlockStatement':
                    stmts = getattr(body, 'body', [])
                    if len(stmts) == 1 and stmts[0].type == 'ReturnStatement':
                        ret_arg = getattr(stmts[0], 'argument', None)
                        if ret_arg:
                            if ret_arg.type == 'Literal':
                                classification = "Constant-Return Wrapper"
                                simplification_target = {"type": "constant", "value": ret_arg.value, "raw": self.source_code[ret_arg.range[0]:ret_arg.range[1]]}
                                self.stats["wrappers_detected"] += 1
                            elif ret_arg.type == 'CallExpression' and getattr(ret_arg.callee, 'type', '') == 'Identifier':
                                # Basic forwarding check
                                classification = "Forwarding Wrapper"
                                simplification_target = {"type": "forward", "target_func": ret_arg.callee.name}
                                self.stats["wrappers_detected"] += 1
                elif node.type == 'ArrowFunctionExpression' and body.type != 'BlockStatement':
                    # Implicit return arrow function e.g. x => 5
                    if body.type == 'Literal':
                        classification = "Constant-Return Wrapper"
                        simplification_target = {"type": "constant", "value": body.value, "raw": self.source_code[body.range[0]:body.range[1]]}
                        self.stats["wrappers_detected"] += 1

            self.functions[name] = {
                "type": node.type,
                "is_anonymous": is_anonymous,
                "is_iife": is_iife,
                "classification": classification,
                "simplification_target": simplification_target,
                "parent_func": current_func_name,
                "range": node.range
            }

        # Recurse
        for key, val in vars(node).items():
            if key in ['type', 'loc', 'range', 'parent']: continue
            if isinstance(val, list):
                for item in val: self._walk_functions(item, next_func_name)
            elif hasattr(val, 'type'):
                self._walk_functions(val, next_func_name)

    def _walk_calls(self, node: Any, current_func_name: str = "global"):
        if not node or not hasattr(node, 'type'): return
        
        next_func_name = current_func_name
        if node.type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']:
            if getattr(node, 'id', None): next_func_name = node.id.name
            
        if node.type == 'CallExpression' and getattr(node.callee, 'type', '') == 'Identifier':
            callee_name = node.callee.name
            self.call_edges.append((current_func_name, callee_name))
            
            # Check for Safe Simplification (Inlining wrappers)
            if callee_name in self.functions:
                target = self.functions[callee_name].get("simplification_target")
                if target:
                    raw_expr = self.source_code[node.range[0]:node.range[1]]
                    if target["type"] == "constant":
                        self.replacements.append({
                            "original_expression": raw_expr,
                            "resolved_value": target["raw"],
                            "type": "Constant Inline",
                            "range": node.range,
                            "target_func": callee_name
                        })
                    elif target["type"] == "forward":
                        # If a forwarding wrapper is called: a(1) -> b(1)
                        # We safely replace the callee identifier in the AST
                        callee_range = node.callee.range
                        self.replacements.append({
                            "original_expression": raw_expr,
                            "resolved_value": f"Forward to {target['target_func']}()",
                            "type": "Forwarding Inline",
                            "range": callee_range,
                            "replacement_str": target["target_func"],
                            "target_func": callee_name
                        })

        for key, val in vars(node).items():
            if key in ['type', 'loc', 'range', 'parent']: continue
            if isinstance(val, list):
                for item in val: self._walk_calls(item, next_func_name)
            elif hasattr(val, 'type'):
                self._walk_calls(val, next_func_name)

    def _generate_dot(self) -> str:
        dot = [
            'digraph CallGraph {',
            '  rankdir=LR;',
            '  node [shape=box, style=filled, color="#2B2B2B", fontcolor="#E0E0E0", fontname="Courier New"];',
            '  edge [color="#666666"];',
            '  bgcolor="#0E1117";'
        ]
        unique_edges = set(self.call_edges)
        for caller, callee in unique_edges:
            # Skip global to global noise if minimal
            if caller == "global" and callee not in self.functions: continue
            
            c1 = caller if caller != "global" else "Global Scope"
            c2 = callee
            dot.append(f'  "{c1}" -> "{c2}";')
            
        dot.append('}')
        return "\n".join(dot)

    def transform(self, source_code: str, approved_simplifications: List[Dict[str, Any]]) -> str:
        replacements = []
        for l in approved_simplifications:
            if not l.get("apply", False): continue
            
            rng = l["range"]
            # Constant Inline uses 'resolved_value', Forwarding uses 'replacement_str'
            new_text = l.get("replacement_str", l.get("resolved_value"))
            replacements.append((rng[0], rng[1], new_text))
            
        # Sort right-to-left to prevent index shifting
        replacements.sort(key=lambda x: x[0], reverse=True)
        
        res = list(source_code)
        for rep in replacements:
            start, end, text = rep
            res[start:end] = list(text)
            
        return "".join(res)
