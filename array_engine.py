import esprima
import json
from typing import Dict, Any, List, Tuple

class ArrayAnalyzer:
    """Advanced String Array Deobfuscation & Reconstruction Engine."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.source_code = ""
        self.arrays = {}         # name -> { elements: [], range: [], is_rotated: bool }
        self.accessors = {}      # name -> { array_name: str, param_idx: int }
        self.lookups = []        # list of { original_expression, resolved_value, range, confidence }
        self.stats = {
            "total_arrays": 0,
            "total_entries": 0,
            "accessor_functions": 0,
            "resolved_lookups": 0,
            "unresolved_lookups": 0,
            "rotation_patterns": 0
        }
        self.replacements = []

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
            
            # Pass 1: Find String Arrays
            self._find_arrays(tree)
            
            # Pass 2: Find Rotations (push/shift mutations)
            self._find_rotations(tree)
            
            # Pass 3: Find Accessor Functions
            self._find_accessors(tree)
            
            # Pass 4: Resolve Lookups
            self._find_lookups(tree)

            # Generate Report Stats
            self.stats["total_arrays"] = len(self.arrays)
            self.stats["total_entries"] = sum(len(a["elements"]) for a in self.arrays.values())
            self.stats["accessor_functions"] = len(self.accessors)
            self.stats["rotation_patterns"] = sum(1 for a in self.arrays.values() if a["is_rotated"])

            return {
                "status": "success",
                "arrays": self.arrays,
                "accessors": self.accessors,
                "lookups": self.lookups,
                "stats": self.stats
            }
        except Exception as e:
            return {"status": "error", "message": f"Array Engine Error: {str(e)}"}

    def _find_arrays(self, node: Any):
        if not node or not hasattr(node, 'type'): return
        if node.type == 'VariableDeclarator' and node.id.type == 'Identifier':
            if getattr(node, 'init', None) and node.init.type == 'ArrayExpression':
                elements = getattr(node.init, 'elements', [])
                # Ensure it's mostly a string array
                str_elements = [e for e in elements if e and e.type == 'Literal' and isinstance(getattr(e, 'value', None), str)]
                if len(str_elements) > 3 and len(str_elements) >= len(elements) * 0.8:
                    vals = [e.value if (e and e.type == 'Literal') else None for e in elements]
                    self.arrays[node.id.name] = {
                        "elements": vals,
                        "range": node.init.range,
                        "is_rotated": False
                    }
        
        for key, val in vars(node).items():
            if key in ['type', 'loc', 'range', 'parent']: continue
            if isinstance(val, list):
                for item in val: self._find_arrays(item)
            elif hasattr(val, 'type'):
                self._find_arrays(val)

    def _find_rotations(self, node: Any):
        if not node or not hasattr(node, 'type'): return
        
        if node.type == 'CallExpression' and node.callee.type == 'MemberExpression':
            obj = node.callee.object
            prop = node.callee.property
            if obj.type == 'Identifier' and obj.name in self.arrays:
                if not getattr(node.callee, 'computed', False) and prop.type == 'Identifier':
                    if prop.name in ['push', 'shift', 'reverse']:
                        self.arrays[obj.name]["is_rotated"] = True
                        
        for key, val in vars(node).items():
            if key in ['type', 'loc', 'range', 'parent']: continue
            if isinstance(val, list):
                for item in val: self._find_rotations(item)
            elif hasattr(val, 'type'):
                self._find_rotations(val)

    def _find_accessors(self, node: Any):
        if not node or not hasattr(node, 'type'): return
        if node.type == 'FunctionDeclaration' and getattr(node, 'id', None) and getattr(node, 'body', None):
            func_name = node.id.name
            params = [p.name for p in getattr(node, 'params', []) if p.type == 'Identifier']
            if params:
                # Look for simple `return arr[param]` or `return arr[param - offset]`
                for stmt in getattr(node.body, 'body', []):
                    if stmt.type == 'ReturnStatement' and getattr(stmt, 'argument', None):
                        arg = stmt.argument
                        if arg.type == 'MemberExpression' and getattr(arg, 'computed', False):
                            if arg.object.type == 'Identifier' and arg.object.name in self.arrays:
                                # Statically mapping function to the array
                                self.accessors[func_name] = {
                                    "array_name": arg.object.name,
                                    "param_idx": 0 # simplified assumption for primary index param
                                }
                                
        for key, val in vars(node).items():
            if key in ['type', 'loc', 'range', 'parent']: continue
            if isinstance(val, list):
                for item in val: self._find_accessors(item)
            elif hasattr(val, 'type'):
                self._find_accessors(val)

    def _find_lookups(self, node: Any):
        if not node or not hasattr(node, 'type'): return

        # 1. Direct Array Indexing (e.g. _0x1234[0])
        if node.type == 'MemberExpression' and getattr(node, 'computed', False):
            if node.object.type == 'Identifier' and node.object.name in self.arrays:
                if node.property.type == 'Literal' and isinstance(node.property.value, (int, float)):
                    idx = int(node.property.value)
                    self._queue_lookup(node, node.object.name, idx)
                else:
                    self.stats["unresolved_lookups"] += 1

        # 2. Function-based Indexing (e.g. getString(0))
        elif node.type == 'CallExpression' and node.callee.type == 'Identifier':
            if node.callee.name in self.accessors:
                acc_info = self.accessors[node.callee.name]
                if len(node.arguments) > 0 and node.arguments[acc_info["param_idx"]].type == 'Literal':
                    val = node.arguments[acc_info["param_idx"]].value
                    if isinstance(val, (int, float)):
                        self._queue_lookup(node, acc_info["array_name"], int(val))
                    else:
                        self.stats["unresolved_lookups"] += 1

        for key, val in vars(node).items():
            if key in ['type', 'loc', 'range', 'parent']: continue
            if isinstance(val, list):
                for item in val: self._find_lookups(item)
            elif hasattr(val, 'type'):
                self._find_lookups(val)

    def _queue_lookup(self, node: Any, array_name: str, index: int):
        arr_info = self.arrays[array_name]
        elements = arr_info["elements"]
        is_rotated = arr_info["is_rotated"]
        
        raw_expr = self.source_code[node.range[0]:node.range[1]]
        
        # If the array was mutated dynamically, static lookup might be wrong
        confidence = "Low (Array Rotated)" if is_rotated else "High (Static)"
        
        if 0 <= index < len(elements) and elements[index] is not None:
            resolved_val = elements[index]
            self.lookups.append({
                "original_expression": raw_expr,
                "resolved_value": resolved_val,
                "range": node.range,
                "confidence": confidence,
                "array": array_name,
                "index": index
            })
            self.stats["resolved_lookups"] += 1
        else:
            self.stats["unresolved_lookups"] += 1

    def transform(self, source_code: str, approved_lookups: List[Dict[str, Any]]) -> str:
        replacements = []
        for l in approved_lookups:
            if not l.get("apply", False): continue
            
            val = l["resolved_value"]
            rng = l["range"]
            # Safely encode the resolved string
            safe_str = json.dumps(val, ensure_ascii=False)
            replacements.append((rng[0], rng[1], safe_str))
            
        # Sort right-to-left to prevent index shifting
        replacements.sort(key=lambda x: x[0], reverse=True)
        
        res = list(source_code)
        for rep in replacements:
            start, end, text = rep
            res[start:end] = list(text)
            
        return "".join(res)
