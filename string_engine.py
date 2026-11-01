import esprima
import json
from typing import Dict, Any, List, Tuple

class StringAnalyzer:
    """Handles AST-based JavaScript string detection, decoding, and static concatenation."""
    
    def __init__(self):
        self.reset()

    def reset(self):
        self.source_code = ""
        self.strings_detected = []
        self.concatenations = []
        self.string_arrays = []
        self.replacements = [] # list of (start, end, replacement_string, reason)
        self.stats = {
            "total_strings": 0,
            "unique_strings": 0,
            "encoded_strings": 0,
            "decoded_strings": 0,
            "failed_decodings": 0,
            "concatenations_folded": 0,
            "string_arrays_detected": 0
        }

    def analyze(self, source_code: str) -> Dict[str, Any]:
        """Parses source to analyze and queue transformations for strings."""
        self.reset()
        if not source_code or not source_code.strip():
            return {"status": "error", "message": "Empty input"}
            
        if len(source_code) > 1024 * 1024:
            return {"status": "error", "message": "File exceeds 1MB limit for safe string analysis."}

        self.source_code = source_code
        try:
            tree = esprima.parseScript(source_code, {"range": True, "tolerant": True})
            self._walk(tree)
            self._analyze_arrays(tree)
            
            # Compute stats
            unique_vals = set(s['value'] for s in self.strings_detected if s.get('value'))
            self.stats["total_strings"] = len(self.strings_detected)
            self.stats["unique_strings"] = len(unique_vals)
            
            return {
                "status": "success",
                "stats": self.stats,
                "strings": self.strings_detected,
                "concatenations": self.concatenations,
                "arrays": self.string_arrays
            }
        except esprima.Error as e:
            return {"status": "error", "message": f"String Engine AST Error: {str(e)}"}
        except Exception as e:
            return {"status": "error", "message": f"String Engine Error: {str(e)}"}

    def _walk(self, node: Any):
        if not node or not hasattr(node, 'type'): return
        
        # 1. Analyze String Literals
        if node.type == 'Literal' and isinstance(getattr(node, 'value', None), str):
            raw = self.source_code[node.range[0]:node.range[1]]
            is_encoded = '\\' in raw and raw not in ['"\\""', "'\\''", '"\\\\"', "'\\\\'"]
            
            self.strings_detected.append({
                "value": node.value,
                "raw": raw,
                "is_encoded": is_encoded,
                "range": node.range
            })
            
            if is_encoded:
                self.stats["encoded_strings"] += 1
                try:
                    # esprima safely decodes the value natively. 
                    # We ensure_ascii=False to preserve readable Unicode.
                    clean_str = json.dumps(node.value, ensure_ascii=False)
                    if clean_str != raw:
                        self.replacements.append((node.range[0], node.range[1], clean_str, "decoded_escape"))
                        self.stats["decoded_strings"] += 1
                except Exception:
                    self.stats["failed_decodings"] += 1

        # 2. Analyze Concatenations (Only statically provable ones)
        if node.type == 'BinaryExpression' and node.operator == '+':
            val, rng = self._evaluate_concat(node)
            if val is not None and getattr(node, '_concat_processed', False) is False:
                self._mark_processed(node) # Prevent children from being processed again
                raw_expr = self.source_code[rng[0]:rng[1]]
                clean_str = json.dumps(val, ensure_ascii=False)
                
                self.concatenations.append({
                    "result": val,
                    "raw_expression": raw_expr,
                    "range": rng
                })
                self.replacements.append((rng[0], rng[1], clean_str, "folded_concat"))
                self.stats["concatenations_folded"] += 1

        # Recurse
        for key, val in vars(node).items():
            if key in ['type', 'range', 'loc']: continue
            if isinstance(val, list):
                for item in val: self._walk(item)
            elif hasattr(val, 'type'):
                self._walk(val)

    def _evaluate_concat(self, node: Any) -> Tuple[str, List[int]]:
        """Recursively checks if a binary expression consists entirely of static strings."""
        if getattr(node, 'type', None) == 'Literal' and isinstance(getattr(node, 'value', None), str):
            return node.value, node.range
        if getattr(node, 'type', None) == 'BinaryExpression' and getattr(node, 'operator', None) == '+':
            l_val, l_rng = self._evaluate_concat(node.left)
            r_val, r_rng = self._evaluate_concat(node.right)
            if l_val is not None and r_val is not None:
                return l_val + r_val, [l_rng[0], r_rng[1]]
        return None, None
        
    def _mark_processed(self, node: Any):
        """Marks nodes to avoid double-processing overlapping strings."""
        node._concat_processed = True
        if getattr(node, 'type', None) == 'BinaryExpression' and getattr(node, 'operator', None) == '+':
            self._mark_processed(node.left)
            self._mark_processed(node.right)

    def _analyze_arrays(self, tree: Any):
        """Finds arrays consisting primarily of string literals (common lookup tables)."""
        def walk_arrays(node):
            if not node or not hasattr(node, 'type'): return
            if node.type == 'ArrayExpression':
                elements = getattr(node, 'elements', [])
                # Check if it's a dense array of strings
                if elements and all(getattr(el, 'type', None) == 'Literal' and isinstance(getattr(el, 'value', None), str) for el in elements):
                    raw = self.source_code[node.range[0]:node.range[1]]
                    vals = [el.value for el in elements]
                    if len(vals) > 2:
                        self.string_arrays.append({
                            "size": len(vals),
                            "preview": vals[:5],
                            "raw": raw[:100] + ("..." if len(raw) > 100 else ""),
                            "range": node.range
                        })
                        self.stats["string_arrays_detected"] += 1
            
            for key, val in vars(node).items():
                if key in ['type', 'range', 'loc']: continue
                if isinstance(val, list):
                    for item in val: walk_arrays(item)
                elif hasattr(val, 'type'):
                    walk_arrays(val)
        walk_arrays(tree)

    def transform(self) -> str:
        """Applies statically proven string replacements from right to left safely."""
        unique_replacements = list(set(self.replacements))
        filtered = []
        
        # Resolve overlaps (e.g., encoded strings inside a concatenation we are folding)
        # We keep the largest bounding node (the parent concatenation).
        for r in unique_replacements:
            is_inside = False
            for other in unique_replacements:
                if r == other: continue
                # if 'r' is completely enveloped by 'other'
                if other[0] <= r[0] and other[1] >= r[1] and (other[1]-other[0] > r[1]-r[0]):
                    is_inside = True
                    break
            if not is_inside:
                filtered.append(r)
                
        # Sort right-to-left to prevent range index shifting during modification
        filtered.sort(key=lambda x: x[0], reverse=True)
        
        res = list(self.source_code)
        for rep in filtered:
            start, end, new_str, reason = rep
            res[start:end] = list(new_str)
            
        return "".join(res)
