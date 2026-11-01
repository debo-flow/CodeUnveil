import esprima
from typing import Dict, Any, List, Tuple

class CFGAnalyzer:
    """Advanced JavaScript Control Flow Analysis and Reconstruction Engine."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.source_code = ""
        self.stats = {
            "basic_blocks": 0,
            "conditional_branches": 0,
            "loops": 0,
            "switch_statements": 0,
            "simplifications": 0,
            "unreachable_removed": 0
        }
        self.cff_detected = False
        self.state_variables = set()
        self.transitions = []
        self.replacements = []  # (start, end, new_string)
        self.dot_nodes = []
        self.dot_edges = []
        self._node_id_counter = 0

    def _get_id(self) -> str:
        self._node_id_counter += 1
        return f"node_{self._node_id_counter}"

    def analyze(self, source_code: str) -> Dict[str, Any]:
        """Parses AST with ranges to perform CFG structural analysis and simplification."""
        self.reset()
        if not source_code or not source_code.strip():
            return {"status": "error", "message": "Empty input"}
            
        if len(source_code) > 1024 * 1024:
            return {"status": "error", "message": "File exceeds 1MB limit for safe CFG analysis."}

        self.source_code = source_code
        try:
            tree = esprima.parseScript(source_code, {"range": True, "tolerant": True})
            
            # Root CFG node
            root_id = self._get_id()
            self.dot_nodes.append(f'  "{root_id}" [label="Program Entry", shape=oval, fillcolor="#4CAF50", style=filled, fontcolor=white];')
            
            self._walk_cfg(tree, parent_id=root_id)
            self._detect_cff(tree)
            self._simplify_ast(tree)

            return {
                "status": "success",
                "stats": self.stats,
                "cff": {
                    "detected": self.cff_detected,
                    "state_variables": list(self.state_variables),
                    "transitions": self.transitions
                },
                "dot_graph": self._generate_dot()
            }
        except esprima.Error as e:
            return {"status": "error", "message": f"CFG AST Error: {str(e)}"}
        except Exception as e:
             return {"status": "error", "message": f"CFG Engine Error: {str(e)}"}

    def _walk_cfg(self, node: Any, parent_id: str):
        """Recursively builds an abstracted Control Flow Graph structure for visualization."""
        if not node or not hasattr(node, 'type'): return

        current_id = parent_id
        ntype = node.type

        if ntype in ['BlockStatement', 'Program']:
            self.stats["basic_blocks"] += 1
            
        elif ntype in ['IfStatement', 'ConditionalExpression']:
            self.stats["conditional_branches"] += 1
            current_id = self._get_id()
            self.dot_nodes.append(f'  "{current_id}" [label="Branch\\n(If/Cond)", shape=diamond, fillcolor="#FF9800", style=filled];')
            self.dot_edges.append(f'  "{parent_id}" -> "{current_id}";')
            
        elif ntype in ['ForStatement', 'WhileStatement', 'DoWhileStatement', 'ForInStatement', 'ForOfStatement']:
            self.stats["loops"] += 1
            current_id = self._get_id()
            self.dot_nodes.append(f'  "{current_id}" [label="Loop\\n({ntype.replace("Statement","")})", shape=hexagon, fillcolor="#2196F3", style=filled, fontcolor=white];')
            self.dot_edges.append(f'  "{parent_id}" -> "{current_id}";')
            
        elif ntype == 'SwitchStatement':
            self.stats["switch_statements"] += 1
            current_id = self._get_id()
            self.dot_nodes.append(f'  "{current_id}" [label="Switch", shape=diamond, fillcolor="#9C27B0", style=filled, fontcolor=white];')
            self.dot_edges.append(f'  "{parent_id}" -> "{current_id}";')

        # Recurse
        for key, val in vars(node).items():
            if key in ['type', 'range', 'loc']: continue
            if isinstance(val, list):
                for item in val: self._walk_cfg(item, current_id)
            elif hasattr(val, 'type'):
                self._walk_cfg(val, current_id)

    def _detect_cff(self, node: Any):
        """Static pattern matching for Control Flow Flattening (while/switch dispatchers)."""
        def walk(n):
            if not n or not hasattr(n, 'type'): return
            
            # Look for While loops
            if n.type == 'WhileStatement' and hasattr(n, 'body'):
                body = n.body
                # Look for a block containing a switch
                if body.type == 'BlockStatement' and getattr(body, 'body', []):
                    for stmt in body.body:
                        if stmt.type == 'SwitchStatement' and hasattr(stmt, 'discriminant'):
                            discrim = stmt.discriminant
                            # Identifier is the State Variable (e.g. _0x123)
                            if discrim.type == 'Identifier':
                                state_var = discrim.name
                                self.state_variables.add(state_var)
                                self.cff_detected = True
                                
                                # Analyze State Transitions inside the cases
                                for case in getattr(stmt, 'cases', []):
                                    case_val = getattr(case.test, 'value', 'default') if case.test else 'default'
                                    transitions_to = []
                                    # Look for Assignment to the state variable
                                    for c_stmt in getattr(case, 'consequent', []):
                                        self._find_assignments(c_stmt, state_var, transitions_to)
                                    
                                    if transitions_to:
                                        self.transitions.append({
                                            "Case/State": str(case_val),
                                            "Transitions To": list(set(transitions_to))
                                        })

            for key, val in vars(n).items():
                if key in ['type', 'range', 'loc']: continue
                if isinstance(val, list):
                    for item in val: walk(item)
                elif hasattr(val, 'type'):
                    walk(val)
        walk(node)

    def _find_assignments(self, node: Any, state_var: str, results: List[str]):
        """Finds static assignments to the identified state variable (e.g. state = 5)."""
        if not node or not hasattr(node, 'type'): return
        
        if node.type == 'AssignmentExpression' and getattr(node.left, 'name', '') == state_var:
            if getattr(node.right, 'type', '') == 'Literal':
                results.append(str(node.right.value))
            else:
                results.append("[Dynamic/Unresolved]")
                
        for key, val in vars(node).items():
            if key in ['type', 'range', 'loc']: continue
            if isinstance(val, list):
                for item in val: self._find_assignments(item, state_var, results)
            elif hasattr(val, 'type'):
                self._find_assignments(val, state_var, results)

    def _simplify_ast(self, node: Any):
        """Safely identifies unreachable branches or constant conditionals for removal."""
        def walk(n):
            if not n or not hasattr(n, 'type'): return
            
            # Constant Condition Evaluation
            if n.type == 'IfStatement' and n.test.type == 'Literal':
                val = n.test.value
                # Conservative Truthy check
                is_truthy = val in [True, 1] or (isinstance(val, str) and len(val) > 0)
                # Conservative Falsy check
                is_falsy = val in [False, 0, None, ""]
                
                if is_truthy:
                    # Keep consequent, drop alternate
                    cons_text = self.source_code[n.consequent.range[0]:n.consequent.range[1]]
                    self.replacements.append((n.range[0], n.range[1], cons_text, "Dead alternate branch removed"))
                    self.stats["simplifications"] += 1
                    self.stats["unreachable_removed"] += 1
                elif is_falsy:
                    # Keep alternate, drop consequent
                    alt_text = self.source_code[n.alternate.range[0]:n.alternate.range[1]] if n.alternate else ""
                    self.replacements.append((n.range[0], n.range[1], alt_text, "Dead consequent branch removed"))
                    self.stats["simplifications"] += 1
                    self.stats["unreachable_removed"] += 1
                    
            for key, val in vars(n).items():
                if key in ['type', 'range', 'loc']: continue
                if isinstance(val, list):
                    for item in val: walk(item)
                elif hasattr(val, 'type'):
                    walk(val)
        walk(node)

    def transform(self) -> str:
        """Applies conservative static simplifications right-to-left."""
        # Resolve overlaps by keeping largest bounds and sorting right-to-left
        unique_replacements = list(set(self.replacements))
        filtered = []
        for r in unique_replacements:
            is_inside = False
            for other in unique_replacements:
                if r == other: continue
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

    def _generate_dot(self) -> str:
        """Compiles the Abstracted CFG DOT string."""
        dot = [
            'digraph CFG {',
            '  rankdir=TB;',
            '  node [shape=box, style=filled, color="#2B2B2B", fontcolor="#E0E0E0", fontname="Courier New"];',
            '  edge [color="#666666"];',
            '  bgcolor="#0E1117";'
        ]
        dot.extend(self.dot_nodes)
        dot.extend(self.dot_edges)
        dot.append('}')
        return "\n".join(dot)
