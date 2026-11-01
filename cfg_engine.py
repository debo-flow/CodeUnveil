import esprima
import json
from typing import Dict, Any, List, Tuple

class CFGAnalyzer:
    """Advanced Control Flow Graph, State Transition, and Deflattening Engine."""

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
            "unreachable_removed": 0,
            "cfg_edges": 0,
            "dispatcher_states": 0
        }
        
        # M14: Advanced Control Flow Flattening (CFF) Data
        self.cff = {
            "detected": False,
            "state_variables": set(),
            "initial_states": {}, # var_name -> initial literal value
            "states": {},         # var_name -> { case_val -> { 'payload_ranges': [], 'next_states': [] } }
            "transitions": [],
            "reconstruction_queue": [] # Safe unrolled payloads
        }
        
        self.replacements = []  # General simplifications
        self.dot_nodes = []
        self.dot_edges = []
        self.stg_nodes = []
        self.stg_edges = []
        self._node_id_counter = 0

    def _get_id(self) -> str:
        self._node_id_counter += 1
        return f"node_{self._node_id_counter}"

    def analyze(self, source_code: str) -> Dict[str, Any]:
        """Parses AST with ranges to perform CFG structural analysis and CFF deflattening."""
        self.reset()
        if not source_code or not source_code.strip():
            return {"status": "error", "message": "Empty input"}
            
        if len(source_code) > 1024 * 1024 * 2: # Expanded limit for heavy CFF
            return {"status": "error", "message": "File exceeds 2MB limit for safe CFG analysis."}

        self.source_code = source_code
        try:
            tree = esprima.parseScript(source_code, {"range": True, "tolerant": True})
            
            # Root CFG node
            root_id = self._get_id()
            self.dot_nodes.append(f'  "{root_id}" [label="Program Entry", shape=oval, fillcolor="#4CAF50", style=filled, fontcolor=white];')
            
            # 1. Base CFG Mapping
            self._walk_cfg(tree, parent_id=root_id)
            
            # 2. Advanced Control Flow Flattening (CFF) Detection & STG Building
            self._detect_advanced_cff(tree)
            
            # 3. Static Code Deflattening Analysis
            self._attempt_deflattening()
            
            # 4. Safe Branch Simplification (M6)
            self._simplify_ast(tree)

            return {
                "status": "success",
                "stats": self.stats,
                "cff": {
                    "detected": self.cff["detected"],
                    "state_variables": list(self.cff["state_variables"]),
                    "transitions": self.cff["transitions"],
                    "reconstruction_queue": self.cff["reconstruction_queue"],
                    "states": self.cff["states"]
                },
                "dot_graph": self._generate_dot(self.dot_nodes, self.dot_edges, title="CFG"),
                "stg_graph": self._generate_dot(self.stg_nodes, self.stg_edges, title="STG")
            }
        except esprima.Error as e:
            return {"status": "error", "message": f"CFG AST Error: {str(e)}"}
        except Exception as e:
             return {"status": "error", "message": f"CFG Engine Error: {str(e)}"}

    def _walk_cfg(self, node: Any, parent_id: str):
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
            self.stats["cfg_edges"] += 1
            
        elif ntype in ['ForStatement', 'WhileStatement', 'DoWhileStatement', 'ForInStatement', 'ForOfStatement']:
            self.stats["loops"] += 1
            current_id = self._get_id()
            self.dot_nodes.append(f'  "{current_id}" [label="Loop\\n({ntype.replace("Statement","")})", shape=hexagon, fillcolor="#2196F3", style=filled, fontcolor=white];')
            self.dot_edges.append(f'  "{parent_id}" -> "{current_id}";')
            self.stats["cfg_edges"] += 1
            
        elif ntype == 'SwitchStatement':
            self.stats["switch_statements"] += 1
            current_id = self._get_id()
            self.dot_nodes.append(f'  "{current_id}" [label="Switch", shape=diamond, fillcolor="#9C27B0", style=filled, fontcolor=white];')
            self.dot_edges.append(f'  "{parent_id}" -> "{current_id}";')
            self.stats["cfg_edges"] += 1

        for key, val in vars(node).items():
            if key in ['type', 'range', 'loc']: continue
            if isinstance(val, list):
                for item in val: self._walk_cfg(item, current_id)
            elif hasattr(val, 'type'):
                self._walk_cfg(val, current_id)

    def _detect_advanced_cff(self, node: Any):
        """Advanced M14 Pattern matching for State-Machine Dispatchers."""
        # Pre-scan for state initializations (e.g., `var _0xstate = 1;` or `var _0xstate = '1|3|2'.split('|');`)
        initial_vars = {}
        
        def pre_scan(n):
            if not n or not hasattr(n, 'type'): return
            if n.type == 'VariableDeclarator' and n.id.type == 'Identifier' and getattr(n, 'init', None):
                if n.init.type == 'Literal':
                    initial_vars[n.id.name] = n.init.value
                elif n.init.type == 'CallExpression' and getattr(n.init.callee, 'property', None) and n.init.callee.property.name == 'split':
                    # Common obfuscator.io pattern: '1|3|2'.split('|')
                    if getattr(n.init.callee.object, 'type', '') == 'Literal':
                        initial_vars[n.id.name] = n.init.callee.object.value
            for k, v in vars(n).items():
                if k in ['type', 'range', 'loc']: continue
                if isinstance(v, list):
                    for i in v: pre_scan(i)
                elif hasattr(v, 'type'): pre_scan(v)
        pre_scan(node)

        # Dispatcher analysis
        def walk(n):
            if not n or not hasattr(n, 'type'): return
            
            if n.type == 'WhileStatement' and hasattr(n, 'body'):
                body = n.body
                if body.type == 'BlockStatement' and getattr(body, 'body', []):
                    for stmt in body.body:
                        if stmt.type == 'SwitchStatement' and hasattr(stmt, 'discriminant'):
                            discrim = stmt.discriminant
                            
                            # Standard Identifier state var OR MemberExpression array state (e.g. state_arr[state_idx++])
                            state_var = None
                            if discrim.type == 'Identifier':
                                state_var = discrim.name
                            elif discrim.type == 'MemberExpression' and discrim.object.type == 'Identifier':
                                state_var = discrim.object.name
                                
                            if state_var:
                                self.cff["detected"] = True
                                self.cff["state_variables"].add(state_var)
                                if state_var in initial_vars:
                                    self.cff["initial_states"][state_var] = initial_vars[state_var]
                                    
                                self.cff["states"][state_var] = {}
                                
                                # Map State Transition Graph (STG)
                                for case in getattr(stmt, 'cases', []):
                                    case_val = getattr(case.test, 'value', 'default') if getattr(case, 'test', None) else 'default'
                                    transitions_to = []
                                    payload_ranges = []
                                    
                                    for c_stmt in getattr(case, 'consequent', []):
                                        if c_stmt.type == 'ExpressionStatement' and c_stmt.expression.type == 'AssignmentExpression':
                                            if getattr(c_stmt.expression.left, 'name', '') == state_var:
                                                if getattr(c_stmt.expression.right, 'type', '') == 'Literal':
                                                    transitions_to.append(c_stmt.expression.right.value)
                                                continue # It's a transition, not payload
                                        
                                        if c_stmt.type in ['BreakStatement', 'ContinueStatement']:
                                            continue
                                            
                                        # Standard payload
                                        payload_ranges.append(c_stmt.range)

                                    self.cff["states"][state_var][str(case_val)] = {
                                        "payload_ranges": payload_ranges,
                                        "next_states": transitions_to
                                    }
                                    
                                    self.stats["dispatcher_states"] += 1
                                    self.stg_nodes.append(f'  "{case_val}" [label="State: {case_val}", shape=box];')
                                    
                                    for n_state in transitions_to:
                                        self.stg_edges.append(f'  "{case_val}" -> "{n_state}";')
                                        self.cff["transitions"].append({"Case/State": str(case_val), "Transitions To": str(n_state)})
                                        
                                # Track the range of the While loop to queue replacement
                                self.cff["states"][state_var]["_while_range"] = n.range

            for key, val in vars(n).items():
                if key in ['type', 'range', 'loc']: continue
                if isinstance(val, list):
                    for item in val: walk(item)
                elif hasattr(val, 'type'):
                    walk(val)
        walk(node)

    def _attempt_deflattening(self):
        """Statically reconstructs the execution order if transitions are deterministic."""
        for state_var, states in self.cff["states"].items():
            init_val = self.cff["initial_states"].get(state_var)
            
            # Handle Array Split Dispatcher (e.g. '1|3|2'.split('|'))
            if isinstance(init_val, str) and '|' in init_val:
                execution_order = init_val.split('|')
                reconstructed_source = ""
                is_safe = True
                
                for step in execution_order:
                    if step not in states:
                        is_safe = False
                        break
                    
                    state_info = states[step]
                    for pr in state_info["payload_ranges"]:
                        reconstructed_source += self.source_code[pr[0]:pr[1]] + "\n"
                        
                if is_safe and "_while_range" in states:
                    self.cff["reconstruction_queue"].append({
                        "state_var": state_var,
                        "type": "Deflatten Array Dispatcher",
                        "original_range": states["_while_range"],
                        "reconstructed_code": reconstructed_source,
                        "confidence": "High"
                    })

            # Handle Simple Linear State Machine (e.g. state = 1 -> state = 2)
            elif init_val is not None:
                current_state = str(init_val)
                visited = set()
                reconstructed_source = ""
                is_safe = True
                
                while current_state and is_safe:
                    if current_state in visited:
                        is_safe = False # Cycle detected, not purely linear
                        break
                    visited.add(current_state)
                    
                    if current_state not in states:
                        break # Terminal or unknown state reached
                        
                    state_info = states[current_state]
                    for pr in state_info["payload_ranges"]:
                        reconstructed_source += self.source_code[pr[0]:pr[1]] + "\n"
                        
                    next_states = state_info["next_states"]
                    if len(next_states) == 1:
                        current_state = str(next_states[0])
                    elif len(next_states) == 0:
                        current_state = None # Terminal
                    else:
                        is_safe = False # Conditional logic inside dispatcher, requires symbolic exec
                        
                if is_safe and len(visited) > 1 and "_while_range" in states:
                    self.cff["reconstruction_queue"].append({
                        "state_var": state_var,
                        "type": "Deflatten Linear Dispatcher",
                        "original_range": states["_while_range"],
                        "reconstructed_code": reconstructed_source,
                        "confidence": "High"
                    })

    def _simplify_ast(self, node: Any):
        """M6 Legacy safe branch identification."""
        def walk(n):
            if not n or not hasattr(n, 'type'): return
            if n.type == 'IfStatement' and n.test.type == 'Literal':
                val = n.test.value
                is_truthy = val in [True, 1] or (isinstance(val, str) and len(val) > 0)
                is_falsy = val in [False, 0, None, ""]
                
                if is_truthy:
                    cons_text = self.source_code[n.consequent.range[0]:n.consequent.range[1]]
                    self.replacements.append((n.range[0], n.range[1], cons_text, "Dead alternate branch removed"))
                    self.stats["simplifications"] += 1
                    self.stats["unreachable_removed"] += 1
                elif is_falsy:
                    alt_text = self.source_code[n.alternate.range[0]:n.alternate.range[1]] if getattr(n, 'alternate', None) else ""
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

    def transform(self, source_code: str, approved_deflatten: List[Dict[str, Any]] = None) -> str:
        """Applies M6 Simplifications AND M14 Deflattening Queues."""
        replacements = list(self.replacements) # (start, end, new_str, reason)
        
        if approved_deflatten:
            for d in approved_deflatten:
                if d.get("apply"):
                    rng = d["original_range"]
                    replacements.append((rng[0], rng[1], d["reconstructed_code"], d["type"]))

        unique_replacements = list(set(replacements))
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
        
        res = list(source_code)
        for rep in filtered:
            start, end, new_str, _ = rep
            res[start:end] = list(new_str)
            
        return "".join(res)

    def _generate_dot(self, nodes: List[str], edges: List[str], title="CFG") -> str:
        dot = [
            f'digraph {title} {{',
            '  rankdir=TB;',
            '  node [shape=box, style=filled, color="#2B2B2B", fontcolor="#E0E0E0", fontname="Courier New"];',
            '  edge [color="#666666"];',
            '  bgcolor="#0E1117";'
        ]
        dot.extend(nodes)
        dot.extend(edges)
        dot.append('}')
        return "\n".join(dot)
