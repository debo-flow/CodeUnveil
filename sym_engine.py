import esprima
import json
import z3
from typing import Dict, Any, List, Tuple

class SymState:
    def __init__(self, parent=None):
        self.variables = {}
        self.path_conditions = []
        if parent:
            self.variables = dict(parent.variables)
            self.path_conditions = list(parent.path_conditions)

    def clone(self):
        return SymState(self)

    def assign(self, name: str, value: Any):
        self.variables[name] = value

    def get(self, name: str):
        if name in self.variables:
            return self.variables[name]
        # Create a new symbolic variable if undefined in current state
        sym_var = z3.Int(name)
        self.variables[name] = sym_var
        return sym_var

    def add_condition(self, condition):
        self.path_conditions.append(condition)

class SymPath:
    def __init__(self, state: SymState, status: str, location: str, block_name: str):
        self.state = state
        self.status = status # "Feasible", "Infeasible", "Unknown"
        self.location = location
        self.block_name = block_name

class SymEngine:
    """Advanced JavaScript Symbolic Execution & Constraint Analysis Engine."""

    def __init__(self, max_depth=100, max_loop_iter=3, timeout_ms=500):
        self.max_depth = max_depth
        self.max_loop_iter = max_loop_iter
        self.timeout_ms = timeout_ms
        self.reset()

    def reset(self):
        self.source_code = ""
        self.completed_paths = []
        self.stats = {
            "paths_explored": 0,
            "feasible_branches": 0,
            "infeasible_branches": 0,
            "unknown_branches": 0,
            "timeout_count": 0
        }

    def analyze(self, source_code: str) -> Dict[str, Any]:
        self.reset()
        if not source_code or not source_code.strip():
            return {"status": "error", "message": "Empty input"}
        self.source_code = source_code
        
        try:
            tree = esprima.parseScript(source_code, {"range": True, "loc": True, "tolerant": True})
            
            initial_state = SymState()
            self._explore_path([tree], initial_state, 0, "Global Entry")
            
            # Formatting results
            report_paths = []
            for path in self.completed_paths:
                cond_strs = [str(c) for c in path.state.path_conditions]
                var_strs = {k: str(v) for k, v in path.state.variables.items()}
                
                report_paths.append({
                    "block_name": path.block_name,
                    "status": path.status,
                    "location": path.location,
                    "conditions": cond_strs,
                    "variables": var_strs
                })
                
                if path.status == "Feasible": self.stats["feasible_branches"] += 1
                elif path.status == "Infeasible": self.stats["infeasible_branches"] += 1
                else: self.stats["unknown_branches"] += 1
                
            self.stats["paths_explored"] = len(self.completed_paths)
                
            return {
                "status": "success",
                "paths": report_paths,
                "stats": self.stats
            }
        except Exception as e:
            return {"status": "error", "message": f"Symbolic Engine Error: {str(e)}"}

    def _check_feasibility(self, state: SymState) -> str:
        """Invokes Z3 Solver to evaluate Path Conditions."""
        if not state.path_conditions:
            return "Feasible"
            
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        try:
            for cond in state.path_conditions:
                if z3.is_bool(cond):
                    solver.add(cond)
                else:
                    return "Unknown" # Type unsupported by simple constraints
                    
            res = solver.check()
            if res == z3.sat:
                return "Feasible"
            elif res == z3.unsat:
                return "Infeasible"
            else:
                self.stats["timeout_count"] += 1
                return "Unknown"
        except Exception:
            return "Unknown"

    def _loc_str(self, node: Any) -> str:
        if hasattr(node, 'loc') and node.loc:
            return f"Line {node.loc.start.line}"
        return "Unknown"

    def _explore_path(self, statements: List[Any], state: SymState, depth: int, block_name: str, loop_counters: Dict[str, int] = None):
        """Recursively explores execution paths in the AST up to a bounded depth."""
        if depth > self.max_depth:
            self.completed_paths.append(SymPath(state, "Unknown (Max Depth Exceeded)", "N/A", block_name))
            return
            
        if loop_counters is None:
            loop_counters = {}

        if not statements:
            # Reached end of a block, check feasibility and log
            status = self._check_feasibility(state)
            # Only record if it has conditions, otherwise it's just sequential code
            if state.path_conditions:
                self.completed_paths.append(SymPath(state, status, "End of Path", block_name))
            return

        node = statements[0]
        remaining = statements[1:]

        if not hasattr(node, 'type'):
            self._explore_path(remaining, state, depth + 1, block_name, loop_counters)
            return

        ntype = node.type

        # Assignments and Declarations (Update Symbolic State)
        if ntype == 'VariableDeclaration':
            for decl in getattr(node, 'declarations', []):
                if decl.type == 'VariableDeclarator' and decl.id.type == 'Identifier' and getattr(decl, 'init', None):
                    val = self._evaluate_sym(decl.init, state)
                    state.assign(decl.id.name, val)
            self._explore_path(remaining, state, depth + 1, block_name, loop_counters)
            
        elif ntype == 'ExpressionStatement' and getattr(node.expression, 'type', '') == 'AssignmentExpression':
            expr = node.expression
            if expr.left.type == 'Identifier':
                val = self._evaluate_sym(expr.right, state)
                # Handle +=, -=, etc.
                if expr.operator == '+=': val = state.get(expr.left.name) + val
                elif expr.operator == '-=': val = state.get(expr.left.name) - val
                state.assign(expr.left.name, val)
            self._explore_path(remaining, state, depth + 1, block_name, loop_counters)
            
        # Branching (Fork Symbolic State)
        elif ntype == 'IfStatement':
            cond_val = self._evaluate_sym(node.test, state)
            
            # TRUE Branch
            true_state = state.clone()
            if z3.is_bool(cond_val): true_state.add_condition(cond_val)
            true_block = [node.consequent] + remaining
            self._explore_path(true_block, true_state, depth + 1, f"If (True) {self._loc_str(node)}", loop_counters)
            
            # FALSE Branch
            false_state = state.clone()
            if z3.is_bool(cond_val): false_state.add_condition(z3.Not(cond_val))
            false_block = ([node.alternate] if getattr(node, 'alternate', None) else []) + remaining
            self._explore_path(false_block, false_state, depth + 1, f"If (False) {self._loc_str(node)}", loop_counters)

        elif ntype in ['WhileStatement', 'ForStatement']:
            loop_id = str(id(node))
            iters = loop_counters.get(loop_id, 0)
            
            if iters < self.max_loop_iter:
                loop_counters[loop_id] = iters + 1
                
                cond_val = None
                if ntype == 'WhileStatement': cond_val = self._evaluate_sym(node.test, state)
                elif getattr(node, 'test', None): cond_val = self._evaluate_sym(node.test, state)
                
                # Loop Body Path (Condition True)
                body_state = state.clone()
                if z3.is_bool(cond_val): body_state.add_condition(cond_val)
                
                if ntype == 'ForStatement' and iters == 0 and getattr(node, 'init', None):
                    body_block = [node.init, node.body, node] + remaining # Re-queue loop
                else:
                    body_block = [node.body, node] + remaining # Re-queue loop
                self._explore_path(body_block, body_state, depth + 1, f"Loop Body {self._loc_str(node)}", loop_counters)
                
                # Exit Loop Path (Condition False)
                exit_state = state.clone()
                if z3.is_bool(cond_val): exit_state.add_condition(z3.Not(cond_val))
                self._explore_path(remaining, exit_state, depth + 1, f"Loop Exit {self._loc_str(node)}", loop_counters)
            else:
                # Unroll limit reached
                self.completed_paths.append(SymPath(state, "Unknown (Loop Limit)", self._loc_str(node), "Loop Bounded"))
                self._explore_path(remaining, state.clone(), depth + 1, block_name, loop_counters)

        elif ntype == 'BlockStatement':
            block = getattr(node, 'body', []) + remaining
            self._explore_path(block, state, depth + 1, block_name, loop_counters)
            
        elif ntype == 'Program':
            block = getattr(node, 'body', []) + remaining
            self._explore_path(block, state, depth + 1, block_name, loop_counters)

        else:
            # Skip unhandled nodes for path construction
            self._explore_path(remaining, state, depth + 1, block_name, loop_counters)

    def _evaluate_sym(self, node: Any, state: SymState) -> Any:
        """Translates AST nodes into Z3 Symbolic Expressions."""
        if not node: return None
        ntype = getattr(node, 'type', '')
        
        if ntype == 'Literal':
            val = node.value
            if isinstance(val, int): return z3.IntVal(val)
            if isinstance(val, bool): return z3.BoolVal(val)
            return str(val) # Strings fallback, bounded support in simple equations

        elif ntype == 'Identifier':
            return state.get(node.name)

        elif ntype == 'BinaryExpression':
            left = self._evaluate_sym(node.left, state)
            right = self._evaluate_sym(node.right, state)
            
            if left is None or right is None or isinstance(left, str) or isinstance(right, str):
                return None
                
            try:
                op = node.operator
                if op == '+': return left + right
                if op == '-': return left - right
                if op == '*': return left * right
                if op == '/': return left / right
                if op in ['==', '===']: return left == right
                if op in ['!=', '!==']: return left != right
                if op == '<': return left < right
                if op == '<=': return left <= right
                if op == '>': return left > right
                if op == '>=': return left >= right
            except Exception:
                return None

        elif ntype == 'LogicalExpression':
            left = self._evaluate_sym(node.left, state)
            right = self._evaluate_sym(node.right, state)
            
            if not z3.is_bool(left) or not z3.is_bool(right):
                return None
                
            op = node.operator
            if op == '&&': return z3.And(left, right)
            if op == '||': return z3.Or(left, right)
            
        elif ntype == 'UnaryExpression':
            arg = self._evaluate_sym(node.argument, state)
            if arg is None: return None
            
            op = node.operator
            if op == '!' and z3.is_bool(arg): return z3.Not(arg)
            if op == '-' and z3.is_arith(arg): return -arg
            
        return None
