import esprima
import json
from typing import Dict, Any, List, Set, Tuple

class SemanticSymbol:
    def __init__(self, name: str, kind: str, scope_level: int):
        self.name = name
        self.kind = kind
        self.scope_level = scope_level
        self.inferred_types = set()
        self.reads = 0
        self.writes = 0
        self.dependencies = set() # Data dependencies (other symbols this relies on)

class SemanticScope:
    def __init__(self, parent=None, scope_type="block"):
        self.parent = parent
        self.scope_type = scope_type
        self.level = parent.level + 1 if parent else 0
        self.symbols: Dict[str, SemanticSymbol] = {}

    def declare(self, name: str, kind: str) -> SemanticSymbol:
        if name not in self.symbols:
            self.symbols[name] = SemanticSymbol(name, kind, self.level)
        return self.symbols[name]

    def lookup(self, name: str) -> SemanticSymbol:
        if name in self.symbols:
            return self.symbols[name]
        if self.parent:
            return self.parent.lookup(name)
        return None

class SemanticAnalyzer:
    """Advanced JavaScript Semantic Analysis & Program Understanding Engine."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.source_code = ""
        self.global_scope = SemanticScope(scope_type="global")
        self.all_symbols = []
        self.function_summaries = {}
        self.side_effects = []
        self.data_deps = []    # (symbol_a, symbol_b)
        self.control_deps = [] # (condition_node_type, statement_type)
        self.stats = {
            "total_symbols": 0,
            "resolved_types": 0,
            "functions_classified": 0,
            "side_effects_detected": 0
        }

    def analyze(self, source_code: str) -> Dict[str, Any]:
        self.reset()
        if not source_code or not source_code.strip():
            return {"status": "error", "message": "Empty input"}
        self.source_code = source_code
        
        try:
            tree = esprima.parseScript(source_code, {"range": True, "loc": True, "tolerant": True})
            
            # Pass 1: Build Scopes, Symbols, and Control Deps
            self._walk_semantics(tree, self.global_scope)
            
            # Extract flattened symbol table
            self._flatten_symbols(self.global_scope)
            
            # Generate metrics
            self.stats["total_symbols"] = len(self.all_symbols)
            self.stats["resolved_types"] = sum(1 for s in self.all_symbols if s.inferred_types and "Unknown" not in s.inferred_types)
            self.stats["functions_classified"] = len(self.function_summaries)
            self.stats["side_effects_detected"] = len(self.side_effects)

            return {
                "status": "success",
                "symbols": [
                    {
                        "name": s.name, 
                        "kind": s.kind, 
                        "types": list(s.inferred_types) or ["Unknown"],
                        "reads": s.reads,
                        "writes": s.writes,
                        "scope_depth": s.scope_level
                    } for s in self.all_symbols
                ],
                "functions": self.function_summaries,
                "side_effects": self.side_effects,
                "stats": self.stats,
                "dependency_graph_dot": self._generate_dot()
            }
        except Exception as e:
            return {"status": "error", "message": f"Semantic Engine Error: {str(e)}"}

    def _infer_type(self, node: Any, scope: SemanticScope) -> Set[str]:
        """Conservatively infers JavaScript data types statically."""
        if not node: return {"Unknown"}
        ntype = getattr(node, 'type', '')
        
        if ntype == 'Literal':
            val = node.value
            if val is None: return {"Null"}
            if isinstance(val, bool): return {"Boolean"}
            if isinstance(val, (int, float)): return {"Number"}
            if isinstance(val, str): return {"String"}
            if hasattr(node, 'regex'): return {"RegExp"}
            
        elif ntype == 'Identifier':
            sym = scope.lookup(node.name)
            if sym and sym.inferred_types:
                return sym.inferred_types
                
        elif ntype == 'ArrayExpression':
            return {"Array"}
            
        elif ntype == 'ObjectExpression':
            return {"Object"}
            
        elif ntype in ['FunctionExpression', 'ArrowFunctionExpression', 'FunctionDeclaration']:
            return {"Function"}
            
        elif ntype == 'BinaryExpression':
            if node.operator in ['+', '+=']:
                lt = self._infer_type(node.left, scope)
                rt = self._infer_type(node.right, scope)
                if "String" in lt or "String" in rt:
                    return {"String"}
                if "Number" in lt and "Number" in rt:
                    return {"Number"}
                return {"String", "Number"} # Union type
            if node.operator in ['-', '*', '/', '%', '**', '<<', '>>', '>>>', '&', '|', '^']:
                return {"Number"}
            if node.operator in ['==', '===', '!=', '!==', '<', '<=', '>', '>=', 'in', 'instanceof']:
                return {"Boolean"}
                
        elif ntype == 'LogicalExpression':
            # Returns the type of the left or right operand depending on short-circuit
            lt = self._infer_type(node.left, scope)
            rt = self._infer_type(node.right, scope)
            return lt.union(rt)
            
        elif ntype == 'UnaryExpression':
            if node.operator == '!': return {"Boolean"}
            if node.operator in ['-', '+', '~']: return {"Number"}
            if node.operator == 'typeof': return {"String"}
            if node.operator == 'void': return {"Undefined"}
            
        return {"Unknown"}

    def _walk_semantics(self, node: Any, current_scope: SemanticScope, active_conditions: List[str] = None):
        if not node or not hasattr(node, 'type'): return
        
        if active_conditions is None:
            active_conditions = []

        is_func = node.type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']
        is_block = node.type in ['BlockStatement', 'Program']
        next_scope = current_scope
        
        # 1. Scope Management
        if is_func:
            next_scope = SemanticScope(parent=current_scope, scope_type="function")
            func_name = getattr(node.id, 'name', 'anonymous') if getattr(node, 'id', None) else 'anonymous'
            
            # Map Parameters
            for p in getattr(node, 'params', []):
                if p.type == 'Identifier':
                    sym = next_scope.declare(p.name, 'param')
                    
            # Semantic Function Analysis (M18)
            self._analyze_function_semantics(node, func_name, next_scope)
            
        elif is_block:
            next_scope = SemanticScope(parent=current_scope, scope_type="block")

        # 2. Control Dependency Tracking
        next_conditions = list(active_conditions)
        if node.type in ['IfStatement', 'WhileStatement', 'DoWhileStatement', 'ForStatement', 'SwitchCase']:
            next_conditions.append(node.type)
        else:
            # Map statement to dominating conditions
            if active_conditions and 'Statement' in node.type:
                self.control_deps.append((active_conditions[-1], node.type))

        # 3. Data Dependency & Type Tracking
        if node.type == 'VariableDeclarator' and node.id.type == 'Identifier':
            kind = getattr(node.parent, 'kind', 'var')
            target_scope = next_scope
            if kind == 'var':
                while target_scope.parent and target_scope.scope_type != 'function':
                    target_scope = target_scope.parent
            sym = target_scope.declare(node.id.name, kind)
            sym.writes += 1
            if getattr(node, 'init', None):
                inferred = self._infer_type(node.init, target_scope)
                sym.inferred_types.update(inferred)
                
                # Track data dependency if RHS is an Identifier
                if node.init.type == 'Identifier':
                    sym.dependencies.add(node.init.name)
                    self.data_deps.append((node.init.name, sym.name))
                    
        elif node.type == 'AssignmentExpression' and node.left.type == 'Identifier':
            sym = next_scope.lookup(node.left.name)
            if sym:
                sym.writes += 1
                inferred = self._infer_type(node.right, next_scope)
                sym.inferred_types.update(inferred)
                if node.right.type == 'Identifier':
                    sym.dependencies.add(node.right.name)
                    self.data_deps.append((node.right.name, sym.name))

        elif node.type == 'Identifier':
            # Read operations
            if not self._is_declaration_or_static_prop(node):
                sym = next_scope.lookup(node.name)
                if sym: sym.reads += 1

        # 4. Global Side-Effect Detection
        self._detect_side_effects(node)

        # Recurse
        for key, val in vars(node).items():
            if key in ['type', 'loc', 'range', 'parent']: continue
            if isinstance(val, list):
                for item in val: self._walk_semantics(item, next_scope, next_conditions)
            elif hasattr(val, 'type'):
                self._walk_semantics(val, next_scope, next_conditions)

    def _analyze_function_semantics(self, node: Any, name: str, scope: SemanticScope):
        """Analyzes a function's AST body to classify its semantic purpose and effects."""
        body = getattr(node, 'body', None)
        features = set()
        returns = set()
        
        def scan(n):
            if not n or not hasattr(n, 'type'): return
            if n.type == 'BinaryExpression':
                if n.operator in ['+', '-', '*', '/']: features.add("math")
                if n.operator in ['==', '===', '!=', '!==']: features.add("logic")
            if n.type == 'CallExpression' and getattr(n.callee, 'type', '') == 'Identifier':
                if n.callee.name in ['fetch', 'XMLHttpRequest']: features.add("network")
                if n.callee.name in ['setTimeout', 'setInterval']: features.add("timer")
            if n.type == 'MemberExpression' and getattr(n.object, 'name', '') in ['document', 'window']:
                features.add("dom")
            if n.type == 'ReturnStatement' and getattr(n, 'argument', None):
                returns.update(self._infer_type(n.argument, scope))
            for k, v in vars(n).items():
                if k in ['type', 'loc', 'range', 'parent']: continue
                if isinstance(v, list):
                    for i in v: scan(i)
                elif hasattr(v, 'type'): scan(v)
                
        scan(body)
        
        # Deterministic Classification
        classification = "Utility Function"
        if "network" in features: classification = "Network Interaction"
        elif "dom" in features: classification = "DOM Manipulation"
        elif "math" in features and "logic" not in features: classification = "Mathematical Operation"
        elif "logic" in features: classification = "Validation Logic"
        
        self.function_summaries[name] = {
            "classification": classification,
            "inferred_return_types": list(returns) or ["Undefined"],
            "has_side_effects": "dom" in features or "network" in features,
            "features": list(features)
        }

    def _detect_side_effects(self, node: Any):
        """Statically isolates operations that mutate environment state."""
        if node.type == 'AssignmentExpression' and node.left.type == 'MemberExpression':
            if getattr(node.left.object, 'name', '') == 'document':
                self.side_effects.append(f"DOM Mutation: Assigned to document.{getattr(node.left.property, 'name', 'property')}")
            if getattr(node.left.object, 'name', '') == 'window':
                self.side_effects.append(f"Global Mutation: Assigned to window.{getattr(node.left.property, 'name', 'property')}")
        if node.type == 'CallExpression' and getattr(node.callee, 'type', '') == 'Identifier':
            if node.callee.name == 'fetch':
                self.side_effects.append("Network Action: fetch() called.")
            if node.callee.name == 'eval':
                self.side_effects.append("Dangerous Evaluation: eval() called.")

    def _is_declaration_or_static_prop(self, node: Any) -> bool:
        p = getattr(node, 'parent', None)
        if not p: return False
        if p.type in ['VariableDeclarator', 'FunctionDeclaration'] and getattr(p, 'id', None) == node: return True
        if p.type == 'MemberExpression' and p.property == node and not getattr(p, 'computed', False): return True
        if p.type == 'Property' and p.key == node and not getattr(p, 'computed', False): return True
        return False

    def _flatten_symbols(self, scope: SemanticScope):
        for sym in scope.symbols.values():
            self.all_symbols.append(sym)
        for child in getattr(scope, 'children', []): # Handled structurally implicitly via recursion if needed
            pass # We recursively gathered scopes, but we can also just append in traversal.
            
    def _generate_dot(self) -> str:
        dot = [
            'digraph SemanticGraph {',
            '  rankdir=LR;',
            '  node [shape=box, style=filled, color="#2B2B2B", fontcolor="#E0E0E0", fontname="Courier New"];',
            '  edge [color="#666666"];',
            '  bgcolor="#0E1117";'
        ]
        
        # Add Data Dependencies
        drawn_nodes = set()
        for src, dst in set(self.data_deps):
            if src not in drawn_nodes:
                dot.append(f'  "{src}" [shape=ellipse, fillcolor="#2196F3"];')
                drawn_nodes.add(src)
            if dst not in drawn_nodes:
                dot.append(f'  "{dst}" [shape=ellipse, fillcolor="#2196F3"];')
                drawn_nodes.add(dst)
            dot.append(f'  "{src}" -> "{dst}" [label=" data", fontsize=10, fontcolor="#888888"];')
            
        dot.append('}')
        return "\n".join(dot)
