import esprima
import networkx as nx
from typing import Dict, Any, List

class AdvancedTaintAnalyzer:
    """Static Taint Tracking and Security Evidence Graph generator."""
    def __init__(self):
        self.sources = {"document.cookie", "location.hash", "location.search", "window.name", "fetch", "XMLHttpRequest"}
        self.sinks = {"eval", "setTimeout", "setInterval", "document.write", "innerHTML", "Function"}
        self.tainted_vars = set()
        self.findings = []
        self.evidence_graph = nx.DiGraph()

    def analyze(self, code: str) -> Dict[str, Any]:
        self.tainted_vars.clear()
        self.findings.clear()
        self.evidence_graph.clear()
        
        if not code: return {}
        try:
            tree = esprima.parseScript(code, {"tolerant": True})
            self._walk(tree)
            return {
                "tainted_variables": list(self.tainted_vars),
                "findings": self.findings,
                "graph_nodes": list(self.evidence_graph.nodes),
                "graph_edges": list(self.evidence_graph.edges)
            }
        except Exception as e:
            return {"error": str(e)}

    def _walk(self, node: Any):
        if not node or not hasattr(node, 'type'): return

        # 1. Source to Variable Assignment
        if node.type == 'VariableDeclarator' and getattr(node, 'init', None):
            self._check_source_flow(getattr(node.id, 'name', 'unknown'), node.init)
        elif node.type == 'AssignmentExpression' and getattr(node.left, 'type', '') == 'Identifier':
            self._check_source_flow(node.left.name, node.right)
            
        # 2. Tainted Variable to Sink Execution
        if node.type == 'CallExpression' and getattr(node.callee, 'type', '') == 'Identifier':
            if node.callee.name in self.sinks:
                for arg in getattr(node, 'arguments', []):
                    if getattr(arg, 'type', '') == 'Identifier' and arg.name in self.tainted_vars:
                        finding = f"Tainted flow: '{arg.name}' reaches dangerous sink '{node.callee.name}()'"
                        self.findings.append(finding)
                        self.evidence_graph.add_edge(arg.name, node.callee.name, label="Execution")
                        
        for k, v in vars(node).items():
            if k in ['type', 'loc', 'range']: continue
            if isinstance(v, list):
                for item in v: self._walk(item)
            elif hasattr(v, 'type'): self._walk(v)

    def _check_source_flow(self, target_var: str, expr: Any):
        if expr.type == 'MemberExpression':
            obj = getattr(expr.object, 'name', '')
            prop = getattr(expr.property, 'name', '')
            sig = f"{obj}.{prop}"
            if sig in self.sources:
                self.tainted_vars.add(target_var)
                self.evidence_graph.add_edge(sig, target_var, label="Assignment")
        elif expr.type == 'CallExpression' and getattr(expr.callee, 'type', '') == 'Identifier':
            if expr.callee.name in self.sources:
                self.tainted_vars.add(target_var)
                self.evidence_graph.add_edge(expr.callee.name, target_var, label="Return Flow")
        elif expr.type == 'Identifier' and expr.name in self.tainted_vars:
            # Taint propagation
            self.tainted_vars.add(target_var)
            self.evidence_graph.add_edge(expr.name, target_var, label="Propagation")


class FunctionBehaviorExplainer:
    """Generates evidence-based Natural-Language explanations of code algorithms."""
    
    def explain(self, ast_data: Dict[str, Any], call_data: Dict[str, Any]) -> List[Dict[str, str]]:
        explanations = []
        funcs = call_data.get("functions", {})
        
        for name, data in funcs.items():
            features = data.get("features", [])
            nl_desc = f"Function `{name}` "
            
            if "network" in features:
                nl_desc += "executes network requests (e.g., fetch/XHR), indicating external C2 communication or data exfiltration. "
            if "dom" in features:
                nl_desc += "manipulates the DOM natively, potentially injecting payloads or scraping page content. "
            if "math" in features and "logic" in features:
                nl_desc += "utilizes heavy mathematical/logical bitwise operations, heavily indicative of custom cryptography or hashing loops. "
                
            if nl_desc == f"Function `{name}` ":
                nl_desc += "appears to be a standard internal utility or wrapper function with no sensitive API calls."
                
            explanations.append({"function": name, "explanation": nl_desc})
            
        return explanations
