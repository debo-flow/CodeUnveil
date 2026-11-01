import esprima
import json
from typing import Dict, Any, List
from security_rules import RuleSet

class SecurityAnalyzer:
    """Advanced JavaScript Malware & Suspicious Code Static Analysis Engine."""

    SOURCES = ['location', 'href', 'search', 'hash', 'cookie', 'localStorage', 'sessionStorage', 'referrer']
    SINKS = ['eval', 'innerHTML', 'outerHTML', 'write', 'writeln', 'fetch', 'send', 'setTimeout', 'setInterval']

    def __init__(self):
        self.rules = RuleSet.get_rules()
        self.reset()

    def reset(self):
        self.source_code = ""
        self.findings = []
        self.tainted_vars = set()
        self.finding_id_counter = 1

    def _get_loc(self, node: Any) -> str:
        loc = getattr(node, 'loc', None)
        if loc and hasattr(loc, 'start'):
            return f"Line {loc.start.line}, Col {loc.start.column}"
        return "Unknown Location"

    def _get_snippet(self, node: Any) -> str:
        rng = getattr(node, 'range', None)
        if rng:
            snip = self.source_code[rng[0]:rng[1]]
            return snip[:100] + "..." if len(snip) > 100 else snip
        return ""

    def analyze(self, source_code: str, obfuscation_metrics: Dict[str, Any] = None) -> Dict[str, Any]:
        self.reset()
        if not source_code or not source_code.strip():
            return {"status": "error", "message": "Empty input"}
        self.source_code = source_code
        
        try:
            tree = esprima.parseScript(source_code, {"range": True, "loc": True, "tolerant": True})
            
            # 1. Walk AST for Rules & Source-to-Sink Analysis
            self._walk_and_analyze(tree)
            
            # 2. Integrate Obfuscation Risk (M5)
            self._integrate_obfuscation_risk(obfuscation_metrics)

            # Summarize
            summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
            for f in self.findings:
                summary[f["severity"]] = summary.get(f["severity"], 0) + 1

            return {
                "status": "success",
                "findings": self.findings,
                "summary": summary,
                "total_findings": len(self.findings)
            }
        except Exception as e:
            return {"status": "error", "message": f"Security Engine Error: {str(e)}"}

    def _walk_and_analyze(self, node: Any):
        if not node or not hasattr(node, 'type'): return

        # Apply Security Rules
        for rule in self.rules:
            try:
                if rule.matcher(node):
                    self._add_finding(rule, node)
            except Exception:
                pass

        # Source-to-Sink Taint Tracking (Basic static assignments)
        if node.type == 'VariableDeclarator' and getattr(node, 'init', None):
            if self._is_tainted_source(node.init):
                if node.id.type == 'Identifier':
                    self.tainted_vars.add(node.id.name)
        elif node.type == 'AssignmentExpression':
            if self._is_tainted_source(node.right):
                if node.left.type == 'Identifier':
                    self.tainted_vars.add(node.left.name)

        # Check Sinks against Tainted Variables
        if node.type == 'CallExpression' or node.type == 'AssignmentExpression':
            self._check_tainted_sink(node)

        # Recurse
        for key, val in vars(node).items():
            if key in ['type', 'loc', 'range', 'parent']: continue
            if isinstance(val, list):
                for item in val: self._walk_and_analyze(item)
            elif hasattr(val, 'type'):
                self._walk_and_analyze(val)

    def _is_tainted_source(self, node: Any) -> bool:
        if node.type == 'Identifier' and node.name in self.tainted_vars: return True
        if node.type == 'MemberExpression' and getattr(node.property, 'name', '') in self.SOURCES: return True
        return False

    def _check_tainted_sink(self, node: Any):
        sink_name = ""
        arg_node = None
        
        if node.type == 'CallExpression' and getattr(node.callee, 'type', '') == 'Identifier':
            if node.callee.name in self.SINKS:
                sink_name = node.callee.name
                arg_node = node.arguments[0] if node.arguments else None
        elif node.type == 'AssignmentExpression' and getattr(node.left, 'type', '') == 'MemberExpression':
            prop = getattr(node.left.property, 'name', '')
            if prop in self.SINKS:
                sink_name = prop
                arg_node = node.right

        if sink_name and arg_node:
            if self._is_tainted_source(arg_node):
                self.findings.append({
                    "id": f"TAINT_{self.finding_id_counter}",
                    "rule_id": "SEC_DATA_FLOW",
                    "category": "Source-to-Sink Data Flow",
                    "severity": "Critical",
                    "confidence": "Medium",
                    "name": "Tainted Data Injection Path",
                    "description": f"User-controlled data flows statically into a dangerous sink ({sink_name}).",
                    "remediation": "Sanitize user inputs before rendering or evaluating.",
                    "location": self._get_loc(node),
                    "snippet": self._get_snippet(node),
                    "status": "Open",
                    "notes": ""
                })
                self.finding_id_counter += 1

    def _add_finding(self, rule, node):
        self.findings.append({
            "id": f"FINDING_{self.finding_id_counter}",
            "rule_id": rule.id,
            "category": rule.category,
            "severity": rule.severity,
            "confidence": rule.confidence,
            "name": rule.name,
            "description": rule.description,
            "remediation": rule.remediation,
            "location": self._get_loc(node),
            "snippet": self._get_snippet(node),
            "status": "Open", # User can change to False Positive later
            "notes": ""
        })
        self.finding_id_counter += 1

    def _integrate_obfuscation_risk(self, m5_metrics: Dict[str, Any]):
        if not m5_metrics or m5_metrics.get("status") != "success": return
        level = m5_metrics.get("severity_level", 0)
        
        if level >= 4:
            self.findings.append({
                "id": f"OBF_{self.finding_id_counter}",
                "rule_id": "SEC_OBFUSCATION_RISK",
                "category": "Evasion & Obfuscation",
                "severity": "High",
                "confidence": "High",
                "name": "High Obfuscation Risk Indicator",
                "description": f"Code exhibits Level {level} obfuscation. This level of evasion is highly correlated with malware distribution (e.g. CFF, String Arrays).",
                "remediation": "Review the deobfuscated payload generated by CodeUnveil.",
                "location": "Global / File Level",
                "snippet": "N/A",
                "status": "Open",
                "notes": ""
            })
            self.finding_id_counter += 1

    @staticmethod
    def generate_html_report(results: Dict[str, Any]) -> str:
        findings_html = ""
        for f in results.get("findings", []):
            color = {"Critical": "#ff4b4b", "High": "#ff7600", "Medium": "#f5b700", "Low": "#0088ff", "Informational": "#888888"}.get(f["severity"], "#fff")
            findings_html += f"""
            <div style="border: 1px solid #444; margin-bottom: 15px; padding: 15px; border-radius: 5px; background: #1e1e1e; color: #ddd;">
                <h4 style="margin-top: 0; color: {color};">[{f['severity']}] {f['name']}</h4>
                <p><strong>Category:</strong> {f['category']} | <strong>Confidence:</strong> {f['confidence']}</p>
                <p><strong>Location:</strong> {f['location']}</p>
                <p><strong>Description:</strong> {f['description']}</p>
                <pre style="background: #000; padding: 10px; border-radius: 3px;"><code>{f['snippet']}</code></pre>
                <p><strong>Remediation:</strong> {f['remediation']}</p>
                <p><strong>Status:</strong> {f['status']} | <strong>Notes:</strong> {f['notes']}</p>
            </div>
            """
            
        html = f"""
        <html>
        <head><title>CodeUnveil Security Report</title><style>body {{ font-family: sans-serif; background: #121212; color: #eee; padding: 20px; }}</style></head>
        <body>
            <h1>🛡️ CodeUnveil Security Analysis Report</h1>
            <h3>Summary</h3>
            <ul>
                <li>Critical: {results['summary'].get('Critical', 0)}</li>
                <li>High: {results['summary'].get('High', 0)}</li>
                <li>Medium: {results['summary'].get('Medium', 0)}</li>
                <li>Low: {results['summary'].get('Low', 0)}</li>
            </ul>
            <hr>
            <h3>Detailed Findings</h3>
            {findings_html}
        </body>
        </html>
        """
        return html
