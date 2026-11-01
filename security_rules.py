from typing import Dict, Any, Callable, List

class SecurityRule:
    def __init__(self, rule_id: str, name: str, category: str, severity: str, 
                 description: str, remediation: str, matcher: Callable[[Any], bool], confidence: str = "High"):
        self.id = rule_id
        self.name = name
        self.category = category
        self.severity = severity # Informational, Low, Medium, High, Critical
        self.description = description
        self.remediation = remediation
        self.matcher = matcher
        self.confidence = confidence

class RuleSet:
    @staticmethod
    def _is_call_to(node: Any, func_names: List[str]) -> bool:
        if node.type == 'CallExpression' and getattr(node.callee, 'type', '') == 'Identifier':
            return node.callee.name in func_names
        # Handle window.eval, document.write, etc.
        if node.type == 'CallExpression' and getattr(node.callee, 'type', '') == 'MemberExpression':
            prop = getattr(node.callee.property, 'name', '')
            return prop in func_names and not getattr(node.callee, 'computed', False)
        return False

    @staticmethod
    def _is_assignment_to(node: Any, prop_names: List[str]) -> bool:
        if node.type == 'AssignmentExpression' and getattr(node.left, 'type', '') == 'MemberExpression':
            prop = getattr(node.left.property, 'name', '')
            return prop in prop_names and not getattr(node.left, 'computed', False)
        return False

    @staticmethod
    def get_rules() -> List[SecurityRule]:
        return [
            SecurityRule(
                "SEC_DYN_EVAL", "Dynamic Code Execution (eval)", "Dynamic Execution", "Critical",
                "The use of eval() allows arbitrary code execution and is a primary indicator of malware unpacking or XSS vulnerabilities.",
                "Avoid eval(). If parsing JSON, use JSON.parse().",
                lambda n: RuleSet._is_call_to(n, ['eval'])
            ),
            SecurityRule(
                "SEC_DYN_FUNC", "Function Constructor Execution", "Dynamic Execution", "High",
                "Using the Function() constructor with dynamic strings acts identically to eval().",
                "Avoid constructing functions from dynamic strings.",
                lambda n: n.type == 'NewExpression' and getattr(n.callee, 'name', '') == 'Function'
            ),
            SecurityRule(
                "SEC_DOM_XSS", "Dangerous DOM Manipulation (innerHTML)", "DOM Security", "High",
                "Assignment to innerHTML/outerHTML can lead to Cross-Site Scripting (XSS) if data is user-controlled.",
                "Use textContent or secure DOM creation methods (createElement).",
                lambda n: RuleSet._is_assignment_to(n, ['innerHTML', 'outerHTML'])
            ),
            SecurityRule(
                "SEC_DOC_WRITE", "Document Write Injection", "DOM Security", "Medium",
                "document.write() is highly suspicious in modern code and often used by exploit kits.",
                "Use standard DOM manipulation APIs instead of document.write.",
                lambda n: RuleSet._is_call_to(n, ['write', 'writeln'])
            ),
            SecurityRule(
                "SEC_NET_FETCH", "Network Request API (fetch/XHR)", "Network & Data Flow", "Informational",
                "Initiates a network request. In obfuscated code, this is often used for data exfiltration or payload downloading.",
                "Verify the destination domain and payload.",
                lambda n: RuleSet._is_call_to(n, ['fetch', 'XMLHttpRequest', 'sendBeacon'])
            ),
            SecurityRule(
                "SEC_STORAGE", "Browser Storage Access", "Data Collection", "Low",
                "Accessing localStorage, sessionStorage, or cookies. Often used by trackers or stealers.",
                "Ensure sensitive data (tokens) are not stored in easily accessible local storage.",
                lambda n: n.type == 'MemberExpression' and getattr(n.property, 'name', '') in ['localStorage', 'sessionStorage', 'cookie']
            )
        ]
