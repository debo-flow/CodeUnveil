from typing import List, Dict, Any

class SignatureDB:
    """Modular database of JavaScript obfuscation signatures."""
    
    SIGNATURES = [
        {
            "id": "SIG_ID_MANGLING",
            "name": "Identifier Mangling",
            "category": "Identifier",
            "description": "Variable and function names are replaced with short, meaningless, or hexadecimal characters to reduce readability.",
            "severity": 1,
            "condition": lambda metrics: metrics.get("unusual_variable_names", 0) > 5 or (metrics.get("variables", 1) > 0 and metrics.get("unusual_variable_names", 0) / metrics.get("variables", 1) > 0.3)
        },
        {
            "id": "SIG_STR_ARRAY",
            "name": "String Array Obfuscation",
            "category": "String",
            "description": "Strings are extracted from the code and placed into a centralized array to hide literal values.",
            "severity": 3,
            "condition": lambda metrics: metrics.get("large_string_collections", 0) >= 1
        },
        {
            "id": "SIG_CFF",
            "name": "Control Flow Flattening",
            "category": "Structure",
            "description": "Standard control flow (if/else/for) is replaced with a flat switch statement inside a loop, making execution paths difficult to trace.",
            "severity": 4,
            "condition": lambda metrics: metrics.get("switch_in_loop", 0) >= 1
        },
        {
            "id": "SIG_COMPUTED_PROP",
            "name": "Computed Property Access",
            "category": "Structure",
            "description": "Object properties are accessed via bracket notation with strings (e.g., obj['prop']) rather than dot notation to evade static analysis.",
            "severity": 2,
            "condition": lambda metrics: metrics.get("computed_property_access", 0) > 10
        },
        {
            "id": "SIG_UNNECESSARY_BOOL",
            "name": "Unnecessary Boolean Expressions",
            "category": "Constant",
            "description": "Usage of complex unary expressions (e.g., !![]) to represent simple constants like true or false.",
            "severity": 2,
            "condition": lambda metrics: metrics.get("unary_booleans", 0) > 5
        },
        {
            "id": "SIG_DEBUG_PROTECT",
            "name": "Debug Protection Patterns",
            "category": "Defense",
            "description": "Presence of debugger statements or cyclical debugger invocations meant to crash or stall developer tools.",
            "severity": 4,
            "condition": lambda metrics: metrics.get("debugger_statements", 0) >= 1
        },
        {
            "id": "SIG_DEAD_CODE",
            "name": "Dead Code Injection Indicators",
            "category": "Structure",
            "description": "High volume of empty blocks or unnecessarily deep nesting indicating artificially inflated code size.",
            "severity": 3,
            "condition": lambda metrics: metrics.get("empty_blocks", 0) > 5 and metrics.get("cyclomatic_complexity", 1) > 50
        },
        {
            "id": "SIG_SUSPICIOUS_WRAPPER",
            "name": "Function Wrapping",
            "category": "Structure",
            "description": "Code is heavily nested inside Immediately Invoked Function Expressions (IIFEs) or generic wrappers.",
            "severity": 2,
            "condition": lambda metrics: metrics.get("suspicious_wrappers", 0) >= 2
        }
    ]

    @staticmethod
    def get_signatures() -> List[Dict[str, Any]]:
        return SignatureDB.SIGNATURES
