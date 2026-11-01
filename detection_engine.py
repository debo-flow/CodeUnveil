import re
from typing import Dict, Any, List
from signature_db import SignatureDB

class DetectionEngine:
    """Advanced JavaScript Obfuscator Detection & Classification Engine."""

    def __init__(self):
        self.signatures = SignatureDB.get_signatures()

    def analyze(self, source_code: str, ast_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Runs the detection heuristic against the gathered metrics."""
        
        # Merge AST stats and complexity for easy rule evaluation
        metrics = {}
        if ast_metrics and ast_metrics.get("status") == "success":
            metrics.update(ast_metrics.get("stats", {}))
            metrics.update(ast_metrics.get("complexity", {}))

        detected_signatures = []
        max_sig_severity = 0
        total_score = 0

        # Evaluate Signatures
        for sig in self.signatures:
            try:
                if sig["condition"](metrics):
                    confidence = min(100, 50 + (sig["severity"] * 10))
                    detected_signatures.append({
                        "id": sig["id"],
                        "name": sig["name"],
                        "category": sig["category"],
                        "description": sig["description"],
                        "severity": sig["severity"],
                        "confidence": f"{confidence}%",
                        "evidence": "Threshold met in AST analysis",
                        "next_step": self._get_next_step(sig["id"])
                    })
                    max_sig_severity = max(max_sig_severity, sig["severity"])
                    total_score += sig["severity"]
            except Exception:
                pass

        # Calculate Overall Severity Level (0-5)
        severity_level, severity_explanation = self._calculate_severity(max_sig_severity, total_score, metrics)
        
        # Fingerprinting
        fingerprint = self._fingerprint(source_code, detected_signatures, metrics)

        return {
            "severity_level": severity_level,
            "severity_name": self._severity_name(severity_level),
            "explanation": severity_explanation,
            "detected_signatures": detected_signatures,
            "fingerprint": fingerprint,
            "metrics_snapshot": metrics
        }

    def _get_next_step(self, sig_id: str) -> str:
        steps = {
            "SIG_ID_MANGLING": "Apply variable renaming map.",
            "SIG_STR_ARRAY": "Execute String Deobfuscation (M3) to fold arrays.",
            "SIG_CFF": "Requires symbolic execution or dynamic unrolling.",
            "SIG_COMPUTED_PROP": "Normalize brackets to dot notation via JSBeautifier.",
            "SIG_DEBUG_PROTECT": "Manually strip 'debugger' statements before dynamic analysis."
        }
        return steps.get(sig_id, "Review code structure manually.")

    def _calculate_severity(self, max_sig_severity: int, total_score: int, metrics: Dict[str, Any]) -> tuple[int, str]:
        if total_score == 0:
            return 0, "No obfuscation signatures detected. Code appears clean."
        
        funcs = metrics.get("functions", 1)
        if funcs == 0: funcs = 1
        vars_count = metrics.get("variables", 1)

        if max_sig_severity == 1 and total_score <= 2:
            return 1, "Only identifier mangling detected. Likely standard minification."
        elif max_sig_severity <= 2 and total_score <= 5:
            return 2, "Light obfuscation. Basic string hiding and variable mangling."
        elif max_sig_severity <= 3 or total_score <= 9:
            return 3, "Moderate obfuscation. Likely uses string arrays and dead code injection."
        elif max_sig_severity == 4 and total_score <= 14:
            return 4, "Heavy obfuscation. Control flow flattening or debug protection actively used."
        elif total_score >= 15:
            return 5, "Highly complex obfuscation. Multiple advanced layers (CFF, Self-Defending, String Arrays) deployed simultaneously."
        
        return max_sig_severity, "Severity based on highest detected signature."

    def _severity_name(self, level: int) -> str:
        names = {0: "Readable Code", 1: "Minified Code", 2: "Light Obfuscation", 3: "Moderate Obfuscation", 4: "Heavy Obfuscation", 5: "Highly Complex Obfuscation"}
        return names.get(level, "Unknown")

    def _fingerprint(self, source_code: str, signatures: List[Dict[str, Any]], metrics: Dict[str, Any]) -> Dict[str, Any]:
        sig_ids = [s["id"] for s in signatures]
        
        # 1. Webpack
        if re.search(r'webpackJsonp|function\s*\(\s*module,\s*exports,\s*__webpack_require__\s*\)', source_code):
            return {
                "tool": "Webpack Bundle", "confidence": "High",
                "evidence": "Standard Webpack bootstrap wrappers detected.",
                "alternatives": "Browserify or Parcel (Low probability)"
            }
        
        # 2. Obfuscator.io / Javascript-Obfuscator
        if "SIG_STR_ARRAY" in sig_ids and "SIG_CFF" in sig_ids and metrics.get("unusual_variable_names", 0) > 10:
            return {
                "tool": "javascript-obfuscator (Obfuscator.io)", "confidence": "High",
                "evidence": "Signature trifecta: Control Flow Flattening, String Arrays, and Hexadecimal mangling (_0x).",
                "alternatives": "Custom obfuscator mirroring popular open-source tools."
            }
            
        # 3. Standard Minifier (Terser/Uglify)
        if "SIG_ID_MANGLING" in sig_ids and len(sig_ids) <= 2 and metrics.get("cyclomatic_complexity", 1) < 100:
             return {
                "tool": "Standard Minifier (Terser / UglifyJS)", "confidence": "Moderate",
                "evidence": "Mangling present without structural distortion or string arrays.",
                "alternatives": "Light custom obfuscation."
            }
             
        # 4. Custom
        if len(sig_ids) > 0:
             return {
                "tool": "Custom / Unknown Obfuscator", "confidence": "Low",
                "evidence": "Signatures match generic evasion techniques without pointing to a specific well-known tool.",
                "alternatives": "Heavily modified version of an open-source obfuscator."
            }
            
        return {
            "tool": "None / Unobfuscated", "confidence": "High",
            "evidence": "Lack of obfuscation signatures.",
            "alternatives": "None."
        }
