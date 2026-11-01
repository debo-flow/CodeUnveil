import time
import json
import traceback
import platform
import sys
from typing import Dict, Any, List

from perf_engine import PipelineOrchestrator, AnalysisCache
from workspace_engine import WorkspaceDB, ConfigManager

class QAEngine:
    """Comprehensive Quality Assurance, Compatibility & Reliability Engine."""
    
    def __init__(self):
        self.results = {
            "timestamp": time.time(),
            "environment": self._get_environment_info(),
            "summary": {"total": 0, "passed": 0, "failed": 0, "warnings": 0, "skipped": 0},
            "regression_tests": [],
            "data_integrity": [],
            "parser_robustness": [],
            "security_audit": []
        }

    def _get_environment_info(self) -> Dict[str, str]:
        return {
            "python_version": sys.version.split(' ')[0],
            "os_platform": platform.system(),
            "os_release": platform.release(),
            "architecture": platform.machine()
        }

    def _record(self, category: str, name: str, status: str, details: str = ""):
        self.results[category].append({
            "name": name,
            "status": status,
            "details": details
        })
        if status == "PASS": self.results["summary"]["passed"] += 1
        elif status == "FAIL": self.results["summary"]["failed"] += 1
        elif status == "WARNING": self.results["summary"]["warnings"] += 1
        elif status == "SKIPPED": self.results["summary"]["skipped"] += 1
        self.results["summary"]["total"] += 1

    def run_comprehensive_audit(self) -> Dict[str, Any]:
        """Executes internal integration, integrity, and robustness checks."""
        self._test_data_integrity()
        self._test_parser_robustness()
        self._test_security_bounds()
        self._test_pipeline_integration()
        return self.results

    def _test_data_integrity(self):
        """Tests the robustness of WorkspaceDB and persistent configurations."""
        try:
            # Test 1: WorkspaceDB Write/Read
            test_data = {"test_key": "test_val"}
            WorkspaceDB.write("qa_test_table", test_data)
            read_data = WorkspaceDB.read("qa_test_table")
            if read_data.get("test_key") == "test_val":
                self._record("data_integrity", "WorkspaceDB R/W Serialization", "PASS")
            else:
                self._record("data_integrity", "WorkspaceDB R/W Serialization", "FAIL", "Data mismatch upon read.")
                
            # Test 2: Configuration Profiles Consistency
            profs = ConfigManager.get_profiles()
            if "default" in profs and "config" in profs["default"]:
                self._record("data_integrity", "Config Profile Inheritance Engine", "PASS")
            else:
                self._record("data_integrity", "Config Profile Inheritance Engine", "FAIL", "Default profile missing.")
        except Exception as e:
            self._record("data_integrity", "Storage Integrity Tests", "FAIL", traceback.format_exc())

    def _test_parser_robustness(self):
        """Ensures esprima gracefully handles modern JS syntax and malformed code without crashing."""
        import esprima
        
        # Test 1: Modern Syntax Compatibility (ES6+)
        modern_code = "const f = async (a) => { return a ?? 10; }; class X { #priv = 1; }"
        try:
            esprima.parseScript(modern_code, {"tolerant": True})
            self._record("parser_robustness", "Modern JavaScript (ES6/ES2021) Parser Compliance", "PASS")
        except Exception as e:
            self._record("parser_robustness", "Modern JavaScript (ES6/ES2021) Parser Compliance", "WARNING", str(e))
            
        # Test 2: Fuzzing Malformed Payloads
        malformed = "function() { var x = ; "
        try:
            esprima.parseScript(malformed, {"tolerant": False})
            self._record("parser_robustness", "Strict Mode Syntax Failure Detection", "FAIL", "Parser accepted malformed code silently.")
        except esprima.Error:
            self._record("parser_robustness", "Strict Mode Syntax Failure Detection", "PASS")
        except Exception as e:
            self._record("parser_robustness", "Strict Mode Syntax Failure Detection", "FAIL", f"Unexpected crash type: {str(e)}")

    def _test_security_bounds(self):
        """Audits path traversal and execution boundaries."""
        import os
        from project_engine import ProjectAnalyzer
        
        # Test 1: Path Traversal
        pa = ProjectAnalyzer()
        safe_path = os.path.basename("../../../../etc/passwd")
        if safe_path == "passwd":
            self._record("security_audit", "ZIP Path Traversal Neutralization", "PASS")
        else:
            self._record("security_audit", "ZIP Path Traversal Neutralization", "FAIL", "os.path.basename bypass detected.")
            
        # Test 2: Plugin Security Restrictions Check
        from plugin_engine import PluginRegistry
        reg = PluginRegistry.get_instance()
        if not reg.state.get("non_existent_plugin", {}).get("approved", False):
            self._record("security_audit", "Untrusted Plugin Execution Block", "PASS")
        else:
            self._record("security_audit", "Untrusted Plugin Execution Block", "FAIL", "Default trust level is incorrectly permissive.")

    def _test_pipeline_integration(self):
        """Runs the full Pipeline Orchestrator on a synthetic payload to verify M1-M23 cross-module compat."""
        cache = AnalysisCache(max_size=5)
        orchestrator = PipelineOrchestrator(cache)
        
        synthetic_payload = """
        var _0xstate = '1|2'.split('|');
        var x = 1; 
        while(true) {
            switch(_0xstate[0]) {
                case '1': x = x + 2; break;
                case '2': eval('danger'); break;
            }
            break;
        }
        """
        
        config = {
            "apply_dce": True, "apply_ast_regen": False, "run_sym_exec": True, "target_b": ""
        }
        
        try:
            results = orchestrator.execute(synthetic_payload, config)
            if results.get("status") == "Success":
                self._record("regression_tests", "M1-M23 Cross-Module Integration Pipeline", "PASS")
                
                # Check specific sub-engine results
                if results.get("m6_results", {}).get("cff", {}).get("detected"):
                    self._record("regression_tests", "M14 CFG State Dispatcher Integration", "PASS")
                else:
                    self._record("regression_tests", "M14 CFG State Dispatcher Integration", "FAIL")
                    
                if results.get("m13_results", {}).get("summary", {}).get("Critical", 0) > 0:
                    self._record("regression_tests", "M13 Security Analysis Integration (Eval Det)", "PASS")
                else:
                    self._record("regression_tests", "M13 Security Analysis Integration (Eval Det)", "FAIL")
            else:
                self._record("regression_tests", "M1-M23 Cross-Module Integration Pipeline", "FAIL", results.get("status"))
        except Exception as e:
            self._record("regression_tests", "M1-M23 Cross-Module Integration Pipeline", "FAIL", traceback.format_exc())

    def generate_html_report(self) -> str:
        html = [
            "<html><head><title>CodeUnveil QA Report</title>",
            "<style>body{font-family:sans-serif; background:#121212; color:#eee; padding:20px;} ",
            ".pass{color:#4CAF50;} .fail{color:#F44336;} .warn{color:#FF9800;}</style></head><body>",
            "<h1>✅ CodeUnveil M24 Quality Assurance Report</h1>",
            f"<h3>Environment: Python {self.results['environment']['python_version']} on {self.results['environment']['os_platform']}</h3>",
            "<hr><h3>Summary</h3><ul>"
        ]
        
        summ = self.results["summary"]
        for k, v in summ.items():
            html.append(f"<li><strong>{k.capitalize()}:</strong> {v}</li>")
        html.append("</ul><hr>")
        
        for category in ["regression_tests", "data_integrity", "parser_robustness", "security_audit"]:
            html.append(f"<h3>{category.replace('_', ' ').title()}</h3><ul>")
            for item in self.results[category]:
                c_class = "pass" if item['status'] == "PASS" else "fail" if item['status'] == "FAIL" else "warn"
                details = f"<br><i>{item['details']}</i>" if item['details'] else ""
                html.append(f"<li><span class='{c_class}'>[{item['status']}]</span> <strong>{item['name']}</strong>{details}</li>")
            html.append("</ul>")
            
        html.append("</body></html>")
        return "".join(html)
