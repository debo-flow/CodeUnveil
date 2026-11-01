import esprima
import time
import json
import traceback
from typing import Dict, Any, List, Tuple
from semantic_engine import SemanticAnalyzer

class TestCase:
    def __init__(self, t_id: str, name: str, category: str, desc: str, milestone: str):
        self.id = t_id
        self.name = name
        self.category = category
        self.description = desc
        self.milestone = milestone
        self.status = "UNKNOWN"
        self.error_info = ""
        self.duration_ms = 0.0

class ASTComparator:
    """Performs deep structural Differential Analysis between two ASTs."""
    
    @staticmethod
    def _clean_ast(node: Any) -> Any:
        if isinstance(node, list):
            return [ASTComparator._clean_ast(n) for n in node]
        if hasattr(node, 'type'):
            res = {'type': node.type}
            for k, v in vars(node).items():
                if k in ['type', 'loc', 'range', 'parent']: continue
                if isinstance(v, (list, dict)) or hasattr(v, 'type'):
                    res[k] = ASTComparator._clean_ast(v)
                else: res[k] = v
            return res
        return node

    @staticmethod
    def diff(ast1_dict: Any, ast2_dict: Any) -> Dict[str, Any]:
        stats = {"added": 0, "removed": 0, "modified": 0, "preserved": 0, "dangerous_changes": []}
        
        def compare(n1, n2, path=""):
            if type(n1) != type(n2):
                stats["modified"] += 1
                return
            
            if isinstance(n1, dict) and isinstance(n2, dict):
                if n1.get('type') != n2.get('type'):
                    stats["modified"] += 1
                    # Flag dangerous structural changes
                    if n1.get('type') in ['CallExpression', 'AssignmentExpression'] or n2.get('type') in ['CallExpression', 'AssignmentExpression']:
                        stats["dangerous_changes"].append(f"Structure altered at {path}: {n1.get('type')} -> {n2.get('type')}")
                    return
                
                stats["preserved"] += 1
                all_keys = set(n1.keys()).union(set(n2.keys()))
                for k in all_keys:
                    if k not in n1:
                        stats["added"] += 1
                    elif k not in n2:
                        stats["removed"] += 1
                    else:
                        compare(n1[k], n2[k], path + f".{k}")
                        
            elif isinstance(n1, list) and isinstance(n2, list):
                len1, len2 = len(n1), len(n2)
                for i in range(min(len1, len2)):
                    compare(n1[i], n2[i], path + f"[{i}]")
                if len2 > len1: stats["added"] += (len2 - len1)
                elif len1 > len2: stats["removed"] += (len1 - len2)
            else:
                if n1 != n2: stats["modified"] += 1
                else: stats["preserved"] += 1

        compare(ast1_dict, ast2_dict, "Program")
        return stats

class SemanticValidator:
    """Validates Semantic Consistency between Original and Transformed code."""
    
    @staticmethod
    def validate(orig_code: str, trans_code: str) -> Dict[str, Any]:
        engine = SemanticAnalyzer()
        orig_res = engine.analyze(orig_code)
        trans_res = engine.analyze(trans_code)
        
        issues = []
        if orig_res["status"] != "success" or trans_res["status"] != "success"]:
            return {"status": "error", "issues": ["Semantic analysis failed during validation."]}
            
        orig_syms = {s["name"]: s for s in orig_res["symbols"]}
        trans_syms = {s["name"]: s for s in trans_res["symbols"]}
        
        # Check for unexpectedly missing symbols
        for name in orig_syms:
            if name not in trans_syms:
                # Might be DCE, mark as warning rather than error
                issues.append(f"WARNING: Symbol '{name}' disappeared. (Safe if DCE applied)")
                
        # Check side-effect consistency
        orig_se = set(orig_res["side_effects"])
        trans_se = set(trans_res["side_effects"])
        
        new_se = trans_se - orig_se
        if new_se:
            issues.append(f"DANGER: Transformation introduced new side-effects: {', '.join(new_se)}")
            
        return {
            "status": "success",
            "issues": issues,
            "symbols_preserved": len(trans_syms),
            "side_effects_consistent": len(new_se) == 0
        }

class TransformationContract:
    def __init__(self, rule_id: str, name: str, pre_cond: callable, post_cond: callable):
        self.rule_id = rule_id
        self.name = name
        self.pre_cond = pre_cond
        self.post_cond = post_cond

class ValidationEngine:
    """Automated Testing, Differential Analysis, and Behavioral Validation Framework."""

    def __init__(self):
        self.tests = []
        self.results = {}

    def _run_test(self, test: TestCase, test_fn: callable):
        start = time.time()
        try:
            res = test_fn()
            test.status = "PASS" if res else "FAIL"
            if not res: test.error_info = "Validation assertion failed."
        except Exception as e:
            test.status = "FAIL"
            test.error_info = traceback.format_exc()
        finally:
            test.duration_ms = (time.time() - start) * 1000
            self.tests.append(test)

    def run_regression_suite(self) -> Dict[str, Any]:
        self.tests = []
        
        # M1: Formatter Idempotency (Metamorphic Property)
        def m1_idempotence():
            from app import DeobfuscatorEngine
            c, _ = DeobfuscatorEngine.process("var x=1;")
            c2, _ = DeobfuscatorEngine.process(c)
            return c == c2
        self._run_test(TestCase("T_M1_01", "Formatter Idempotence", "Metamorphic", "Repeated formatting should not mutate code.", "M1"), m1_idempotence)
        
        # M19: Parser Robustness Fuzzing
        def parser_fuzz():
            bad_code = ["function() { var x = ; }", "let 0x_invalid = 1;", "const x = 'missing_quote;"]
            for bad in bad_code:
                try:
                    esprima.parseScript(bad)
                    return False # Should have raised an error
                except esprima.Error:
                    continue
            return True
        self._run_test(TestCase("T_M19_01", "Parser Robustness Fuzzer", "Robustness", "Ensure malformed JS throws safely without crashing engine.", "M19"), parser_fuzz)

        # M11: Constant Folding Property
        def m11_constant_fold():
            from expr_engine import ExprAnalyzer
            res = ExprAnalyzer().analyze("var x = 2 + 3;")
            return any(r["resolved"] == "5" for r in res["replacements"])
        self._run_test(TestCase("T_M11_01", "Constant Folding Contract", "Unit", "2+3 must statically fold to 5.", "M11"), m11_constant_fold)

        stats = {"PASS": 0, "FAIL": 0, "WARNING": 0}
        for t in self.tests: stats[t.status] = stats.get(t.status, 0) + 1
        
        return {
            "tests": [vars(t) for t in self.tests],
            "stats": stats
        }

    def run_differential_analysis(self, orig_code: str, trans_code: str) -> Dict[str, Any]:
        """Runs AST Diffing and Semantic Consistency checks between code states."""
        try:
            tree1 = esprima.parseScript(orig_code, {"tolerant": True})
            tree2 = esprima.parseScript(trans_code, {"tolerant": True})
            
            ast1_dict = ASTComparator._clean_ast(tree1)
            ast2_dict = ASTComparator._clean_ast(tree2)
            
            ast_diff = ASTComparator.diff(ast1_dict, ast2_dict)
            sem_diff = SemanticValidator.validate(orig_code, trans_code)
            
            return {
                "ast_diff": ast_diff,
                "semantic_diff": sem_diff
            }
        except Exception as e:
            return {"error": str(e)}
