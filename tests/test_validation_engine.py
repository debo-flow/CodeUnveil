import pytest
from validation_engine import ASTComparator, SemanticValidator, ValidationEngine
import esprima

def test_ast_differential_analysis():
    # Original AST
    code1 = "var x = 1; function test() { return x; }"
    tree1 = ASTComparator._clean_ast(esprima.parseScript(code1))
    
    # Transformed AST (modified value, added console.log)
    code2 = "var x = 2; function test() { console.log('h'); return x; }"
    tree2 = ASTComparator._clean_ast(esprima.parseScript(code2))
    
    diff = ASTComparator.diff(tree1, tree2)
    
    # x=1 -> x=2 is a modification (Literal value changed)
    assert diff["modified"] >= 1
    # console.log addition means Nodes added
    assert diff["added"] >= 1
    # Function wrapper preserved
    assert diff["preserved"] >= 1

def test_dangerous_structural_shift_detection():
    # A CallExpression changed into an AssignmentExpression (Dangerous structural shift)
    code1 = "test();"
    code2 = "test = 1;"
    tree1 = ASTComparator._clean_ast(esprima.parseScript(code1))
    tree2 = ASTComparator._clean_ast(esprima.parseScript(code2))
    
    diff = ASTComparator.diff(tree1, tree2)
    assert len(diff["dangerous_changes"]) == 1
    assert "CallExpression -> AssignmentExpression" in diff["dangerous_changes"][0]

def test_metamorphic_parser_robustness():
    engine = ValidationEngine()
    res = engine.run_regression_suite()
    
    tests = res["tests"]
    fuzz_test = next(t for t in tests if t["id"] == "T_M19_01")
    
    # Ensuring the fuzzer safely caught exceptions from bad JS without crashing Python
    assert fuzz_test["status"] == "PASS"

def test_semantic_consistency_validator():
    code_orig = "var x = 1; window.global = x;"
    code_trans = "var x = 1; window.global = x; fetch('malicious');"
    
    # Pipeline injected a fetch (new side effect). Contract must flag it.
    res = SemanticValidator.validate(code_orig, code_trans)
    
    assert res["status"] == "success"
    assert res["side_effects_consistent"] is False
    assert any("DANGER" in issue and "fetch" in issue for issue in res["issues"])
