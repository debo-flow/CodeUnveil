import pytest
from function_engine import FunctionAnalyzer

def test_function_type_detection():
    engine = FunctionAnalyzer()
    code = """
    function namedDecl() {}
    var expr = function() {};
    var arrow = () => {};
    """
    res = engine.analyze(code)
    
    assert res["status"] == "success"
    assert res["stats"]["total_functions"] == 3
    assert res["stats"]["arrow_functions"] == 1
    assert res["stats"]["named_functions"] >= 1

def test_iife_detection():
    engine = FunctionAnalyzer()
    code = """
    (function(a, b) {
        console.log(a + b);
    })(1, 2);
    """
    res = engine.analyze(code)
    
    assert res["stats"]["iifes"] == 1
    assert res["iifes"][0]["params"] == 2
    assert res["iifes"][0]["args"] == 2

def test_wrapper_detection_and_inlining():
    engine = FunctionAnalyzer()
    # Constant wrapper and forwarding wrapper
    code = """
    function getConstant() { return 42; }
    function forwarder(x) { return targetFunc(x); }
    
    var a = getConstant();
    var b = forwarder(10);
    """
    res = engine.analyze(code)
    
    assert res["stats"]["wrappers_detected"] == 2
    
    replacements = res["simplifications"]
    assert len(replacements) == 2
    
    # Check Constant inline queue
    const_rep = next(r for r in replacements if r["type"] == "Constant Inline")
    assert const_rep["original_expression"] == "getConstant()"
    assert const_rep["resolved_value"] == "42"
    
    # Check Forward inline queue
    fwd_rep = next(r for r in replacements if r["type"] == "Forwarding Inline")
    assert fwd_rep["original_expression"] == "forwarder(10)"
    assert fwd_rep["replacement_str"] == "targetFunc"

def test_transformation_application():
    engine = FunctionAnalyzer()
    code = "function getC() { return 'hello'; } var a = getC();"
    res = engine.analyze(code)
    
    payload = [
        {
            "apply": True,
            "resolved_value": res["simplifications"][0]["resolved_value"],
            "range": res["simplifications"][0]["range"]
        }
    ]
    
    new_code = engine.transform(code, payload)
    assert "var a = 'hello';" in new_code
    assert "getC()" not in new_code

def test_call_graph_mapping():
    engine = FunctionAnalyzer()
    code = """
    function a() { b(); c(); }
    function b() { c(); }
    function c() {}
    """
    res = engine.analyze(code)
    
    dot = res["call_graph_dot"]
    assert 'digraph CallGraph' in dot
    assert '"a" -> "b";' in dot
    assert '"a" -> "c";' in dot
    assert '"b" -> "c";' in dot
