import pytest
from dce_engine import DCEAnalyzer

def test_unused_variables_and_functions():
    engine = DCEAnalyzer()
    code = """
    var unusedGlobal = 1;
    function unusedFunc() {}
    function activeFunc() {
        let unusedLocal = 2;
        const usedLocal = 3;
        console.log(usedLocal);
    }
    activeFunc();
    """
    res = engine.analyze(code)
    assert res["status"] == "success"
    
    unused_names = [u["name"] for u in res["unused"]]
    assert "unusedGlobal" in unused_names
    assert "unusedFunc" in unused_names
    assert "unusedLocal" in unused_names
    
    assert "activeFunc" not in unused_names
    assert "usedLocal" not in unused_names
    
    # Assert Safe Deletion queue
    assert res["stats"]["safely_removable"] >= 3

def test_shadowed_scope_preservation():
    engine = DCEAnalyzer()
    code = """
    var x = 1; 
    function test() {
        var x = 2; // Shadows outer x
        console.log(x);
    }
    test();
    """
    res = engine.analyze(code)
    
    unused_names = [u["name"] for u in res["unused"]]
    # The outer 'x' is completely unused because the inner 'x' shadows and satisfies the reference.
    # We expect exactly one unused var tracking here (the outer one).
    assert unused_names.count("x") == 1

def test_unreachable_code_after_return():
    engine = DCEAnalyzer()
    code = """
    function calc() {
        var a = 1;
        return a;
        console.log("Dead code");
        var b = 2;
    }
    """
    res = engine.analyze(code)
    assert res["stats"]["unreachable_statements"] == 2 # The console.log and var b=2 are both dead

def test_unreachable_code_after_throw():
    engine = DCEAnalyzer()
    code = """
    function crash() {
        throw new Error("Crash");
        console.log("Never happens");
    }
    """
    res = engine.analyze(code)
    assert res["stats"]["unreachable_statements"] == 1

def test_constant_conditions_dead_branches():
    engine = DCEAnalyzer()
    code = """
    if (false) {
        console.log("Dead branch");
    }
    """
    res = engine.analyze(code)
    assert res["stats"]["unreachable_statements"] == 1

def test_safe_destructive_transformation():
    engine = DCEAnalyzer()
    code = "var deadVar = 1; console.log('Alive'); if (false) { console.log('Dead'); }"
    res = engine.analyze(code)
    
    assert res["status"] == "success"
    
    transformed = engine.transform()
    assert "console.log('Alive');" in transformed
    assert "var deadVar" not in transformed
    assert "console.log('Dead');" not in transformed
