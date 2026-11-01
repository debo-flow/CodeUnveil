import pytest
from sym_engine import SymEngine

def test_sym_feasible_branch():
    engine = SymEngine()
    code = """
    var x = 15;
    if (x > 10) {
        var y = 1;
    } else {
        var y = 2;
    }
    """
    res = engine.analyze(code)
    
    assert res["status"] == "success"
    stats = res["stats"]
    assert stats["feasible_branches"] >= 1
    assert stats["infeasible_branches"] == 1 # The 'else' branch (15 <= 10) is UNSAT

def test_sym_contradiction_infeasible():
    engine = SymEngine()
    code = """
    var x = 5;
    if (x > 10) {
        if (x < 3) {
            var unreachable = true;
        }
    }
    """
    res = engine.analyze(code)
    
    # x = 5 -> x > 10 is false -> outer if is Infeasible
    assert res["stats"]["infeasible_branches"] >= 1

def test_sym_dynamic_reassignment():
    engine = SymEngine()
    code = """
    var x = 1;
    x = 10;
    if (x == 10) {
        var success = true;
    }
    """
    res = engine.analyze(code)
    
    # After reassignment, condition is SAT
    paths = res["paths"]
    feasible = [p for p in paths if p["status"] == "Feasible" and "If (True)" in p["block_name"]]
    assert len(feasible) == 1

def test_sym_bounded_loop_unrolling():
    engine = SymEngine(max_loop_iter=2)
    code = """
    var i = 0;
    while(i < 5) {
        i += 1;
    }
    """
    res = engine.analyze(code)
    
    paths = res["paths"]
    # Ensure it bounds out and flags as Unknown or bounds out
    limit_paths = [p for p in paths if "Loop Bounded" in p["block_name"]]
    assert len(limit_paths) >= 1
    
def test_sym_unsupported_type_fallback():
    engine = SymEngine()
    code = """
    var str = "Hello";
    if (str == "World") {
        var a = 1;
    }
    """
    res = engine.analyze(code)
    # Since string constraint models are bounded/complex, we expect Unknown or fallback.
    assert res["status"] == "success"
