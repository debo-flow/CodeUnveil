import pytest
from cfg_engine import CFGAnalyzer

def test_basic_cfg_stats():
    engine = CFGAnalyzer()
    code = """
    if (x > 0) {
        for (let i = 0; i < 10; i++) {
            console.log(i);
        }
    }
    """
    res = engine.analyze(code)
    assert res["status"] == "success"
    assert res["stats"]["conditional_branches"] == 1
    assert res["stats"]["loops"] == 1

def test_cff_detection_and_state_transitions():
    engine = CFGAnalyzer()
    # Typical Obfuscator.io state machine wrapper
    code = """
    var _0xstate = 0;
    while(true) {
        switch(_0xstate) {
            case 0:
                doSomething();
                _0xstate = 1;
                break;
            case 1:
                end();
                _0xstate = 99;
                break;
        }
    }
    """
    res = engine.analyze(code)
    assert res["status"] == "success"
    assert res["cff"]["detected"] is True
    assert "_0xstate" in res["cff"]["state_variables"]
    
    transitions = res["cff"]["transitions"]
    assert len(transitions) == 2
    
    # Assert transitions mapped properly
    c0 = next(t for t in transitions if t["Case/State"] == "0")
    assert "1" in c0["Transitions To"]
    
    c1 = next(t for t in transitions if t["Case/State"] == "1")
    assert "99" in c1["Transitions To"]

def test_safe_simplification_dead_branch():
    engine = CFGAnalyzer()
    # Falsy test condition, consequent should be dropped
    code = "if (false) { console.log('Dead'); } else { console.log('Alive'); }"
    res = engine.analyze(code)
    
    assert res["status"] == "success"
    assert res["stats"]["unreachable_removed"] == 1
    
    transformed = engine.transform()
    assert "console.log('Alive');" in transformed
    assert "console.log('Dead');" not in transformed

def test_safe_simplification_truthy_branch():
    engine = CFGAnalyzer()
    # Truthy test condition, alternate should be dropped
    code = "if (1) { var x = 1; } else { var y = 2; }"
    res = engine.analyze(code)
    
    assert res["stats"]["unreachable_removed"] == 1
    transformed = engine.transform()
    
    assert "var x = 1;" in transformed
    assert "var y = 2;" not in transformed

def test_cfg_dot_generation():
    engine = CFGAnalyzer()
    code = "if (a) { while(b) { } }"
    res = engine.analyze(code)
    
    dot = res["dot_graph"]
    assert "digraph CFG" in dot
    assert "Branch" in dot
    assert "Loop" in dot
    assert "->" in dot # ensure edges exist
