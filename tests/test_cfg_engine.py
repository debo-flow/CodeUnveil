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

def test_advanced_cff_linear_detection_and_deflatten():
    engine = CFGAnalyzer()
    # Typical Obfuscator.io linear split dispatcher
    code = """
    var _0xstate = '1|3|2'.split('|');
    var i = 0;
    while(true) {
        switch(_0xstate[i++]) {
            case '1':
                doFirst();
                continue;
            case '2':
                doThird();
                continue;
            case '3':
                doSecond();
                continue;
        }
        break;
    }
    """
    res = engine.analyze(code)
    
    assert res["status"] == "success"
    assert res["cff"]["detected"] is True
    assert "_0xstate" in res["cff"]["state_variables"]
    
    # Verify the State Transition Graph logic mapped the states
    assert len(res["cff"]["states"]["_0xstate"]) == 3
    
    # Verify Safe Reconstruction Queue caught the deterministic sequence
    queue = res["cff"]["reconstruction_queue"]
    assert len(queue) == 1
    assert queue[0]["type"] == "Deflatten Array Dispatcher"
    assert queue[0]["confidence"] == "High"
    
    # Reconstructed source should be linearly reordered: 1 -> 3 -> 2
    recon = queue[0]["reconstructed_code"]
    assert recon.index("doFirst()") < recon.index("doSecond()")
    assert recon.index("doSecond()") < recon.index("doThird()")

def test_cff_state_variable_transition_deflatten():
    engine = CFGAnalyzer()
    # Numeric state assignment transitions
    code = """
    var state = 1;
    while(true) {
        switch(state) {
            case 1:
                init();
                state = 5;
                break;
            case 5:
                process();
                state = 99;
                break;
            case 99:
                end();
                break;
        }
        if (state === 99) break;
    }
    """
    res = engine.analyze(code)
    
    assert res["cff"]["detected"] is True
    assert res["cff"]["initial_states"]["state"] == 1
    
    queue = res["cff"]["reconstruction_queue"]
    assert len(queue) == 1
    assert queue[0]["type"] == "Deflatten Linear Dispatcher"
    
    recon = queue[0]["reconstructed_code"]
    assert recon.index("init()") < recon.index("process()")
    assert recon.index("process()") < recon.index("end()")
    
def test_cfg_dot_generation():
    engine = CFGAnalyzer()
    code = "if (a) { while(b) { } }"
    res = engine.analyze(code)
    
    dot = res["dot_graph"]
    assert "digraph CFG" in dot
    assert "Branch" in dot
    assert "Loop" in dot
    assert "->" in dot
