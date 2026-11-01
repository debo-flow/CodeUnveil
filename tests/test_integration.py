import pytest
from perf_engine import PipelineOrchestrator, AnalysisCache

def test_full_pipeline_cross_module_integration():
    """Validates the Orchestrator safely manages dependencies across all analysis modules."""
    cache = AnalysisCache()
    orchestrator = PipelineOrchestrator(cache)
    
    code = """
    var arr = ['hello', 'world'];
    function test(idx) { return arr[idx]; }
    
    var state = 1;
    while(true) {
        switch(state) {
            case 1:
                console.log(test(0));
                state = 2;
                break;
            case 2:
                eval('danger');
                break;
        }
        if (state === 2) break;
    }
    """
    
    config = {
        "apply_dce": True,
        "apply_ast_regen": False,
        "run_sym_exec": True,
        "target_b": ""
    }
    
    res = orchestrator.execute(code, config)
    
    assert res["status"] == "Success"
    # M9: Array Integration
    assert res["m9_results"]["stats"]["total_arrays"] == 1
    # M14: CFG Integration
    assert res["m6_results"]["cff"]["detected"] is True
    # M13: Security Integration (Eval inside CFF)
    assert res["m13_results"]["summary"]["Critical"] >= 1
    # M18: Semantic Integration
    assert res["m18_results"]["stats"]["total_symbols"] >= 2
    # M19: Validation Integration
    assert res["m19_tests"]["stats"]["PASS"] >= 1
