import pytest
from perf_engine import AnalysisCache, PipelineOrchestrator

def test_cache_hit_ratio_and_fingerprint():
    cache = AnalysisCache(max_size=5)
    source = "var x = 1;"
    config = {"apply_dce": True}
    
    # Run 1: Miss
    res1 = cache.get(source, config)
    assert res1 is None
    
    # Store
    cache.put(source, config, {"status": "success", "data": 123})
    
    # Run 2: Hit
    res2 = cache.get(source, config)
    assert res2 is not None
    assert res2["data"] == 123
    
    # Run 3: Config Change -> Miss
    res3 = cache.get(source, {"apply_dce": False})
    assert res3 is None
    
    stats = cache.get_stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 2
    assert stats["ratio"] == round((1/3)*100, 2)

def test_pipeline_orchestrator_execution():
    cache = AnalysisCache(max_size=5)
    orchestrator = PipelineOrchestrator(cache)
    
    source = "function test() { return 1 + 2; }"
    config = {"apply_dce": False, "apply_ast_regen": False, "run_sym_exec": False}
    
    # End-to-end execution
    res = orchestrator.execute(source, config)
    
    # Verify monolithic result structure
    assert res["status"] == "Success"
    assert "m1_results" in res
    assert "m11_results" in res
    
    # Verify Profiler successfully wrapped the execution
    assert "profiler_stats" in res
    assert "total_time_ms" in res["profiler_stats"]
    assert "stages" in res["profiler_stats"]
    
    # Verify cache write occurred
    stats = cache.get_stats()
    assert stats["size"] == 1

def test_orchestrator_cache_bypass():
    cache = AnalysisCache(max_size=5)
    orchestrator = PipelineOrchestrator(cache)
    source = "var x = 1;"
    config = {"apply_dce": False}
    
    res1 = orchestrator.execute(source, config)
    assert res1["profiler_stats"]["cached_run"] is False
    
    # Second execution MUST skip computation and flag cached_run
    res2 = orchestrator.execute(source, config)
    assert res2["profiler_stats"]["cached_run"] is True
