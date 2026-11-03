import pytest
from intelligence_engine import AdvancedTaintAnalyzer
from benchmark_engine import BenchmarkLaboratory

def test_advanced_taint_analyzer():
    analyzer = AdvancedTaintAnalyzer()
    code = """
    var malicious_data = document.cookie;
    var transfer = malicious_data;
    eval(transfer);
    """
    res = analyzer.analyze(code)
    
    assert "malicious_data" in res["tainted_variables"]
    assert "transfer" in res["tainted_variables"]
    assert any("reaches dangerous sink 'eval()'" in f for f in res["findings"])

def test_benchmark_laboratory():
    lab = BenchmarkLaboratory()
    res = lab.run_suite({"apply_dce": True, "max_passes": 2})
    
    assert res["total_time_ms"] > 0
    assert res["fixtures_run"] == 4
    assert len(res["details"]) == 4
    # Check that exact hex obfuscation fixture passed
    assert res["details"][0]["status"] == "PASS"
