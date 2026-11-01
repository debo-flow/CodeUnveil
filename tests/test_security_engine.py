import pytest
from security_engine import SecurityAnalyzer

def test_eval_detection():
    engine = SecurityAnalyzer()
    code = "var payload = 'alert(1)'; eval(payload);"
    res = engine.analyze(code)
    
    assert res["status"] == "success"
    assert res["summary"]["Critical"] >= 1
    
    finding = next(f for f in res["findings"] if f["rule_id"] == "SEC_DYN_EVAL")
    assert finding["severity"] == "Critical"
    assert "eval(payload)" in finding["snippet"]

def test_dom_xss_detection():
    engine = SecurityAnalyzer()
    code = "document.getElementById('div').innerHTML = '<img src=x onerror=alert(1)>';"
    res = engine.analyze(code)
    
    finding = next(f for f in res["findings"] if f["rule_id"] == "SEC_DOM_XSS")
    assert finding["severity"] == "High"

def test_source_to_sink_taint_tracking():
    engine = SecurityAnalyzer()
    # Taint flows from location.search -> user_input -> eval
    code = """
    var user_input = window.location.search;
    eval(user_input);
    """
    res = engine.analyze(code)
    
    # Check if taint path was identified
    taint_finding = next((f for f in res["findings"] if f["rule_id"] == "SEC_DATA_FLOW"), None)
    assert taint_finding is not None
    assert taint_finding["severity"] == "Critical"
    assert "location.search" in code
    
def test_false_positive_rejection():
    # Simple assignment, no sink
    engine = SecurityAnalyzer()
    code = "var x = 1; var y = x + 2;"
    res = engine.analyze(code)
    assert res["total_findings"] == 0

def test_obfuscation_risk_integration():
    engine = SecurityAnalyzer()
    code = "var x = 1;"
    m5_metrics = {"status": "success", "severity_level": 4} # High Obfuscation
    
    res = engine.analyze(code, obfuscation_metrics=m5_metrics)
    obf_finding = next(f for f in res["findings"] if f["rule_id"] == "SEC_OBFUSCATION_RISK")
    assert obf_finding["severity"] == "High"
    
def test_network_and_storage_detection():
    engine = SecurityAnalyzer()
    code = "fetch('http://malicious.com'); var token = localStorage.getItem('token');"
    res = engine.analyze(code)
    
    rules_fired = [f["rule_id"] for f in res["findings"]]
    assert "SEC_NET_FETCH" in rules_fired
    assert "SEC_STORAGE" in rules_fired
