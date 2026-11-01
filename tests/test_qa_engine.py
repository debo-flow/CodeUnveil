import pytest
from qa_engine import QAEngine

def test_comprehensive_audit():
    engine = QAEngine()
    results = engine.run_comprehensive_audit()
    
    assert "environment" in results
    assert "python_version" in results["environment"]
    
    summ = results["summary"]
    assert summ["total"] > 0
    # The integration and integrity checks must pass
    assert summ["passed"] > 0
    assert summ["failed"] == 0 # We expect no internal engine failures in a healthy state
    
def test_html_report_generation():
    engine = QAEngine()
    engine.run_comprehensive_audit()
    html = engine.generate_html_report()
    
    assert "✅ CodeUnveil M24 Quality Assurance Report" in html
    assert "Environment: Python" in html
    assert "</html>" in html
