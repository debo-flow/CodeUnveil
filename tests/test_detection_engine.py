import pytest
from detection_engine import DetectionEngine
from ast_engine import ASTAnalyzer

def test_signature_id_mangling():
    ast_metrics = {
        "status": "success",
        "stats": {"variables": 10},
        "complexity": {"unusual_variable_names": 6}
    }
    engine = DetectionEngine()
    res = engine.analyze("var _0x123=1;", ast_metrics)
    
    sigs = [s["id"] for s in res["detected_signatures"]]
    assert "SIG_ID_MANGLING" in sigs
    assert res["severity_level"] >= 1

def test_obfuscator_io_fingerprint():
    ast_metrics = {
        "status": "success",
        "stats": {"variables": 20},
        "complexity": {
            "unusual_variable_names": 15,
            "large_string_collections": 1,
            "switch_in_loop": 1
        }
    }
    engine = DetectionEngine()
    res = engine.analyze("var _0xabc = ['a']; while(!![]){switch(x){}}", ast_metrics)
    
    assert res["severity_level"] >= 4
    assert "javascript-obfuscator" in res["fingerprint"]["tool"]
    assert res["fingerprint"]["confidence"] == "High"

def test_webpack_fingerprint():
    code = "function(module, exports, __webpack_require__) { var x = 1; }"
    ast_metrics = {"status": "success", "stats": {}, "complexity": {}}
    
    engine = DetectionEngine()
    res = engine.analyze(code, ast_metrics)
    
    assert "Webpack" in res["fingerprint"]["tool"]

def test_clean_code():
    ast_metrics = {
        "status": "success",
        "stats": {"variables": 5},
        "complexity": {"unusual_variable_names": 0, "switch_in_loop": 0}
    }
    engine = DetectionEngine()
    res = engine.analyze("let x = 10; console.log(x);", ast_metrics)
    
    assert res["severity_level"] == 0
    assert len(res["detected_signatures"]) == 0
    assert "Unobfuscated" in res["fingerprint"]["tool"]

def test_cff_and_debug_protection():
    ast_metrics = {
        "status": "success",
        "stats": {},
        "complexity": {
            "switch_in_loop": 2,
            "debugger_statements": 3
        }
    }
    engine = DetectionEngine()
    res = engine.analyze("while(1){switch(x){}} debugger;", ast_metrics)
    
    sigs = [s["id"] for s in res["detected_signatures"]]
    assert "SIG_CFF" in sigs
    assert "SIG_DEBUG_PROTECT" in sigs
    assert res["severity_level"] >= 4
