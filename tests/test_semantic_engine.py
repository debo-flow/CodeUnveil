import pytest
from semantic_engine import SemanticAnalyzer

def test_type_inference_basic_and_union():
    engine = SemanticAnalyzer()
    code = """
    var num = 10;
    var str = "hello";
    var union = num + str; // Should infer string because of coercion
    var num2 = num * 2;    // Should infer number
    """
    res = engine.analyze(code)
    
    assert res["status"] == "success"
    symbols = res["symbols"]
    
    union_sym = next(s for s in symbols if s["name"] == "union")
    assert "String" in union_sym["types"]
    
    num_sym = next(s for s in symbols if s["name"] == "num2")
    assert "Number" in num_sym["types"]

def test_symbol_table_read_write_tracking():
    engine = SemanticAnalyzer()
    code = """
    var x = 1;     // Write 1
    x = 2;         // Write 2
    console.log(x);// Read 1
    var y = x;     // Read 2 (for x), Write 1 (for y)
    """
    res = engine.analyze(code)
    
    symbols = res["symbols"]
    x_sym = next(s for s in symbols if s["name"] == "x")
    assert x_sym["writes"] == 2
    assert x_sym["reads"] == 2
    
    y_sym = next(s for s in symbols if s["name"] == "y")
    assert y_sym["writes"] == 1
    assert y_sym["reads"] == 0

def test_function_semantic_classification():
    engine = SemanticAnalyzer()
    code = """
    function doMath(a, b) {
        return a * b + 10;
    }
    
    function fetchPayload(url) {
        fetch(url);
    }
    """
    res = engine.analyze(code)
    funcs = res["functions"]
    
    assert "Mathematical Operation" in funcs["doMath"]["classification"]
    assert "Number" in funcs["doMath"]["inferred_return_types"]
    
    assert "Network Interaction" in funcs["fetchPayload"]["classification"]
    assert funcs["fetchPayload"]["has_side_effects"] is True

def test_side_effect_detection():
    engine = SemanticAnalyzer()
    code = "window.attack = 1; document.body.innerHTML = 'x';"
    res = engine.analyze(code)
    
    effects = res["side_effects"]
    assert len(effects) == 2
    assert any("Global Mutation" in e for e in effects)
    assert any("DOM Mutation" in e for e in effects)

def test_data_dependency_graph():
    engine = SemanticAnalyzer()
    code = "var a = 1; var b = a;"
    res = engine.analyze(code)
    
    dot = res["dependency_graph_dot"]
    assert '"a" -> "b"' in dot
