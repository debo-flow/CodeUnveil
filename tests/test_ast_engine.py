import pytest
from ast_engine import ASTAnalyzer

def test_ast_parsing_basic():
    engine = ASTAnalyzer()
    code = "let x = 10; const y = 20;"
    result = engine.analyze(code)
    
    assert result["status"] == "success"
    assert result["stats"]["variables"] == 1
    assert result["stats"]["constants"] == 1
    assert result["stats"]["numeric_literals"] == 2

def test_ast_functions_and_complexity():
    engine = ASTAnalyzer()
    code = """
    function main(data) {
        if (data > 0) {
            for(let i=0; i<data; i++) {
                console.log("Processing");
            }
        }
    }
    """
    result = engine.analyze(code)
    
    assert result["status"] == "success"
    assert result["stats"]["functions"] == 1
    assert result["stats"]["conditionals"] == 1
    assert result["stats"]["loops"] == 1
    assert result["stats"]["string_literals"] == 1
    assert result["stats"]["function_calls"] == 1
    # Base(1) + If(1) + For(1)
    assert result["complexity"]["cyclomatic_complexity"] >= 3

def test_ast_obfuscation_patterns():
    engine = ASTAnalyzer()
    code = """
    var _0x1a2b = ['string1', 'string2', 'string3', 'string4', 's5', 's6', 's7', 's8', 's9', 's10', 's11'];
    function a() {
        return window['document'];
    }
    """
    result = engine.analyze(code)
    
    assert result["status"] == "success"
    assert result["complexity"]["large_string_collections"] == 1
    assert result["complexity"]["unusual_variable_names"] >= 1
    assert result["complexity"]["computed_property_access"] == 1

def test_ast_error_handling():
    engine = ASTAnalyzer()
    
    # 1. Syntax Error
    bad_code = "let x = ; function () {}"
    result = engine.analyze(bad_code)
    assert result["status"] == "error"
    assert "AST Parsing Error" in result["message"]

    # 2. Empty Input
    with pytest.raises(ValueError):
        engine.analyze("")

    # 3. Size limit test
    with pytest.raises(ValueError):
        large_code = "var x = 1;" * (1024 * 1024)
        engine.analyze(large_code)
