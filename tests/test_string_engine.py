import pytest
from string_engine import StringAnalyzer

def test_hex_unicode_decoding():
    engine = StringAnalyzer()
    code = "var a = '\\x48\\x65\\x6c\\x6c\\x6f'; var b = '\\u0057\\u006f\\u0072\\u006c\\u0064';"
    result = engine.analyze(code)
    
    assert result["status"] == "success"
    assert result["stats"]["encoded_strings"] == 2
    assert result["stats"]["decoded_strings"] == 2
    
    transformed = engine.transform()
    assert '"Hello"' in transformed
    assert '"World"' in transformed

def test_static_concatenation_folding():
    engine = StringAnalyzer()
    code = "var greeting = 'He' + 'll' + 'o ' + 'World';"
    result = engine.analyze(code)
    
    assert result["status"] == "success"
    assert result["stats"]["concatenations_folded"] >= 1
    
    transformed = engine.transform()
    assert '"Hello World"' in transformed
    assert "'He'" not in transformed

def test_dynamic_concatenation_ignored():
    engine = StringAnalyzer()
    code = "var greeting = 'Hello ' + userName + '!';"
    result = engine.analyze(code)
    
    assert result["status"] == "success"
    assert result["stats"]["concatenations_folded"] == 0 # Must ignore dynamic vars
    
    transformed = engine.transform()
    assert "'Hello '" in transformed # Unchanged

def test_string_array_detection():
    engine = StringAnalyzer()
    code = "var _0xabc = ['\\x61', '\\x62', '\\x63', 'd'];"
    result = engine.analyze(code)
    
    assert result["status"] == "success"
    assert result["stats"]["string_arrays_detected"] == 1
    assert result["arrays"][0]["size"] == 4
    
    transformed = engine.transform()
    assert '"a"' in transformed
    assert '"b"' in transformed

def test_overlap_resolution_safety():
    engine = StringAnalyzer()
    # Encoded strings INSIDE a concatenation. Engine should fold it cleanly into ONE string.
    code = "var res = '\\x61' + '\\x62' + '\\x63';"
    result = engine.analyze(code)
    
    transformed = engine.transform()
    assert '"abc"' in transformed
