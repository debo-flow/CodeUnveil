import pytest
from array_engine import ArrayAnalyzer

def test_array_detection():
    engine = ArrayAnalyzer()
    code = "var strings = ['a', 'b', 'c', 'd']; var not_strings = [1, 2];"
    res = engine.analyze(code)
    
    assert res["status"] == "success"
    assert "strings" in res["arrays"]
    assert "not_strings" not in res["arrays"] # Too small/not strings
    assert len(res["arrays"]["strings"]["elements"]) == 4

def test_accessor_mapping():
    engine = ArrayAnalyzer()
    code = """
    var arr = ['hello', 'world', 'test', 'data'];
    function getString(idx) {
        return arr[idx];
    }
    """
    res = engine.analyze(code)
    
    assert "getString" in res["accessors"]
    assert res["accessors"]["getString"]["array_name"] == "arr"

def test_rotation_detection():
    engine = ArrayAnalyzer()
    code = """
    var arr = ['hello', 'world', 'test', 'data'];
    (function(a) {
        while(true) {
            a.push(a.shift());
        }
    })(arr);
    """
    res = engine.analyze(code)
    
    assert res["arrays"]["arr"]["is_rotated"] is True

def test_lookup_resolution():
    engine = ArrayAnalyzer()
    code = """
    var arr = ['hello', 'world', 'test', 'data'];
    function getString(idx) { return arr[idx]; }
    
    console.log(arr[0]);
    console.log(getString(1));
    """
    res = engine.analyze(code)
    
    lookups = res["lookups"]
    assert len(lookups) == 2
    
    direct = next(l for l in lookups if l["original_expression"] == "arr[0]")
    assert direct["resolved_value"] == "hello"
    assert "High" in direct["confidence"]
    
    func = next(l for l in lookups if l["original_expression"] == "getString(1)")
    assert func["resolved_value"] == "world"

def test_safe_transformation():
    engine = ArrayAnalyzer()
    code = "var arr = ['hello', 'world', 'test', 'data']; console.log(arr[0]);"
    res = engine.analyze(code)
    
    payload = [
        {
            "apply": True,
            "resolved_value": res["lookups"][0]["resolved_value"],
            "range": res["lookups"][0]["range"]
        }
    ]
    
    new_code = engine.transform(code, payload)
    assert 'console.log("hello");' in new_code
