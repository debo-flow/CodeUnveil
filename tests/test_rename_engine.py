import pytest
from rename_engine import RenameAnalyzer

def test_identifier_extraction_and_suspicious_detection():
    engine = RenameAnalyzer()
    code = "var _0x1a2b = 100; let readable = 200;"
    res = engine.analyze(code)
    
    assert res["status"] == "success"
    assert res["stats"]["total_identifiers"] == 2
    
    suspicious = [i for i in res["identifiers"] if i["is_suspicious"]]
    assert len(suspicious) == 1
    assert suspicious[0]["original_name"] == "_0x1a2b"
    assert "var_" in suspicious[0]["suggestion"]

def test_scope_shadowing_preservation():
    engine = RenameAnalyzer()
    code = """
    var x = 1;
    function outer() {
        var x = 2; // Shadows global x
        console.log(x);
    }
    """
    res = engine.analyze(code)
    
    # We should have two distinct 'x' identifiers because of shadowing
    x_idents = [i for i in res["identifiers"] if i["original_name"] == "x"]
    assert len(x_idents) == 2
    
    global_x = next(i for i in x_idents if i["scope_type"] == "global")
    func_x = next(i for i in x_idents if i["scope_type"] == "function")
    
    # The reference inside `console.log(x)` should belong to func_x
    assert len(func_x["ref_ranges"]) == 1
    assert len(global_x["ref_ranges"]) == 0

def test_object_property_safety():
    engine = RenameAnalyzer()
    # 'prop' should NOT be extracted as a renamable identifier because it is a static object key
    code = "var obj = { prop: 1 }; console.log(obj.prop);"
    res = engine.analyze(code)
    
    prop_idents = [i for i in res["identifiers"] if i["original_name"] == "prop"]
    assert len(prop_idents) == 0 # Successfully ignored static property keys and MemberExpression properties
    
    obj_idents = [i for i in res["identifiers"] if i["original_name"] == "obj"]
    assert len(obj_idents) == 1
    assert len(obj_idents[0]["ref_ranges"]) == 1 # console.log(obj)

def test_transformation_application():
    engine = RenameAnalyzer()
    code = "var _0xabc = 1; function test() { return _0xabc; }"
    res = engine.analyze(code)
    
    approved = [
        {
            "original_name": "_0xabc",
            "suggestion": "safe_var",
            "decl_range": res["identifiers"][0]["decl_range"],
            "ref_ranges": res["identifiers"][0]["ref_ranges"]
        }
    ]
    
    new_code = engine.transform(code, approved)
    assert "var safe_var = 1;" in new_code
    assert "return safe_var;" in new_code
    assert "_0xabc" not in new_code

def test_destructuring_extraction():
    engine = RenameAnalyzer()
    code = "let { a, b } = obj; let [c, d] = arr;"
    res = engine.analyze(code)
    
    names = [i["original_name"] for i in res["identifiers"]]
    assert "a" in names
    assert "b" in names
    assert "c" in names
    assert "d" in names
