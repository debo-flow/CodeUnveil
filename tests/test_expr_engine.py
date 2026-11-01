import pytest
from expr_engine import ExprAnalyzer

def test_arithmetic_constant_folding():
    engine = ExprAnalyzer()
    code = "var x = 2 + 3 * 4; var y = 'Hello ' + 'World';"
    res = engine.analyze(code)
    
    reps = res["replacements"]
    # 3 * 4 -> 12, 2 + 12 -> 14
    assert any(r["resolved"] == "14" for r in reps)
    assert any(r["resolved"] == '"Hello World"' for r in reps)

def test_constant_propagation():
    engine = ExprAnalyzer()
    code = "const a = 10; const b = a + 5;"
    res = engine.analyze(code)
    
    reps = res["replacements"]
    assert any(r["type"] == "Constant Propagation" and r["resolved"] == "10" for r in reps)
    assert any(r["type"] == "Binary Constant Fold" and r["resolved"] == "15" for r in reps)

def test_prevent_propagation_on_mutation():
    engine = ExprAnalyzer()
    # 'a' is mutated, so it should NOT be propagated, but 'c' is safe.
    code = "let a = 10; a++; const c = 5; let b = a + c;"
    res = engine.analyze(code)
    
    reps = res["replacements"]
    assert not any(r["original"] == "a" for r in reps) # 'a' is unsafe
    assert any(r["original"] == "c" and r["resolved"] == "5" for r in reps) # 'c' is safe

def test_js_semantics_division_by_zero():
    engine = ExprAnalyzer()
    code = "var pos = 1 / 0; var neg = -1 / 0; var nan = 0 / 0;"
    res = engine.analyze(code)
    
    reps = res["replacements"]
    assert any(r["resolved"] == "Infinity" for r in reps)
    assert any(r["resolved"] == "-Infinity" for r in reps)
    assert any(r["resolved"] == "NaN" for r in reps)

def test_bitwise_32bit_casts():
    engine = ExprAnalyzer()
    code = "var x = 5 | 2; var y = ~5; var z = 4294967295 >> 0;"
    res = engine.analyze(code)
    
    reps = res["replacements"]
    assert any(r["resolved"] == "7" for r in reps)     # 5 | 2
    assert any(r["resolved"] == "-6" for r in reps)    # ~5
    assert any(r["resolved"] == "-1" for r in reps)    # 4294967295 as int32 is -1

def test_arithmetic_simplification_redundancy():
    engine = ExprAnalyzer()
    code = "var x = a * 1; var y = b + 0; var z = true && c;"
    res = engine.analyze(code)
    
    reps = res["replacements"]
    assert any(r["type"] == "Expression Simplification" and r["resolved"] == "a" for r in reps)
    assert any(r["type"] == "Expression Simplification" and r["resolved"] == "b" for r in reps)
    assert any(r["type"] == "Expression Simplification" and r["resolved"] == "c" for r in reps)

def test_transform_overlapping_safety():
    engine = ExprAnalyzer()
    code = "const x = 1 + 2 * 3;"
    res = engine.analyze(code)
    
    # Enable all replacements
    for r in res["replacements"]: r["apply"] = True
    new_code = engine.transform(code, res["replacements"])
    
    # 2*3 overlaps inside 1+6, engine should prefer overarching 1+6 = 7.
    assert "const x = 7;" in new_code
    assert "6" not in new_code # The inner overlap must be safely bypassed
