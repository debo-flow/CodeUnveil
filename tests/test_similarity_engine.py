import pytest
from similarity_engine import SimilarityEngine

def test_type1_exact_match():
    engine = SimilarityEngine()
    code_a = "function test() { var x = 1; return x; }"
    code_b = "function test() { var x = 1; return x; }"
    
    res = engine.compare(code_a, code_b)
    
    assert res["status"] == "success"
    assert res["stats"]["type1_exact_match"] is True
    assert res["stats"]["type2_normalized_match"] is True
    assert res["stats"]["overall_similarity_score"] == 1.0

def test_type2_normalized_match_renamed_vars():
    engine = SimilarityEngine()
    code_a = "function test() { var x = 1; return x; }"
    code_b = "function obfuscated() { var _0x123 = 1; return _0x123; }"
    
    res = engine.compare(code_a, code_b)
    
    assert res["status"] == "success"
    assert res["stats"]["type1_exact_match"] is False # Variable names differ
    assert res["stats"]["type2_normalized_match"] is True # Structure is identical
    assert res["stats"]["overall_similarity_score"] == 1.0
    assert res["stats"]["fingerprint_a"] == res["stats"]["fingerprint_b"]

def test_type3_structural_similarity():
    engine = SimilarityEngine()
    # Code B has an extra branch (Type 3 structural modification)
    code_a = "function test(a) { if (a > 1) return 1; return 0; }"
    code_b = "function test(a) { if (a > 1) { console.log('h'); return 1; } return 0; }"
    
    res = engine.compare(code_a, code_b)
    
    assert res["status"] == "success"
    assert res["stats"]["type1_exact_match"] is False
    assert res["stats"]["type2_normalized_match"] is False
    
    # Cosine and Jaccard should still report high similarity (> 80%)
    score = res["stats"]["overall_similarity_score"]
    assert 0.8 < score < 1.0

def test_distinct_files():
    engine = SimilarityEngine()
    code_a = "function test(a) { if (a > 1) return 1; return 0; }"
    code_b = "var x = 1; while(x < 10) { x++; }"
    
    res = engine.compare(code_a, code_b)
    
    assert res["status"] == "success"
    score = res["stats"]["overall_similarity_score"]
    assert score < 0.5 # Totally different structures
