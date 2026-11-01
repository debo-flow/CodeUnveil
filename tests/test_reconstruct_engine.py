import pytest
import esprima
from reconstruct_engine import ASTGenerator, CodeQualityAnalyzer, ReconstructionPipeline

def test_ast_generator_basic():
    code = "var x = 10; function test(a) { return a + 1; }"
    tree = esprima.parseScript(code)
    
    generator = ASTGenerator()
    recon = generator.generate(tree)
    
    assert "var x = 10;" in recon
    assert "function test(a)" in recon
    assert "return a + 1;" in recon

def test_operator_precedence():
    code = "var x = (1 + 2) * 3;"
    tree = esprima.parseScript(code)
    
    generator = ASTGenerator()
    recon = generator.generate(tree)
    
    # Needs to preserve the grouping otherwise 1 + 2 * 3 = 7
    assert "(1 + 2) * 3" in recon

def test_complex_structures():
    code = """
    try {
        for (let i = 0; i < 10; i++) {
            if (i == 5) break;
            continue;
        }
    } catch (e) {
        throw e;
    }
    """
    tree = esprima.parseScript(code)
    generator = ASTGenerator()
    recon = generator.generate(tree)
    
    assert "try {" in recon
    assert "for (let i = 0; i < 10; i++)" in recon
    assert "if (i == 5)" in recon
    assert "break;" in recon
    assert "continue;" in recon
    assert "catch (e)" in recon
    assert "throw e;" in recon

def test_arrow_and_objects():
    code = "const f = (x) => { return { val: x }; };"
    tree = esprima.parseScript(code)
    generator = ASTGenerator()
    recon = generator.generate(tree)
    
    assert "(x) => {" in recon
    assert "val: x" in recon

def test_code_quality_analyzer():
    obfuscated = "var x=1;var y=2;var z=3;if(x){if(y){if(z){console.log('hi');}}}"
    stats = CodeQualityAnalyzer.analyze(obfuscated)
    
    # 1 line, high density, high nesting
    assert stats["total_lines"] == 1
    assert stats["max_nesting_depth"] >= 3
    assert stats["statement_density"] >= 4.0

def test_pipeline_validation():
    code = "var x = 10;"
    success, recon, msg = ReconstructionPipeline.rebuild_ast_source(code)
    
    assert success is True
    assert "var x = 10;" in recon
