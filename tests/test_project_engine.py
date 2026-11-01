import pytest
import io
import zipfile
from project_engine import ProjectAnalyzer

def create_mock_zip(file_dict):
    """Helper to create an in-memory zip file from a dictionary of path -> content."""
    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        for path, content in file_dict.items():
            zf.writestr(path, content)
    return mem_zip.getvalue()

def test_safe_memory_extraction():
    engine = ProjectAnalyzer(max_files=10)
    files = {
        "index.js": "console.log(1);",
        "../traversal_attack.js": "malicious",
        "/absolute_attack.js": "malicious",
        "package.json": '{"name": "test"}'
    }
    
    res = engine.analyze_zip(create_mock_zip(files))
    
    assert res["status"] == "success"
    assert "index.js" in engine.files
    assert "package.json" in engine.files
    assert "traversal_attack.js" not in engine.files # Path traversal neutralized
    assert "absolute_attack.js" in engine.files # Leading slash stripped successfully

def test_import_export_detection():
    engine = ProjectAnalyzer()
    files = {
        "main.js": "import { foo } from './utils.js'; const fs = require('fs');",
        "utils.js": "export function foo() { return 1; }"
    }
    
    res = engine.analyze_zip(create_mock_zip(files))
    
    assert res["stats"]["js_files"] == 2
    
    # Imports main.js
    main_imports = res["modules"]["main.js"]["imports"]
    assert any(i["source"] == "./utils.js" for i in main_imports)
    assert any(i["source"] == "fs" and i["type"] == "require" for i in main_imports)
    
    # Exports utils.js
    utils_exports = res["modules"]["utils.js"]["exports"]
    assert any(e["name"] == "foo" and e["type"] == "named" for e in utils_exports)

def test_circular_dependency_detection():
    engine = ProjectAnalyzer()
    files = {
        "a.js": "import './b.js';",
        "b.js": "import './c.js';",
        "c.js": "import './a.js';" # Creates A -> B -> C -> A
    }
    
    res = engine.analyze_zip(create_mock_zip(files))
    
    assert res["stats"]["circular_dependencies"] >= 1
    
    cycles = res["circular_chains"]
    assert any("a.js" in cycle and "b.js" in cycle and "c.js" in cycle for cycle in cycles)

def test_module_resolution_and_external_deps():
    engine = ProjectAnalyzer()
    files = {
        "src/app.js": "import { init } from './lib/init.js'; import axios from 'axios';",
        "src/lib/init.js": "export const init = () => {};"
    }
    
    res = engine.analyze_zip(create_mock_zip(files))
    
    # "axios" should be identified as external
    assert "axios" in res["external_deps"]
    
    # "./lib/init.js" should resolve to "src/lib/init.js"
    assert "src/lib/init.js" in res["dependency_graph"]["src/app.js"]

def test_isolated_modules():
    engine = ProjectAnalyzer()
    files = {
        "entry.js": "import './a.js';",
        "a.js": "console.log(1);",
        "dead_module.js": "console.log('Unused');"
    }
    
    res = engine.analyze_zip(create_mock_zip(files))
    
    # dead_module.js and entry.js have 0 incoming edges.
    assert res["stats"]["isolated_modules"] == 2
