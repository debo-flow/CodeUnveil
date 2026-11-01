import time
import hashlib
import psutil
import os
import jsbeautifier
import re
import concurrent.futures
from typing import Dict, Any, List, Tuple

from ast_engine import ASTAnalyzer
from string_engine import StringAnalyzer
from encoding_engine import EncodingAnalyzer
from detection_engine import DetectionEngine
from cfg_engine import CFGAnalyzer
from dce_engine import DCEAnalyzer
from rename_engine import RenameAnalyzer
from array_engine import ArrayAnalyzer
from function_engine import FunctionAnalyzer
from expr_engine import ExprAnalyzer
from reconstruct_engine import ASTGenerator, CodeQualityAnalyzer, ReconstructionPipeline
from security_engine import SecurityAnalyzer
from sym_engine import SymEngine
from similarity_engine import SimilarityEngine
from semantic_engine import SemanticAnalyzer
from validation_engine import ValidationEngine

# M23 Integration
from plugin_engine import PluginRegistry, TransformationPlugin, DetectionPlugin, AnalysisPlugin

class CodeAnalyzer:
    @staticmethod
    def analyze(code: str) -> Dict[str, Any]:
        if not code or not code.strip(): return {"error": "Empty input"}
        return {
            "hex_count": len(re.findall(r'\b0x[0-9a-fA-F]+\b', code, re.IGNORECASE)),
            "escaped_count": len(re.findall(r'\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}', code, re.IGNORECASE)),
            "long_string_count": len(re.findall(r'["\']([a-zA-Z0-9+/=]{100,})["\']', code)),
            "array_access_count": len(re.findall(r'\b_[a-zA-Z0-9_]+\b\[[0-9]+\]', code)),
            "original_length": len(code), "original_lines": len(code.splitlines())
        }

class DeobfuscatorEngine:
    @staticmethod
    def process(code: str) -> Tuple[str, str]:
        if not code or not code.strip(): raise ValueError("No JavaScript code provided.")
        try:
            opts = jsbeautifier.default_options()
            opts.indent_size = 4; opts.space_in_empty_paren = True; opts.preserve_newlines = True
            opts.max_preserve_newlines = 2; opts.break_chained_methods = True; opts.unescape_strings = False 
            return jsbeautifier.beautify(code, opts), "Success"
        except Exception as e: return "", f"Processing Error: {str(e)}"

class AnalysisCache:
    def __init__(self, max_size=50):
        self.cache = {}
        self.max_size = max_size
        self.hits = 0
        self.misses = 0

    def _hash(self, source: str, config: Dict[str, Any]) -> str:
        key_string = source + json.dumps(config, sort_keys=True)
        return hashlib.sha256(key_string.encode('utf-8')).hexdigest()

    def get(self, source: str, config: Dict[str, Any]) -> Dict[str, Any]:
        k = self._hash(source, config)
        if k in self.cache:
            self.hits += 1
            return self.cache[k]
        self.misses += 1
        return None

    def put(self, source: str, config: Dict[str, Any], results: Dict[str, Any]):
        if len(self.cache) >= self.max_size:
            self.cache.pop(next(iter(self.cache)))
        self.cache[self._hash(source, config)] = results
        
    def get_stats(self) -> Dict[str, int]:
        total = self.hits + self.misses
        hit_ratio = (self.hits / total * 100) if total > 0 else 0
        return {"hits": self.hits, "misses": self.misses, "ratio": round(hit_ratio, 2), "size": len(self.cache)}

class Profiler:
    def __init__(self):
        self.process = psutil.Process(os.getpid())
        self.stages = {}
        self.start_time = time.time()

    def profile_stage(self, name: str, func, *args, **kwargs):
        mem_before = self.process.memory_info().rss
        t0 = time.time()
        result = func(*args, **kwargs)
        t1 = time.time()
        mem_after = self.process.memory_info().rss
        
        self.stages[name] = {
            "time_ms": round((t1 - t0) * 1000, 2),
            "mem_mb": round(max(0, (mem_after - mem_before) / (1024 * 1024)), 2)
        }
        return result

class PipelineOrchestrator:
    def __init__(self, cache: AnalysisCache):
        self.cache = cache
        self.registry = PluginRegistry.get_instance() # M23 Integration

    def execute(self, source_code: str, config: Dict[str, Any]) -> Dict[str, Any]:
        cached_result = self.cache.get(source_code, config)
        if cached_result:
            cached_result["profiler_stats"]["cached_run"] = True
            return cached_result

        profiler = Profiler()
        state = {}
        
        try:
            state["m12_original_stats"] = profiler.profile_stage("Pre-Recon Quality (M12)", CodeQualityAnalyzer.analyze, source_code)
            state["m6_original"] = source_code
            
            state["m1_results"] = profiler.profile_stage("Regex Metrics (M1)", CodeAnalyzer.analyze, source_code)
            state["m2_results"] = profiler.profile_stage("AST Extraction (M2)", ASTAnalyzer().analyze, source_code)
            
            string_engine = StringAnalyzer()
            state["m3_results"] = profiler.profile_stage("String Analytics (M3)", string_engine.analyze, source_code)
            
            transformed_code = source_code
            if state["m3_results"].get("status") == "success":
                transformed_code = profiler.profile_stage("String Transform (M3)", string_engine.transform)
                state["m4_results"] = profiler.profile_stage("Encoding Payload Scan (M4)", EncodingAnalyzer.analyze_payloads, state["m3_results"]["strings"])
            else:
                state["m4_results"] = None
                
            state["m5_results"] = profiler.profile_stage("Obfuscator Signatures (M5)", DetectionEngine().analyze, user_input=source_code, ast_metrics=state["m2_results"])
            
            cfg_engine = CFGAnalyzer()
            state["m14_code_base"] = transformed_code
            state["m6_results"] = profiler.profile_stage("CFG & CFF Tracking (M6/M14)", cfg_engine.analyze, transformed_code)
            if state["m6_results"].get("status") == "success":
                transformed_code = profiler.profile_stage("CFG Branch Simplify (M6)", cfg_engine.transform, transformed_code, approved_deflatten=[])
                
            dce_engine = DCEAnalyzer()
            state["m7_results"] = profiler.profile_stage("Dead Code Analytics (M7)", dce_engine.analyze, transformed_code)
            state["m7_replacements"] = dce_engine.replacements
            if config.get("apply_dce") and state["m7_results"].get("status") == "success":
                transformed_code = profiler.profile_stage("Dead Code Purge (M7)", dce_engine.transform)

            state["m8_code_base"] = transformed_code
            state["m8_results"] = profiler.profile_stage("Identifier Tracking (M8)", RenameAnalyzer().analyze, transformed_code)
            
            state["m9_code_base"] = transformed_code
            state["m9_results"] = profiler.profile_stage("String Arrays (M9)", ArrayAnalyzer().analyze, transformed_code)
            
            state["m10_code_base"] = transformed_code
            state["m10_results"] = profiler.profile_stage("Function Call Graph (M10)", FunctionAnalyzer().analyze, transformed_code)
            
            state["m11_code_base"] = transformed_code
            state["m11_results"] = profiler.profile_stage("Expression Folding (M11)", ExprAnalyzer().analyze, transformed_code)

            if config.get("run_sym_exec"):
                sym = SymEngine(max_depth=50, max_loop_iter=3)
                state["m15_results"] = profiler.profile_stage("Symbolic Execution (M15)", sym.analyze, transformed_code)
            else:
                state["m15_results"] = None

            if config.get("apply_ast_regen"):
                success, ast_code, msg = profiler.profile_stage("AST Strict Regen (M12)", ReconstructionPipeline.rebuild_ast_source, transformed_code)
                if success: transformed_code = ast_code
                
            # M23: Custom Transformation Plugins execution
            trans_plugins = self.registry.get_active_plugins_by_type(TransformationPlugin)
            for p in trans_plugins:
                transformed_code = profiler.profile_stage(f"Plugin Transform ({p.metadata.name})", p.transform, transformed_code, state["m2_results"])
                
            processed, d_status = profiler.profile_stage("JS Beautify (M1)", DeobfuscatorEngine.process, transformed_code)
            
            if d_status == "Success":
                state["processed_code"] = processed
                state["status"] = "Success"
                
                state["m12_results"] = profiler.profile_stage("Post-Recon Quality (M12)", CodeQualityAnalyzer.analyze, processed)
                
                # M23: Inject Custom Security Rules from Detection Plugins
                sec_engine = SecurityAnalyzer()
                det_plugins = self.registry.get_active_plugins_by_type(DetectionPlugin)
                for dp in det_plugins:
                    try:
                        sec_engine.rules.extend(dp.get_custom_rules())
                    except Exception: pass
                
                state["m13_results"] = profiler.profile_stage("Security Taint Tracking (M13)", sec_engine.analyze, processed, state["m5_results"])
                state["m18_results"] = profiler.profile_stage("Semantic Type Inference (M18)", SemanticAnalyzer().analyze, processed)
                
                val_engine = ValidationEngine()
                state["m19_results"] = profiler.profile_stage("AST Diff Validator (M19)", val_engine.run_differential_analysis, source_code, processed)
                state["m19_tests"] = profiler.profile_stage("Metamorphic Fuzzer (M19)", val_engine.run_regression_suite)
                
                # M23: Execute Custom Analysis Plugins
                ana_plugins = self.registry.get_active_plugins_by_type(AnalysisPlugin)
                for ap in ana_plugins:
                    try:
                        profiler.profile_stage(f"Plugin Analysis ({ap.metadata.name})", ap.analyze, processed, state["m2_results"])
                    except Exception: pass
                
                target_b = config.get("target_b")
                if target_b:
                    state["m17_results"] = profiler.profile_stage("Clone Fingerprinting (M17)", SimilarityEngine().compare, source_code, target_b)
                else:
                    state["m17_results"] = None
            else:
                state["processed_code"] = ""
                state["status"] = d_status
                
            state["profiler_stats"] = {
                "total_time_ms": round((time.time() - profiler.start_time) * 1000, 2),
                "stages": profiler.stages,
                "cached_run": False
            }
            
            self.cache.put(source_code, config, state)
            return state
            
        except Exception as e:
            return {"status": f"Pipeline Crash: {str(e)}"}
