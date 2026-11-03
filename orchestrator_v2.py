import time
import copy
from typing import Dict, Any, List, Tuple
from perf_engine import PipelineOrchestrator, AnalysisCache, Profiler
from validation_engine import ValidationEngine
from intelligence_engine import AdvancedTaintAnalyzer, FunctionBehaviorExplainer

class MultiPassOrchestrator(PipelineOrchestrator):
    """
    Next-Generation Multi-Pass Deobfuscation Engine.
    Executes iterative transformations with AST snapshot comparisons, validation rollbacks, and adaptive stopping.
    """
    def __init__(self, cache: AnalysisCache):
        super().__init__(cache)
        self.validation_engine = ValidationEngine()

    def execute_multipass(self, source_code: str, config: Dict[str, Any]) -> Dict[str, Any]:
        max_passes = config.get("max_passes", 3)
        current_code = source_code
        history = []
        profiler = Profiler()
        
        final_state = {}
        pass_metrics = []

        for pass_idx in range(1, max_passes + 1):
            t0 = time.time()
            
            # Execute standard M1-M20 pipeline pass
            state = self.execute(current_code, config)
            
            if state.get("status") != "Success":
                final_state = {"status": f"Failed on Pass {pass_idx}: {state.get('status')}"}
                break

            new_code = state.get("processed_code", "")
            
            # M19 Validation: Semantic & AST Consistency
            diff_results = self.validation_engine.run_differential_analysis(current_code, new_code)
            
            # Rollback logic (Adaptive Deobfuscation)
            dangerous = diff_results.get("ast_diff", {}).get("dangerous_changes", [])
            sem_issues = diff_results.get("semantic_diff", {}).get("issues", [])
            
            if dangerous or any("DANGER" in issue for issue in sem_issues):
                # Validation failed, rollback to previous stable code
                final_state["status"] = "Success (Rolled Back)"
                final_state["rollback_reason"] = "Unsafe semantic shifts detected."
                break
                
            # Stopping Condition: Code stabilized
            if diff_results.get("ast_diff", {}).get("modified", 0) == 0 and diff_results.get("ast_diff", {}).get("removed", 0) == 0:
                final_state = state
                pass_metrics.append({"pass": pass_idx, "time_ms": round((time.time()-t0)*1000, 2), "status": "Stable (Completed)"})
                break
                
            # Accept Pass
            history.append({
                "pass": pass_idx,
                "ast_diff": diff_results["ast_diff"],
                "code": new_code
            })
            pass_metrics.append({"pass": pass_idx, "time_ms": round((time.time()-t0)*1000, 2), "status": "Mutated (Continuing)"})
            
            current_code = new_code
            final_state = state

        # Phase B: Advanced Code Intelligence Enrichment
        if final_state.get("status", "").startswith("Success"):
            final_state["multipass_history"] = history
            final_state["multipass_metrics"] = pass_metrics
            
            # Run Intelligence Engines on final stabilized AST
            taint_engine = AdvancedTaintAnalyzer()
            final_state["taint_results"] = taint_engine.analyze(final_state["processed_code"])
            
            explainer = FunctionBehaviorExplainer()
            final_state["nlp_explanations"] = explainer.explain(final_state.get("m2_results", {}), final_state.get("m10_results", {}))

        return final_state
