import time
from typing import Dict, Any, List
from orchestrator_v2 import MultiPassOrchestrator
from perf_engine import AnalysisCache

class BenchmarkLaboratory:
    """Scientific Benchmarking and Accuracy Metrics Engine."""
    
    FIXTURES = {
        "hex_obf": "var x = '\\x48\\x65\\x6c\\x6c\\x6f'; function a() { return x; }",
        "cff_simple": "var state=1; while(true){switch(state){case 1: var a=1; state=2; break; case 2: break;} if(state===2)break;}",
        "dead_code": "function unused() { return 1; } var active = 2;",
        "math_fold": "var result = (10 * 5) + (20 - 8);"
    }

    def __init__(self):
        self.cache = AnalysisCache(max_size=10)
        self.orchestrator = MultiPassOrchestrator(self.cache)

    def run_suite(self, config: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        overall_t0 = time.time()
        
        for name, source in self.FIXTURES.items():
            t0 = time.time()
            # Force uncached run for benchmark accuracy
            conf = config.copy()
            conf["benchmark_nonce"] = time.time() 
            
            state = self.orchestrator.execute_multipass(source, conf)
            t1 = time.time()
            
            ast_nodes_orig = state.get("m2_results", {}).get("stats", {}).get("total_nodes", 1)
            ast_nodes_final = state.get("m12_results", {}).get("total_nodes", 1) # Note: approximated for benchmark output
            
            recovery_rate = max(0.0, 100.0 - (ast_nodes_final / max(1, ast_nodes_orig) * 100))
            
            results.append({
                "fixture": name,
                "time_ms": round((t1 - t0) * 1000, 2),
                "passes_required": len(state.get("multipass_metrics", [1])),
                "ast_reduction_pct": round(recovery_rate, 2),
                "status": "PASS" if state.get("status", "").startswith("Success") else "FAIL"
            })
            
        total_time = round((time.time() - overall_t0) * 1000, 2)
        return {
            "total_time_ms": total_time,
            "fixtures_run": len(self.FIXTURES),
            "details": results
        }
