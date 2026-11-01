import threading
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any

from perf_engine import PipelineOrchestrator, AnalysisCache
from workspace_engine import ConfigManager

app = FastAPI(title="CodeUnveil API", description="Local Programmatic API for automated static analysis.")

class AnalysisRequest(BaseModel):
    source_code: str
    apply_dce: bool = False
    apply_ast_regen: bool = False
    run_sym_exec: bool = False

@app.post("/api/v1/analyze")
def analyze_code(req: AnalysisRequest):
    if not req.source_code.strip():
        raise HTTPException(status_code=400, detail="Source code cannot be empty.")
    
    # We use a localized cache instance for the API to prevent cross-contamination of UI state
    cache = AnalysisCache(max_size=10)
    orchestrator = PipelineOrchestrator(cache)
    
    config = {
        "apply_dce": req.apply_dce,
        "apply_ast_regen": req.apply_ast_regen,
        "run_sym_exec": req.run_sym_exec,
        "target_b": ""
    }
    
    # Secure headless execution
    results = orchestrator.execute(req.source_code, config)
    if results.get("status") != "Success":
        raise HTTPException(status_code=500, detail=results.get("status"))
        
    # Strip massive AST raw dictionaries to keep the JSON response lightweight
    res_clean = {k: v for k, v in results.items() if k not in ["input_code", "m6_original", "m8_code_base", "m9_code_base", "m10_code_base", "m11_code_base", "m14_code_base"]}
    if "m2_results" in res_clean and "ast_tree" in res_clean["m2_results"]:
        del res_clean["m2_results"]["ast_tree"]
        
    return res_clean

@app.get("/api/v1/health")
def health_check():
    return {"status": "healthy", "version": "Milestone 23"}

class LocalAPIServer:
    """Manages the background execution of the Uvicorn server to avoid blocking Streamlit."""
    _server_thread = None
    _server = None
    
    @classmethod
    def start(cls, port=8000):
        if cls._server_thread and cls._server_thread.is_alive():
            return False, "Server is already running."
            
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
        cls._server = uvicorn.Server(config)
        
        cls._server_thread = threading.Thread(target=cls._server.run, daemon=True)
        cls._server_thread.start()
        return True, f"API Server started on http://127.0.0.1:{port}"
        
    @classmethod
    def stop(cls):
        if cls._server:
            cls._server.should_exit = True
            cls._server_thread.join(timeout=2)
            cls._server = None
            return True, "API Server stopped."
        return False, "Server is not running."
        
    @classmethod
    def is_running(cls) -> bool:
        return cls._server_thread is not None and cls._server_thread.is_alive()
