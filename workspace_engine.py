import os
import json
import uuid
import time
import zipfile
import io
import shutil
from typing import Dict, Any, List

STORAGE_DIR = ".codeunveil_data"
FILES_DIR = os.path.join(STORAGE_DIR, "files")
SNAPSHOTS_DIR = os.path.join(STORAGE_DIR, "snapshots")

DEFAULT_PROFILES = {
    "default": {
        "name": "Balanced Analysis",
        "config": {"apply_dce": False, "apply_ast_regen": True, "run_sym_exec": False, "max_workers": 4}
    },
    "deep": {
        "name": "Deep Security Analysis",
        "config": {"apply_dce": True, "apply_ast_regen": True, "run_sym_exec": True, "max_workers": 8}
    },
    "fast": {
        "name": "Fast Analysis",
        "config": {"apply_dce": False, "apply_ast_regen": False, "run_sym_exec": False, "max_workers": 2}
    }
}

class WorkspaceDB:
    """Singleton-like JSON database wrapper for local storage."""
    
    @staticmethod
    def init_db():
        os.makedirs(STORAGE_DIR, exist_ok=True)
        os.makedirs(FILES_DIR, exist_ok=True)
        os.makedirs(SNAPSHOTS_DIR, exist_ok=True)
        
        for table in ["workspaces", "projects", "profiles", "history", "sessions"]:
            path = os.path.join(STORAGE_DIR, f"{table}.json")
            if not os.path.exists(path):
                with open(path, "w") as f:
                    # Inject default profiles
                    if table == "profiles": json.dump(DEFAULT_PROFILES, f)
                    else: json.dump({}, f)

    @staticmethod
    def read(table: str) -> Dict[str, Any]:
        try:
            with open(os.path.join(STORAGE_DIR, f"{table}.json"), "r") as f:
                return json.load(f)
        except Exception: return {}

    @staticmethod
    def write(table: str, data: Dict[str, Any]):
        with open(os.path.join(STORAGE_DIR, f"{table}.json"), "w") as f:
            json.dump(data, f, indent=4)


class ConfigManager:
    """Manages hierarchical configurations and reusable profiles."""
    
    @staticmethod
    def get_profiles() -> Dict[str, Any]:
        return WorkspaceDB.read("profiles")

    @staticmethod
    def create_profile(name: str, config: Dict[str, Any]) -> str:
        profs = ConfigManager.get_profiles()
        pid = str(uuid.uuid4())
        profs[pid] = {"name": name, "config": config}
        WorkspaceDB.write("profiles", profs)
        return pid

    @staticmethod
    def get_effective_config(project_id: str) -> Dict[str, Any]:
        # Resolution: Project > Workspace > Base Profile > Default
        projects = WorkspaceDB.read("projects")
        workspaces = WorkspaceDB.read("workspaces")
        profiles = ConfigManager.get_profiles()
        
        base_config = profiles["default"]["config"].copy()
        
        if project_id in projects:
            p = projects[project_id]
            ws_id = p.get("workspace_id")
            
            # Merge Profile if set
            prof_id = p.get("profile_id")
            if prof_id and prof_id in profiles:
                base_config.update(profiles[prof_id]["config"])
                
            # Merge Workspace Config
            if ws_id and ws_id in workspaces:
                base_config.update(workspaces[ws_id].get("config", {}))
                
            # Merge Project Config
            base_config.update(p.get("config", {}))
            
        return base_config


class HistoryManager:
    """Tracks project-level audit events."""
    
    @staticmethod
    def log(project_id: str, event_type: str, description: str):
        history = WorkspaceDB.read("history")
        evt_id = str(uuid.uuid4())
        history[evt_id] = {
            "id": evt_id,
            "project_id": project_id,
            "event_type": event_type,
            "description": description,
            "timestamp": time.time()
        }
        WorkspaceDB.write("history", history)

    @staticmethod
    def get_project_history(project_id: str) -> List[Dict[str, Any]]:
        history = WorkspaceDB.read("history")
        events = [v for k, v in history.items() if v["project_id"] == project_id]
        return sorted(events, key=lambda x: x["timestamp"], reverse=True)


class WorkspaceEngine:
    """Manages Workspaces, Projects, Files, and Sessions."""

    def __init__(self):
        WorkspaceDB.init_db()

    # --- WORKSPACES ---
    def create_workspace(self, name: str, desc: str = "") -> str:
        ws = WorkspaceDB.read("workspaces")
        wid = str(uuid.uuid4())
        ws[wid] = {
            "id": wid, "name": name, "description": desc,
            "created_at": time.time(), "config": {}
        }
        WorkspaceDB.write("workspaces", ws)
        return wid

    def get_workspaces(self) -> Dict[str, Any]:
        return WorkspaceDB.read("workspaces")

    # --- PROJECTS ---
    def create_project(self, workspace_id: str, name: str, desc: str = "", profile_id: str = "default") -> str:
        projs = WorkspaceDB.read("projects")
        pid = str(uuid.uuid4())
        projs[pid] = {
            "id": pid, "workspace_id": workspace_id, "name": name, "description": desc,
            "profile_id": profile_id, "created_at": time.time(), "modified_at": time.time(),
            "config": {}, "files": []
        }
        WorkspaceDB.write("projects", projs)
        os.makedirs(os.path.join(FILES_DIR, pid), exist_ok=True)
        HistoryManager.log(pid, "PROJECT_CREATED", f"Project '{name}' initialized.")
        return pid

    def get_projects(self, workspace_id: str = None) -> List[Dict[str, Any]]:
        projs = WorkspaceDB.read("projects")
        if workspace_id:
            return [p for p in projs.values() if p["workspace_id"] == workspace_id]
        return list(projs.values())
        
    def get_project(self, project_id: str) -> Dict[str, Any]:
        return WorkspaceDB.read("projects").get(project_id)

    def delete_project(self, project_id: str):
        projs = WorkspaceDB.read("projects")
        if project_id in projs:
            del projs[project_id]
            WorkspaceDB.write("projects", projs)
            # Cleanup files
            fpath = os.path.join(FILES_DIR, project_id)
            if os.path.exists(fpath): shutil.rmtree(fpath)

    # --- FILE MANAGEMENT ---
    def add_file_to_project(self, project_id: str, filename: str, content: str):
        if not filename.endswith(('.js', '.mjs', '.cjs', '.jsx', '.json')):
            raise ValueError("Unsupported file type.")
        if len(content) > 10 * 1024 * 1024:
            raise ValueError("File exceeds 10MB safety limit.")
            
        projs = WorkspaceDB.read("projects")
        if project_id not in projs: return
        
        safe_name = os.path.basename(filename) # Prevent traversal
        file_path = os.path.join(FILES_DIR, project_id, safe_name)
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
            
        if safe_name not in projs[project_id]["files"]:
            projs[project_id]["files"].append(safe_name)
            
        projs[project_id]["modified_at"] = time.time()
        WorkspaceDB.write("projects", projs)
        HistoryManager.log(project_id, "FILE_ADDED", f"File '{safe_name}' added.")

    def get_file_content(self, project_id: str, filename: str) -> str:
        safe_name = os.path.basename(filename)
        path = os.path.join(FILES_DIR, project_id, safe_name)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        return ""

    # --- SESSIONS & SNAPSHOTS ---
    def save_session(self, project_id: str, session_name: str, results: Dict[str, Any]):
        sess = WorkspaceDB.read("sessions")
        sid = str(uuid.uuid4())
        
        # Strip massive raw buffers to save disk space on sessions, keep analytics
        clean_results = {}
        for k, v in results.items():
            if "code_base" not in k and k not in ["input_code", "processed_code", "m6_original"]:
                clean_results[k] = v
                
        sess[sid] = {
            "id": sid, "project_id": project_id, "name": session_name,
            "timestamp": time.time(), "results": clean_results
        }
        WorkspaceDB.write("sessions", sess)
        HistoryManager.log(project_id, "SESSION_SAVED", f"Analysis session '{session_name}' completed.")

    def get_sessions(self, project_id: str) -> List[Dict[str, Any]]:
        sess = WorkspaceDB.read("sessions")
        return sorted([s for s in sess.values() if s["project_id"] == project_id], key=lambda x: x["timestamp"], reverse=True)

    # --- SECURE EXPORT / IMPORT ---
    def export_project(self, project_id: str) -> bytes:
        proj = self.get_project(project_id)
        if not proj: return b""
        
        mem_zip = io.BytesIO()
        with zipfile.ZipFile(mem_zip, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
            # Metadata
            zf.writestr("codeunveil_meta.json", json.dumps(proj, indent=4))
            # Files
            for fname in proj["files"]:
                content = self.get_file_content(project_id, fname)
                zf.writestr(f"src/{fname}", content)
                
        HistoryManager.log(project_id, "PROJECT_EXPORTED", "Project exported to ZIP.")
        return mem_zip.getvalue()

    def import_project_safe(self, workspace_id: str, zip_bytes: bytes) -> str:
        """Securely imports a project, preventing ZIP path traversal and archive bombs."""
        if len(zip_bytes) > 50 * 1024 * 1024:
            raise ValueError("Archive exceeds maximum import size.")
            
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            # Extract metadata
            if "codeunveil_meta.json" not in z.namelist():
                raise ValueError("Invalid project archive. Missing codeunveil_meta.json.")
                
            meta = json.loads(z.read("codeunveil_meta.json").decode('utf-8'))
            pid = self.create_project(workspace_id, f"Imported: {meta.get('name', 'Unknown')}", meta.get('description', ''))
            
            # Safe File Extraction
            for info in z.infolist():
                if info.is_dir() or not info.filename.startswith("src/"): continue
                if info.file_size > 10 * 1024 * 1024: continue # Skip massive files
                
                safe_name = os.path.basename(info.filename)
                if not safe_name or ".." in safe_name: continue
                
                content = z.read(info).decode('utf-8', errors='replace')
                self.add_file_to_project(pid, safe_name, content)
                
        return pid
