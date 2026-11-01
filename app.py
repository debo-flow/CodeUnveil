import streamlit as st
import io
import os
import json
import pandas as pd
from datetime import datetime
from streamlit_ace import st_ace

# ==========================================
# CodeUnveil v1.0.0 Stable Engine Imports
# ==========================================
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
from project_engine import ProjectAnalyzer
from similarity_engine import SimilarityEngine
from semantic_engine import SemanticAnalyzer
from validation_engine import ValidationEngine
from perf_engine import AnalysisCache, PipelineOrchestrator, DeobfuscatorEngine
from workspace_engine import WorkspaceEngine, ConfigManager, HistoryManager
from plugin_engine import PluginRegistry, PLUGIN_DIR
from api_server import LocalAPIServer
from qa_engine import QAEngine

VERSION = "1.0.0"

def inject_design_system():
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&family=Inter:wght@400;500;600&display=swap');
        html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
        code, pre, .stTextArea textarea { font-family: 'Fira Code', monospace !important; font-size: 13px !important; }
        .metric-container { background-color: #1E1E1E; border: 1px solid #333; border-radius: 8px; padding: 16px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        hr { border-top: 1px solid #333; }
        .stButton button { transition: all 0.2s ease-in-out; border-radius: 6px; }
        .stButton button:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(255, 75, 75, 0.2); }
        </style>
    """, unsafe_allow_html=True)

class CodeUnveilIDE:
    def __init__(self):
        self.workspace_engine = WorkspaceEngine()
        self.registry = PluginRegistry.get_instance()
        self.initialize_state()
        
    def initialize_state(self):
        if 'global_cache' not in st.session_state:
            st.session_state.global_cache = AnalysisCache(max_size=50)
            
        base_keys = [
            'current_page', 'editor_theme', 'search_query', 'notifications',
            'current_workspace_id', 'current_project_id', 'current_file',
            'input_code', 'processed_code', 'm6_original', 'm17_target_code', 'm24_results'
        ]
        for key in base_keys:
            if key not in st.session_state:
                st.session_state[key] = "📊 Dashboard" if key == 'current_page' else "monokai" if key == 'editor_theme' else [] if key == 'notifications' else None if 'id' in key or 'file' in key else ""
        
        ws = self.workspace_engine.get_workspaces()
        if not ws:
            wid = self.workspace_engine.create_workspace("Default Workspace", "Auto-generated default workspace.")
            st.session_state.current_workspace_id = wid
        elif not st.session_state.current_workspace_id:
            st.session_state.current_workspace_id = list(ws.keys())[0]

        engine_keys = [f"m{i}_results" for i in range(1, 25)] + ['m7_replacements', 'm19_tests', 'profiler_stats']
        for key in engine_keys:
            if key not in st.session_state: st.session_state[key] = None

    def dispatch_notification(self, msg: str, icon: str = "ℹ️"):
        st.toast(msg, icon=icon)
        st.session_state.notifications.append(f"{icon} [{datetime.now().strftime('%H:%M:%S')}] {msg}")

    def handle_global_command(self):
        cmd = st.session_state.search_query.strip().lower()
        if not cmd: return
        routes = {
            "> dashboard": "📊 Dashboard", "> workspace": "📁 Workspace & Projects", "> editor": "💻 Code Editor",
            "> config": "⚙️ Config & Profiles", "> history": "🕰️ History & Sessions", "> ast": "🌳 AST & Semantics",
            "> security": "🛡️ Security Center", "> graph": "🔀 Graph Explorer", "> transform": "🛠️ Transform Studio", 
            "> perf": "⚡ Validation & Perf", "> plugins": "🧩 Plugins & API", "> api": "🧩 Plugins & API",
            "> qa": "✅ Quality Assurance", "> audit": "✅ Quality Assurance"
        }
        for k, v in routes.items():
            if cmd.startswith(k):
                st.session_state.current_page = v
                self.dispatch_notification(f"Navigated to {v}", "🧭")
                st.session_state.search_query = ""
                st.rerun()

    def run(self):
        st.set_page_config(page_title=f"CodeUnveil v{VERSION}", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
        inject_design_system()
        
        with st.sidebar:
            st.title(f"🛡️ CodeUnveil v{VERSION}")
            st.caption("Reveal the Logic Behind Obfuscated Code")
            st.text_input("🔍 Global Command (e.g. '> qa')", key="search_query", on_change=self.handle_global_command)
            st.markdown("---")
            
            pages = [
                "📊 Dashboard", "📁 Workspace & Projects", "⚙️ Config & Profiles", "🕰️ History & Sessions",
                "💻 Code Editor", "🛠️ Transform Studio", "🌳 AST & Semantics", "🔀 Graph Explorer",
                "🛡️ Security Center", "⚡ Validation & Perf", "🧩 Plugins & API", "✅ Quality Assurance"
            ]
            
            st.session_state.current_page = st.radio("Navigation", pages, index=pages.index(st.session_state.current_page))
            st.markdown("---")
            st.session_state.editor_theme = st.selectbox("Editor Theme", ["monokai", "github", "tomorrow_night", "dracula", "eclipse"], index=0)

            if st.button("🗑️ Reset Application State", use_container_width=True):
                for key in list(st.session_state.keys()):
                    if key not in ['global_cache', 'current_page', 'editor_theme', 'current_workspace_id', 'current_project_id']:
                        del st.session_state[key]
                self.initialize_state()
                self.dispatch_notification("Application State Reset", "🗑️")
                st.rerun()

        page = st.session_state.current_page
        if page == "📊 Dashboard": self.render_dashboard()
        elif page == "📁 Workspace & Projects": self.render_workspace_manager()
        elif page == "⚙️ Config & Profiles": self.render_configuration()
        elif page == "🕰️ History & Sessions": self.render_history()
        elif page == "💻 Code Editor": self.render_code_editor()
        elif page == "🛠️ Transform Studio": self.render_transform_studio()
        elif page == "🌳 AST & Semantics": self.render_ast_semantics()
        elif page == "🔀 Graph Explorer": self.render_graphs()
        elif page == "🛡️ Security Center": self.render_security()
        elif page == "⚡ Validation & Perf": self.render_validation_perf()
        elif page == "🧩 Plugins & API": self.render_plugins_api()
        elif page == "✅ Quality Assurance": self.render_qa_center()

    # ==========================================
    # 📊 Dashboard
    # ==========================================
    def render_dashboard(self):
        st.header("📊 Executive Dashboard")
        st.write(f"**CodeUnveil Version:** `{VERSION} Stable`")
        if not st.session_state.m1_results:
            st.info("👋 Welcome to CodeUnveil. Navigate to the **💻 Code Editor** to begin analysis.")
            return

        c1, c2, c3, c4 = st.columns(4)
        m2 = st.session_state.m2_results["stats"] if st.session_state.m2_results else {}
        m13 = st.session_state.m13_results["summary"] if st.session_state.m13_results else {}
        
        c1.metric("Total AST Nodes", m2.get("total_nodes", 0))
        c2.metric("Functions Detected", m2.get("functions", 0))
        c3.metric("Critical Security Risks", m13.get("Critical", 0))
        
        score = 0.0
        if st.session_state.m17_results and "stats" in st.session_state.m17_results:
            score = st.session_state.m17_results["stats"]["overall_similarity_score"] * 100
        c4.metric("Clone Similarity", f"{score:.1f}%")

        st.markdown("---")
        col_act, col_perf = st.columns(2)
        
        with col_act:
            st.subheader("Recent Activity Log")
            if st.session_state.notifications:
                for n in reversed(st.session_state.notifications[-8:]):
                    st.write(n)
            else:
                st.write("No recent activity.")
                
        with col_perf:
            st.subheader("Latest Pipeline Performance")
            if st.session_state.profiler_stats:
                p = st.session_state.profiler_stats
                st.write(f"**Total Execution Time:** {p['total_time_ms']} ms")
                st.write(f"**Cache Hit?** {'Yes ⚡' if p.get('cached_run') else 'No 🐢'}")
                st.progress(min(1.0, p['total_time_ms'] / 5000.0), text="Pipeline Latency")
            else:
                st.write("No performance data available.")

    # ==========================================
    # 📁 Workspace & Project Manager
    # ==========================================
    def render_workspace_manager(self):
        st.header("📁 Workspace & Project Manager")
        
        workspaces = self.workspace_engine.get_workspaces()
        ws_opts = {w["id"]: w["name"] for w in workspaces.values()}
        
        c_ws1, c_ws2 = st.columns([3, 1])
        with c_ws1:
            sel_ws = st.selectbox("Active Workspace", options=list(ws_opts.keys()), format_func=lambda x: ws_opts[x], index=list(ws_opts.keys()).index(st.session_state.current_workspace_id) if st.session_state.current_workspace_id in ws_opts else 0)
            if sel_ws != st.session_state.current_workspace_id:
                st.session_state.current_workspace_id = sel_ws
                st.session_state.current_project_id = None
                st.rerun()
                
        with c_ws2:
            with st.popover("➕ New Workspace"):
                nw_name = st.text_input("Workspace Name")
                if st.button("Create Workspace"):
                    wid = self.workspace_engine.create_workspace(nw_name)
                    st.session_state.current_workspace_id = wid
                    self.dispatch_notification(f"Workspace '{nw_name}' created.", "📁")
                    st.rerun()

        st.markdown("---")
        projects = self.workspace_engine.get_projects(st.session_state.current_workspace_id)
        if not projects:
            st.info("No projects in this workspace. Create or Import one to begin.")
        else:
            proj_opts = {p["id"]: p["name"] for p in projects}
            idx = list(proj_opts.keys()).index(st.session_state.current_project_id) if st.session_state.current_project_id in proj_opts else 0
            
            cp1, cp2, cp3 = st.columns([2, 1, 1])
            with cp1:
                sel_proj = st.selectbox("Active Project", options=list(proj_opts.keys()), format_func=lambda x: proj_opts[x], index=idx)
                if sel_proj != st.session_state.current_project_id:
                    st.session_state.current_project_id = sel_proj
                    st.session_state.current_file = None
                    st.rerun()
            with cp2:
                if st.button("🗑️ Delete Project") and st.session_state.current_project_id:
                    self.workspace_engine.delete_project(st.session_state.current_project_id)
                    st.session_state.current_project_id = None
                    self.dispatch_notification("Project deleted.", "🗑️")
                    st.rerun()
            with cp3:
                if st.button("📦 Export Project ZIP") and st.session_state.current_project_id:
                    zip_data = self.workspace_engine.export_project(st.session_state.current_project_id)
                    st.download_button("💾 Download ZIP", zip_data, "project_export.zip", "application/zip")

        with st.expander("➕ Create or Import Project", expanded=(not projects)):
            c_new, c_imp = st.columns(2)
            with c_new:
                np_name = st.text_input("New Project Name")
                if st.button("Create Empty Project"):
                    pid = self.workspace_engine.create_project(st.session_state.current_workspace_id, np_name)
                    st.session_state.current_project_id = pid
                    self.dispatch_notification(f"Project '{np_name}' created.", "✨")
                    st.rerun()
            with c_imp:
                imp_file = st.file_uploader("Import Project Archive (.zip)", type=["zip"])
                if imp_file and st.button("Import Safely"):
                    try:
                        pid = self.workspace_engine.import_project_safe(st.session_state.current_workspace_id, imp_file.getvalue())
                        st.session_state.current_project_id = pid
                        self.dispatch_notification("Project imported successfully.", "📦")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Import Failed: {str(e)}")

        if st.session_state.current_project_id:
            st.markdown("---")
            st.subheader("📄 Project File Explorer")
            active_proj = self.workspace_engine.get_project(st.session_state.current_project_id)
            
            c_f1, c_f2 = st.columns([1, 2])
            with c_f1:
                uploaded_file = st.file_uploader("Add File to Project", type=["js", "txt", "json"])
                if uploaded_file and st.button("Upload File"):
                    content = uploaded_file.getvalue().decode("utf-8", errors="replace")
                    self.workspace_engine.add_file_to_project(active_proj["id"], uploaded_file.name, content)
                    self.dispatch_notification(f"File {uploaded_file.name} added.", "📄")
                    st.rerun()
                    
            with c_f2:
                if not active_proj.get("files"):
                    st.write("No files in this project.")
                else:
                    sel_f = st.radio("Project Files", active_proj["files"])
                    if st.button("Load File into Editor Buffer"):
                        content = self.workspace_engine.get_file_content(active_proj["id"], sel_f)
                        st.session_state.input_code = content
                        st.session_state.current_file = sel_f
                        st.session_state.current_page = "💻 Code Editor"
                        self.dispatch_notification(f"Loaded {sel_f} into Editor.", "💻")
                        st.rerun()

    # ==========================================
    # ⚙️ Configuration & Profiles
    # ==========================================
    def render_configuration(self):
        st.header("⚙️ Configuration & Profiles")
        st.write("Configurations dictate how the Pipeline Orchestrator behaves. Settings inherit as: Project > Workspace > Profile.")
        
        profiles = ConfigManager.get_profiles()
        
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("Global Profiles")
            for pid, p in profiles.items():
                with st.expander(f"{p['name']} (ID: {pid[:8]})"):
                    st.json(p["config"])
                    
        with c2:
            st.subheader("Active Project Configuration")
            if not st.session_state.current_project_id:
                st.warning("Select a project in the Workspace Manager first.")
                return
                
            active_proj = self.workspace_engine.get_project(st.session_state.current_project_id)
            eff_config = ConfigManager.get_effective_config(st.session_state.current_project_id)
            
            st.write(f"**Project:** {active_proj['name']}")
            st.write(f"**Base Profile:** {profiles.get(active_proj['profile_id'], {}).get('name', 'Unknown')}")
            
            st.markdown("#### Effective Resolved Settings")
            st.json(eff_config)

    # ==========================================
    # 🕰️ History & Sessions
    # ==========================================
    def render_history(self):
        st.header("🕰️ Project History & Sessions")
        if not st.session_state.current_project_id:
            st.warning("Select a project in the Workspace Manager first.")
            return

        tabs = st.tabs(["Analysis Sessions (Snapshots)", "Audit History Log"])
        
        with tabs[0]:
            sessions = self.workspace_engine.get_sessions(st.session_state.current_project_id)
            if not sessions:
                st.info("No analysis sessions recorded yet. Run the pipeline in the Code Editor.")
            else:
                for s in sessions:
                    ts = datetime.fromtimestamp(s['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                    with st.expander(f"Session: {s['name']} [{ts}]"):
                        res = s['results']
                        st.write(f"**Pipeline Status:** {res.get('status', 'Unknown')}")
                        if "profiler_stats" in res:
                            st.write(f"**Execution Time:** {res['profiler_stats'].get('total_time_ms')} ms")
                        if st.button("Load Session Results to UI", key=f"load_{s['id']}"):
                            for k, v in res.items():
                                if k in st.session_state: st.session_state[k] = v
                            self.dispatch_notification("Session Results Loaded.", "🕰️")
                            st.rerun()

        with tabs[1]:
            history = HistoryManager.get_project_history(st.session_state.current_project_id)
            if history:
                df = pd.DataFrame([{
                    "Time": datetime.fromtimestamp(h['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
                    "Event": h['event_type'],
                    "Description": h['description']
                } for h in history])
                st.dataframe(df, use_container_width=True)
            else:
                st.write("No audit events recorded.")

    # ==========================================
    # 💻 Code Editor & Pipeline Execution
    # ==========================================
    def render_code_editor(self):
        st.header("💻 Code Editor & Pipeline Execution")
        
        if not st.session_state.current_project_id:
            st.warning("⚠️ No active project. Pipeline configuration defaults will be used. Go to Workspace to create a project.")
            eff_config = ConfigManager.get_profiles()["default"]["config"]
        else:
            eff_config = ConfigManager.get_effective_config(st.session_state.current_project_id)

        c1, c2 = st.columns([4, 1])
        with c1:
            st.write(f"**Active Configuration:** `apply_dce={eff_config.get('apply_dce')}`, `apply_ast_regen={eff_config.get('apply_ast_regen')}`, `sym_exec={eff_config.get('run_sym_exec')}`")
        with c2:
            if st.button("🚀 Execute v1.0.0 Orchestrated Pipeline", type="primary", use_container_width=True):
                self.execute_pipeline(eff_config)

        st.markdown("---")
        e1, e2 = st.columns(2)
        with e1:
            st.markdown(f"**Original Source** `{st.session_state.current_file or 'Scratchpad'}`")
            new_val = st_ace(value=st.session_state.input_code, language="javascript", theme=st.session_state.editor_theme, keybinding="vscode", font_size=14, tab_size=4, wrap=True, min_lines=25)
            if new_val != st.session_state.input_code:
                st.session_state.input_code = new_val

        with e2:
            st.markdown("**Transformed Source (Output)**")
            st_ace(value=st.session_state.processed_code, language="javascript", theme=st.session_state.editor_theme, keybinding="vscode", font_size=14, tab_size=4, wrap=True, min_lines=25, readonly=True)
            if st.session_state.processed_code:
                st.download_button("💾 Download Output", st.session_state.processed_code, "output.js", "text/javascript")

    def execute_pipeline(self, config: Dict[str, Any]):
        if not st.session_state.input_code.strip():
            st.error("Editor buffer is empty.")
            return
            
        with st.spinner("Orchestrating M1-M24 Static Analysis Pipeline (Including Active Plugins)..."):
            config["target_b"] = st.session_state.m17_target_code
            orchestrator = PipelineOrchestrator(cache=st.session_state.global_cache)
            results = orchestrator.execute(st.session_state.input_code, config)
            
            if results.get("status") == "Success":
                for key, val in results.items():
                    if key in st.session_state: st.session_state[key] = val
                
                cached = results["profiler_stats"].get("cached_run", False)
                self.dispatch_notification(f"Pipeline Complete! (Cache Hit: {cached})", "✅")
                
                if st.session_state.current_project_id:
                    self.workspace_engine.save_session(st.session_state.current_project_id, f"Session {datetime.now().strftime('%H:%M:%S')}", results)
            else:
                st.error(results.get("status", "Unknown Error"))
                self.dispatch_notification("Pipeline Execution Failed.", "❌")

    # ==========================================
    # 🛠️ Transform Studio
    # ==========================================
    def render_transform_studio(self):
        st.header("🛠️ Transformation Studio")
        st.write("Review and safely apply static deobfuscation transformations generated by the analysis engines.")
        
        if not st.session_state.m1_results:
            st.info("Run the pipeline in the Code Editor first.")
            return

        tabs = st.tabs(["Strings & Encodings", "Dead Code", "Renaming", "Arrays", "Functions", "Expressions"])
        
        with tabs[0]:
            if st.session_state.m3_results:
                st.dataframe(pd.DataFrame([{"Raw": s["raw"], "Decoded": s["value"]} for s in st.session_state.m3_results.get("strings", []) if s.get("is_encoded")]), use_container_width=True)
            if st.session_state.m4_results:
                st.write("**Deep Encodings Detected**")
                st.dataframe(pd.DataFrame(st.session_state.m4_results).drop(columns=["Full Decoded"]), use_container_width=True)

        with tabs[1]:
            reps = st.session_state.m7_replacements
            if reps:
                st.warning(f"{len(reps)} code blocks successfully flagged for safe removal.")
                st.dataframe(pd.DataFrame([{"Reason": r[3], "Range": f"[{r[0]}, {r[1]}]"} for r in reps]), use_container_width=True)
            else:
                st.success("No dead code detected.")

        with tabs[2]:
            m8 = st.session_state.m8_results
            if m8 and m8.get("identifiers"):
                df = pd.DataFrame([{ "Original Name": i["original_name"], "Suggestion": i["suggestion"], "Suspicious": i["is_suspicious"], "Scope": i["scope_type"] } for i in m8["identifiers"]])
                st.dataframe(df, use_container_width=True)

        with tabs[3]:
            m9 = st.session_state.m9_results
            if m9 and m9.get("lookups"):
                df = pd.DataFrame([{ "Original": l["original_expression"], "Resolved": l["resolved_value"], "Confidence": l["confidence"] } for l in m9["lookups"]])
                st.dataframe(df, use_container_width=True)

        with tabs[4]:
            m10 = st.session_state.m10_results
            if m10 and m10.get("simplifications"):
                df = pd.DataFrame([{ "Original Call": l["original_expression"], "Inlined Code": l["resolved_value"], "Type": l["type"] } for l in m10["simplifications"]])
                st.dataframe(df, use_container_width=True)

        with tabs[5]:
            m11 = st.session_state.m11_results
            if m11 and m11.get("replacements"):
                df = pd.DataFrame([{ "Original Expression": r["original"], "Simplified Result": r["resolved"], "Type": r["type"] } for r in m11["replacements"]])
                st.dataframe(df, use_container_width=True)

    # ==========================================
    # 🌳 AST & Semantics
    # ==========================================
    def render_ast_semantics(self):
        st.header("🌳 AST & Semantic Analysis")
        
        if not st.session_state.m2_results:
            st.info("Run the pipeline in the Code Editor first.")
            return

        c_ast, c_sem = st.columns(2)
        with c_ast:
            st.subheader("Interactive AST Explorer")
            st.json(st.session_state.m2_results.get("ast_tree", {}), expanded=False)
            
        with c_sem:
            st.subheader("Symbol Table & Type Inference")
            m18 = st.session_state.m18_results
            if m18 and m18.get("symbols"):
                df_sym = pd.DataFrame(m18["symbols"])
                st.dataframe(df_sym, use_container_width=True)
                
            st.subheader("Function Semantic Summaries")
            if m18 and m18.get("functions"):
                funcs = [{"Name": n, "Classification": d["classification"], "Return": " | ".join(d["inferred_return_types"])} for n, d in m18["functions"].items()]
                st.dataframe(pd.DataFrame(funcs), use_container_width=True)

    # ==========================================
    # 🔀 Graph Explorer
    # ==========================================
    def render_graphs(self):
        st.header("🔀 Graph Explorer")
        st.write("Interactive visualizations for Control Flow, State Transitions, and Dependencies.")
        
        if not st.session_state.m6_results:
            st.info("Run the pipeline in the Code Editor first.")
            return

        tabs = st.tabs(["Control Flow Graph (CFG)", "State Transitions (STG)", "Data Dependencies", "Function Calls", "Project Architecture"])
        
        with tabs[0]:
            st.graphviz_chart(st.session_state.m6_results.get("dot_graph", ""))
        with tabs[1]:
            st.graphviz_chart(st.session_state.m14_code_base and st.session_state.m6_results.get("stg_graph", ""))
        with tabs[2]:
            if st.session_state.m18_results:
                st.graphviz_chart(st.session_state.m18_results.get("dependency_graph_dot", ""))
        with tabs[3]:
            if st.session_state.m10_results:
                st.graphviz_chart(st.session_state.m10_results.get("call_graph_dot", ""))
        with tabs[4]:
            if st.session_state.m16_results and "dot_graph" in st.session_state.m16_results:
                st.graphviz_chart(st.session_state.m16_results["dot_graph"])
            else:
                st.write("No Project ZIP loaded.")

    # ==========================================
    # 🛡️ Security Center
    # ==========================================
    def render_security(self):
        st.header("🛡️ Security & Malware Static Analysis Center")
        
        if not st.session_state.m13_results:
            st.info("Run the pipeline in the Code Editor first.")
            return
            
        m13 = st.session_state.m13_results
        summ = m13["summary"]
        
        sc1, sc2, sc3, sc4 = st.columns(4)
        sc1.metric("🔴 Critical Risks", summ.get("Critical", 0))
        sc2.metric("🟠 High Risks", summ.get("High", 0))
        sc3.metric("🟡 Medium Risks", summ.get("Medium", 0))
        sc4.metric("⚪ Info / Trackers", summ.get("Informational", 0) + summ.get("Low", 0))
        
        st.markdown("---")
        st.subheader("Security Findings & Data Flows")
        if not m13["findings"]:
            st.success("✅ No suspicious API usage or malware indicators detected statically.")
        else:
            df = pd.DataFrame(m13["findings"])
            st.dataframe(df.drop(columns=["id", "rule_id"]), use_container_width=True)
            
        st.markdown("---")
        st.subheader("Obfuscator Classification (M5)")
        m5 = st.session_state.m5_results
        if m5:
            st.write(f"**Predicted Tool Family:** {m5['fingerprint']['tool']} (Confidence: {m5['fingerprint']['confidence']})")
            if m5['detected_signatures']:
                st.write([s['name'] for s in m5['detected_signatures']])

    # ==========================================
    # ⚡ Validation & Perf
    # ==========================================
    def render_validation_perf(self):
        st.header("⚡ Validation, Performance & Similarity Center")
        
        tabs = st.tabs(["Performance Profiler", "Validation & Contracts", "Clone Detection", "Symbolic Constraints"])
        
        with tabs[0]:
            st.subheader("Execution Bottlenecks (M20)")
            p_stats = st.session_state.profiler_stats
            if p_stats:
                st.write(f"**Total Execution Time:** {p_stats['total_time_ms']} ms")
                if not p_stats.get("cached_run"):
                    df = pd.DataFrame([{"Stage": k, "Time (ms)": v["time_ms"], "RAM (MB)": v["mem_mb"]} for k, v in p_stats["stages"].items()])
                    st.dataframe(df.style.highlight_max(color='rgba(255, 75, 75, 0.4)'), use_container_width=True)
                else:
                    st.success("Results loaded instantly from SHA-256 Analysis Cache.")
            else:
                st.info("Run Pipeline first.")
                
        with tabs[1]:
            st.subheader("AST Differential & Semantic Consistency (M19)")
            if st.session_state.m19_results:
                diff = st.session_state.m19_results.get("ast_diff", {})
                st.write(f"Nodes Added: **{diff.get('added')}** | Removed: **{diff.get('removed')}** | Modified: **{diff.get('modified')}** | Preserved: **{diff.get('preserved')}**")
                if diff.get("dangerous_changes"):
                    st.error("Potentially Unsafe Modifications:\n" + "\n".join(diff["dangerous_changes"]))
                else:
                    st.success("No dangerous top-level structure shifts detected.")
                    
        with tabs[2]:
            st.subheader("Structural Clone Fingerprinting (M17)")
            if st.session_state.m17_results and "stats" in st.session_state.m17_results:
                stats = st.session_state.m17_results["stats"]
                st.write(f"**Overall Structural Similarity:** {stats['overall_similarity_score']*100:.2f}%")
                st.write(f"**Type-1 Exact Clone:** {stats['type1_exact_match']}")
                st.write(f"**Type-2 Normalized Clone:** {stats['type2_normalized_match']}")
                st.code(f"Source A Fingerprint: {stats['fingerprint_a']}\nSource B Fingerprint: {stats['fingerprint_b']}")
            else:
                st.info("Upload Source B in the Sidebar to calculate clone similarity.")
                
        with tabs[3]:
            st.subheader("Z3 Constraint Solver & Branch Feasibility (M15)")
            if st.session_state.m15_results and "paths" in st.session_state.m15_results:
                st.dataframe(pd.DataFrame(st.session_state.m15_results["paths"]), use_container_width=True)
            else:
                st.info("Enable Symbolic Execution in the Sidebar config and re-run.")

    # ==========================================
    # 🧩 Plugins & API
    # ==========================================
    def render_plugins_api(self):
        st.header("🧩 Plugin Architecture & Local API")
        
        tabs = st.tabs(["Plugin Manager", "Developer Templates", "Programmatic API"])
        
        with tabs[0]:
            st.subheader("Installed Plugins")
            
            c_up, c_warn = st.columns([1, 2])
            with c_up:
                plugin_file = st.file_uploader("Upload Custom Plugin (.py)", type=["py"])
                if plugin_file and st.button("Install Plugin"):
                    path = os.path.join(PLUGIN_DIR, os.path.basename(plugin_file.name))
                    with open(path, "wb") as f:
                        f.write(plugin_file.getvalue())
                    self.registry.discover_plugins()
                    self.dispatch_notification("Plugin installed. Please approve and enable it.", "🧩")
                    st.rerun()
            with c_warn:
                st.warning("⚠️ **Security Notice**: CodeUnveil Python plugins execute in the host process and are NOT sandboxed. Only approve plugins from trusted developers.")
            
            st.markdown("---")
            plugins = self.registry.discovered_plugins
            state = self.registry.state
            
            if not plugins:
                st.info("No external plugins discovered. Install one or generate a template.")
            else:
                for pid, p in plugins.items():
                    meta = p["metadata"]
                    approved = state.get(pid, {}).get("approved", False)
                    enabled = state.get(pid, {}).get("enabled", False)
                    
                    with st.expander(f"{'✅' if enabled else '❌'} {meta.name} v{meta.version} ({meta.category})"):
                        st.write(f"**Author:** {meta.author} | **ID:** {pid}")
                        st.write(f"**Description:** {meta.description}")
                        st.write(f"**Requested Permissions:** `{', '.join(meta.permissions)}`")
                        
                        ca, cb, cc = st.columns(3)
                        if not approved:
                            if ca.button("Approve Trust & Enable", key=f"app_{pid}", type="primary"):
                                self.registry.approve_plugin(pid)
                                success, msg = self.registry.enable_plugin(pid)
                                if success:
                                    self.dispatch_notification(f"Plugin {meta.name} enabled!", "🚀")
                                else:
                                    st.error(msg)
                                st.rerun()
                        else:
                            if not enabled:
                                if ca.button("Enable Plugin", key=f"en_{pid}"):
                                    success, msg = self.registry.enable_plugin(pid)
                                    if success:
                                        self.dispatch_notification(f"Plugin {meta.name} enabled!", "🚀")
                                    else:
                                        st.error(msg)
                                    st.rerun()
                            else:
                                if ca.button("Disable Plugin", key=f"dis_{pid}"):
                                    self.registry.disable_plugin(pid)
                                    st.rerun()
                                    
                        if cb.button("🗑️ Delete Plugin", key=f"del_{pid}"):
                            self.registry.delete_plugin(pid)
                            self.dispatch_notification(f"Plugin {pid} deleted.", "🗑️")
                            st.rerun()

        with tabs[1]:
            st.subheader("Developer Center & SDK")
            st.write("Bootstrap your own custom rules by copying these SDK templates.")
            
            t_type = st.radio("Select Template Type", ["Detection", "Transformation"])
            template_code = self.registry.get_template(t_type)
            st_ace(value=template_code, language="python", theme=st.session_state.editor_theme, readonly=True, min_lines=20)
            
        with tabs[2]:
            st.subheader("🤖 Local Programmatic API")
            st.write("CodeUnveil exposes an optional headless FastAPI wrapper allowing external scripts to automatically trigger the `PipelineOrchestrator` on port 8000.")
            
            is_running = LocalAPIServer.is_running()
            
            c_stat, c_ctrl = st.columns(2)
            with c_stat:
                st.metric("API Server Status", "🟢 Running (Port 8000)" if is_running else "🔴 Stopped")
            with c_ctrl:
                if not is_running:
                    if st.button("Start Local API", type="primary"):
                        succ, msg = LocalAPIServer.start(8000)
                        if succ: self.dispatch_notification(msg, "🤖")
                        st.rerun()
                else:
                    if st.button("Stop Local API"):
                        LocalAPIServer.stop()
                        self.dispatch_notification("API Server Stopped.", "🛑")
                        st.rerun()
                        
            st.markdown("#### API Endpoint: `POST http://127.0.0.1:8000/api/v1/analyze`")
            st.code('{"source_code": "var _0x123 = 1;", "apply_dce": false}', language="json")

    # ==========================================
    # ✅ Quality Assurance
    # ==========================================
    def render_qa_center(self):
        st.header("✅ Quality Assurance & Compatibility (v1.0.0)")
        st.write("Perform comprehensive System Audits, Cross-Module Regression Tests, and Data Integrity checks.")
        
        c_btn, c_stat = st.columns([1, 3])
        with c_btn:
            if st.button("🚀 Run Comprehensive v1.0.0 Audit", type="primary", use_container_width=True):
                with st.spinner("Executing Integration Tests, Parser Fuzzers, and Integrity Checks..."):
                    engine = QAEngine()
                    st.session_state.m24_results = engine.run_comprehensive_audit()
                    self.dispatch_notification("v1.0.0 Audit Complete.", "✅")
                    
        with c_stat:
            if st.session_state.m24_results:
                res = st.session_state.m24_results
                st.write(f"**Environment:** Python {res['environment']['python_version']} on {res['environment']['os_platform']}")
                
        st.markdown("---")
        
        if st.session_state.m24_results:
            res = st.session_state.m24_results
            summ = res["summary"]
            
            sc1, sc2, sc3, sc4 = st.columns(4)
            sc1.metric("Total Checks", summ["total"])
            sc2.metric("✅ Passed", summ["passed"])
            sc3.metric("❌ Failed", summ["failed"])
            sc4.metric("⚠️ Warnings", summ["warnings"])
            
            st.markdown("---")
            tabs = st.tabs(["Integration & Regression", "Parser & Security", "Data Integrity"])
            
            def _render_test_group(group_key):
                data = res.get(group_key, [])
                if not data:
                    st.info("No tests in this category.")
                else:
                    df = pd.DataFrame(data)
                    st.dataframe(
                        df.style.map(lambda x: 'color: #4CAF50;' if x == 'PASS' else 'color: #F44336;' if x == 'FAIL' else 'color: #FF9800;' if x == 'WARNING' else '', subset=['status']),
                        use_container_width=True
                    )
            
            with tabs[0]: _render_test_group("regression_tests")
            with tabs[1]:
                st.subheader("Parser Robustness")
                _render_test_group("parser_robustness")
                st.subheader("Security Constraints")
                _render_test_group("security_audit")
            with tabs[2]: _render_test_group("data_integrity")
            
            st.markdown("---")
            st.markdown("#### 📄 Export QA Reports")
            ec1, ec2 = st.columns(2)
            with ec1:
                st.download_button("Download QA JSON", json.dumps(res, indent=4), "qa_audit_report.json", "application/json", use_container_width=True)
            with ec2:
                exporter = QAEngine()
                exporter.results = res
                st.download_button("Download QA HTML", exporter.generate_html_report(), "qa_audit_report.html", "text/html", use_container_width=True)

if __name__ == "__main__":
    CodeUnveilIDE().run()
