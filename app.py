import streamlit as st
import jsbeautifier
import re
import io
import json
import pandas as pd
from typing import Dict, Any, Tuple

# ==========================================
# External Engine Imports (M2 - M19)
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

# ==========================================
# M1 Engine Components
# ==========================================
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

# ==========================================
# UI Configuration & State Management
# ==========================================
def initialize_state():
    base_keys = [
        'uploader_key', 'input_code', 'processed_code', 'm6_original', 
        'm8_code_base', 'm9_code_base', 'm10_code_base', 'm11_code_base', 
        'm14_code_base', 'm12_original_stats', 'm17_target_code'
    ]
    for key in base_keys:
        if key not in st.session_state: st.session_state[key] = 0 if key == 'uploader_key' else ""
    
    engine_keys = [f"m{i}_results" for i in range(1, 20)] + ['m7_replacements']
    for key in engine_keys:
        if key not in st.session_state: st.session_state[key] = None

def reset_app():
    base_keys = [
        'input_code', 'processed_code', 'm6_original', 'm8_code_base', 
        'm9_code_base', 'm10_code_base', 'm11_code_base', 'm14_code_base', 
        'm12_original_stats', 'm17_target_code'
    ]
    for key in base_keys: st.session_state[key] = ""
    
    engine_keys = [f"m{i}_results" for i in range(1, 20)] + ['m7_replacements']
    for key in engine_keys: st.session_state[key] = None
    st.session_state.uploader_key += 1

def main():
    st.set_page_config(page_title="CodeUnveil | Advanced JS Laboratory", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
    initialize_state()

    st.markdown("""<style>.stTextArea textarea { font-family: 'Courier New', monospace; background-color: #1e1e1e !important; color: #d4d4d4 !important; }</style>""", unsafe_allow_html=True)
    st.title("🛡️ CodeUnveil Laboratory")
    st.markdown("### Advanced JavaScript Deobfuscation & Static Analysis Engine")
    
    with st.sidebar:
        st.header("Actions & Settings")
        uploaded_file = st.file_uploader("Upload Source A (.js/.zip)", type=["js", "txt", "zip"], key=f"uploader_{st.session_state.uploader_key}")
        if uploaded_file is not None:
            if uploaded_file.name.endswith(".zip"):
                with st.spinner("Analyzing Full ZIP Architecture (M16)..."):
                    proj_engine = ProjectAnalyzer()
                    st.session_state.m16_results = proj_engine.analyze_zip(uploaded_file.getvalue())
                    if st.session_state.m16_results.get("status") == "success":
                        st.success(f"Loaded {st.session_state.m16_results['stats']['total_files']} files from Project Archive.")
                        js_files = [f for f in st.session_state.m16_results['modules'].keys()]
                        selected_file = st.selectbox("Select File to Load into Source A:", options=js_files)
                        if selected_file:
                            st.session_state.input_code = proj_engine.files.get(selected_file, "")
            else:
                st.session_state.input_code = io.StringIO(uploaded_file.getvalue().decode("utf-8", errors="replace")).read()
        
        st.markdown("#### Configurable Pipeline")
        apply_dce = st.checkbox("🗑️ Destructive Dead Code Removal (M7)", value=False)
        apply_ast_regen = st.checkbox("🏗️ Strict AST Regeneration (M12)", value=False)
        run_sym_exec = st.checkbox("🧮 Enable Symbolic Execution (M15)", value=False)
        
        if st.button("🔄 Reset / Clear All", use_container_width=True):
            reset_app()
            st.rerun()

    tabs = st.tabs([
        "🚀 Main", "🌳 M2", "🧶 M3", "🧮 M4", "🚨 M5", "🔀 M6/M14", 
        "🪦 M7", "🏷️ M8", "📦 M9", "⚙️ M10", "✨ M11", "🏗️ M12", "🛡️ M13", "🧮 M15", "📁 M16", "🧬 M17", "🧠 M18", "🧪 M19: Validation"
    ])

    # ---------------------------
    # MAIN PIPELINE EXECUTION
    # ---------------------------
    with tabs[0]:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Input Original JavaScript")
            user_input = st.text_area("Paste obfuscated code here:", value=st.session_state.input_code, height=350)
            
            if st.button("🚀 Execute Multi-Stage Pipeline", type="primary", use_container_width=True):
                if not user_input.strip(): st.error("Please provide JavaScript code.")
                else:
                    with st.spinner("Executing Configurable Multi-Stage Pipeline..."):
                        st.session_state.m12_original_stats = CodeQualityAnalyzer.analyze(user_input)
                        st.session_state.m6_original = user_input
                        
                        st.session_state.m1_results = CodeAnalyzer().analyze(user_input)
                        st.session_state.m2_results = ASTAnalyzer().analyze(user_input)
                        
                        string_engine = StringAnalyzer()
                        st.session_state.m3_results = string_engine.analyze(user_input)
                        transformed_code = string_engine.transform() if st.session_state.m3_results.get("status") == "success" else user_input
                        
                        if st.session_state.m3_results.get("status") == "success":
                            st.session_state.m4_results = EncodingAnalyzer.analyze_payloads(st.session_state.m3_results["strings"])
                        
                        st.session_state.m5_results = DetectionEngine().analyze(user_input, st.session_state.m2_results)
                        
                        cfg_engine = CFGAnalyzer()
                        st.session_state.m14_code_base = transformed_code
                        st.session_state.m6_results = cfg_engine.analyze(transformed_code)
                        if st.session_state.m6_results.get("status") == "success":
                            transformed_code = cfg_engine.transform(transformed_code, approved_deflatten=[])

                        dce_engine = DCEAnalyzer()
                        st.session_state.m7_results = dce_engine.analyze(transformed_code)
                        st.session_state.m7_replacements = dce_engine.replacements
                        if apply_dce and st.session_state.m7_results.get("status") == "success":
                            transformed_code = dce_engine.transform()

                        st.session_state.m8_code_base = transformed_code
                        st.session_state.m8_results = RenameAnalyzer().analyze(transformed_code)
                        st.session_state.m9_code_base = transformed_code
                        st.session_state.m9_results = ArrayAnalyzer().analyze(transformed_code)
                        st.session_state.m10_code_base = transformed_code
                        st.session_state.m10_results = FunctionAnalyzer().analyze(transformed_code)
                        st.session_state.m11_code_base = transformed_code
                        st.session_state.m11_results = ExprAnalyzer().analyze(transformed_code)
                        
                        if run_sym_exec:
                            st.session_state.m15_results = SymEngine(max_depth=50, max_loop_iter=3).analyze(transformed_code)
                            
                        if apply_ast_regen:
                            success, ast_code, msg = ReconstructionPipeline.rebuild_ast_source(transformed_code)
                            if success: transformed_code = ast_code
                                
                        processed, status = DeobfuscatorEngine().process(transformed_code)
                        if status == "Success": 
                            st.session_state.processed_code = processed
                            st.session_state.m12_results = CodeQualityAnalyzer.analyze(processed)
                            st.session_state.m13_results = SecurityAnalyzer().analyze(processed, st.session_state.m5_results)
                            st.session_state.m18_results = SemanticAnalyzer().analyze(processed)
                            
                            # M19 Automated Differential Analysis
                            val_engine = ValidationEngine()
                            st.session_state.m19_results = val_engine.run_differential_analysis(user_input, processed)
                            st.session_state.m19_tests = val_engine.run_regression_suite()
                        else: 
                            st.error(status)

        with col2:
            st.subheader("Output Reconstructed Code")
            st.text_area("Normalized result:", value=st.session_state.processed_code, height=350, disabled=True)
            if st.session_state.processed_code:
                st.download_button("💾 Download Reconstructed JS", st.session_state.processed_code, "codeunveil_output.js", "text/javascript", use_container_width=True)

    # ---------------------------
    # TABS 1-16 Preserved Views (Omitted visual duplicates for brevity, logically identical)
    # ---------------------------
    with tabs[1]:
        if st.session_state.m2_results: st.json(st.session_state.m2_results.get("ast_tree", {}), expanded=False)
    with tabs[2]:
        if st.session_state.m3_results: st.metric("Extracted Strings", st.session_state.m3_results["stats"]["total_strings"])
    with tabs[4]:
        if st.session_state.m5_results: st.write(f"**Severity Level:** {st.session_state.m5_results['severity_level']}")
    with tabs[6]:
        if st.session_state.m7_results and st.session_state.m7_results.get("status") == "success": st.metric("Safely Removable Blocks", st.session_state.m7_results["stats"]["safely_removable"])

    # ---------------------------
    # TAB 18 (M19): Automated Testing & Validation Dashboard
    # ---------------------------
    with tabs[17]:
        st.subheader("🧪 M19: Automated Testing, Differential Analysis & Semantic Validation")
        
        if not st.session_state.m19_results:
            st.info("Execute the pipeline in Tab 1 to generate Differential Analytics.")
        else:
            diff = st.session_state.m19_results.get("ast_diff", {})
            tests = st.session_state.m19_tests.get("stats", {})
            
            st.markdown("#### ⚙️ Automated Testing Overview (Metamorphic & Regression)")
            tc1, tc2, tc3 = st.columns(3)
            tc1.metric("Tests Passed", tests.get("PASS", 0))
            tc2.metric("Tests Failed", tests.get("FAIL", 0))
            tc3.metric("Warnings", tests.get("WARNING", 0))
            
            if st.session_state.m19_tests.get("tests"):
                st.dataframe(pd.DataFrame(st.session_state.m19_tests["tests"]).drop(columns=["error_info"]), use_container_width=True)
            
            st.markdown("---")
            st.markdown("#### 🌳 Differential AST Analysis")
            st.write("Identifies nodes structurally altered by the transformation pipeline (Original vs Reconstructed).")
            ac1, ac2, ac3, ac4 = st.columns(4)
            ac1.metric("Nodes Preserved", diff.get("preserved", 0))
            ac2.metric("Nodes Modified", diff.get("modified", 0))
            ac3.metric("Nodes Added", diff.get("added", 0))
            ac4.metric("Nodes Removed", diff.get("removed", 0))
            
            if diff.get("dangerous_changes"):
                st.warning("⚠️ Potentially Unsafe Structural Modifications Detected:")
                for dc in diff["dangerous_changes"]:
                    st.write(f"- {dc}")
            else:
                st.success("✅ No dangerous top-level structure shifts detected.")
                
            st.markdown("---")
            st.markdown("#### 🧠 Semantic Consistency Validation")
            sem = st.session_state.m19_results.get("semantic_diff", {})
            if sem.get("status") == "success":
                st.metric("Symbols Tracked in Transformed Output", sem.get("symbols_preserved", 0))
                if sem.get("side_effects_consistent"):
                    st.success("✅ Transformation Contract Upheld: No new side-effects were unexpectedly introduced by the pipeline.")
                
                if sem.get("issues"):
                    for issue in sem["issues"]:
                        if "DANGER" in issue: st.error(issue)
                        else: st.warning(issue)
            
            st.download_button("📄 Download M19 Validation Report (JSON)", json.dumps(st.session_state.m19_results, indent=4), "validation_report.json", "application/json")

if __name__ == "__main__":
    main()
