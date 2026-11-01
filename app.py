import streamlit as st
import jsbeautifier
import re
import io
import json
import pandas as pd
from typing import Dict, Any, Tuple

# ==========================================
# External Engine Imports (M2 - M17)
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
    
    engine_keys = [f"m{i}_results" for i in range(1, 18)] + ['m7_replacements']
    for key in engine_keys:
        if key not in st.session_state: st.session_state[key] = None

def reset_app():
    base_keys = [
        'input_code', 'processed_code', 'm6_original', 'm8_code_base', 
        'm9_code_base', 'm10_code_base', 'm11_code_base', 'm14_code_base', 
        'm12_original_stats', 'm17_target_code'
    ]
    for key in base_keys: st.session_state[key] = ""
    
    engine_keys = [f"m{i}_results" for i in range(1, 18)] + ['m7_replacements']
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
        
        # Target B Upload for Similarity Engine
        upload_b = st.file_uploader("Upload Source B (.js) for Clone Comp.", type=["js", "txt"], key="upload_b")
        if upload_b is not None:
            st.session_state.m17_target_code = io.StringIO(upload_b.getvalue().decode("utf-8", errors="replace")).read()
            
        st.markdown("#### Configurable Pipeline")
        apply_dce = st.checkbox("🗑️ Destructive Dead Code Removal (M7)", value=False)
        apply_ast_regen = st.checkbox("🏗️ Strict AST Regeneration (M12)", value=False)
        run_sym_exec = st.checkbox("🧮 Enable Symbolic Execution (M15)", value=False)
        
        if st.button("🔄 Reset / Clear All", use_container_width=True):
            reset_app()
            st.rerun()

    tabs = st.tabs([
        "🚀 Main", "🌳 M2", "🧶 M3", "🧮 M4", "🚨 M5", "🔀 M6/M14", 
        "🪦 M7", "🏷️ M8", "📦 M9", "⚙️ M10", "✨ M11", "🏗️ M12", "🛡️ M13", "🧮 M15", "📁 M16", "🧬 M17: Clones"
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
                            
                            # M17 Auto-Run Clone Detection if Source B exists
                            if st.session_state.m17_target_code:
                                sim_engine = SimilarityEngine()
                                st.session_state.m17_results = sim_engine.compare(user_input, st.session_state.m17_target_code)
                        else: 
                            st.error(status)

        with col2:
            st.subheader("Output Reconstructed Code")
            st.text_area("Normalized result:", value=st.session_state.processed_code, height=350, disabled=True)
            if st.session_state.processed_code:
                st.download_button("💾 Download Reconstructed JS", st.session_state.processed_code, "codeunveil_output.js", "text/javascript", use_container_width=True)

    # ---------------------------
    # TAB 16 (M17): Clone Detection & Fingerprinting
    # ---------------------------
    with tabs[15]:
        st.subheader("🧬 Code Similarity, Clone Detection & Fingerprinting Engine")
        
        if not st.session_state.m17_target_code:
            st.info("Upload 'Source B' in the sidebar and execute the pipeline to generate Clone Similarity analytics.")
        elif not st.session_state.m17_results:
            st.warning("Execute the pipeline in Tab 1 to run comparisons.")
        else:
            m17 = st.session_state.m17_results
            if m17.get("status") == "error":
                st.error(m17["message"])
            else:
                stats = m17["stats"]
                mets = m17["metrics"]
                
                score = stats["overall_similarity_score"] * 100
                score_color = "red" if score > 85 else "orange" if score > 50 else "green"
                st.markdown(f"### Overall Structural Similarity: <span style='color:{score_color}'>{score:.2f}%</span>", unsafe_allow_html=True)
                
                st.markdown("---")
                sc1, sc2, sc3, sc4 = st.columns(4)
                sc1.metric("AST Jaccard Index", f"{stats['ast_jaccard_score']*100:.1f}%")
                sc2.metric("Token Frequency Score", f"{mets['cosine_freq_score']*100:.1f}%")
                sc3.metric("CFG Edge Similarity", f"{stats['cfg_edge_similarity']*100:.1f}%")
                sc4.metric("Type-1 Exact Clone?", "Yes" if stats["type1_exact_match"] else "No")
                
                st.markdown("---")
                st.markdown("#### 🔍 Structural Hash Fingerprints (Normalized)")
                st.info("These fingerprints ignore mutable literals and renamed identifiers (Type-2 Clone check). If they match, the files are structurally identical obfuscated payloads.")
                
                hc1, hc2 = st.columns(2)
                hc1.metric("Source A Fingerprint", stats["fingerprint_a"])
                hc2.metric("Source B Fingerprint", stats["fingerprint_b"])
                
                if stats["type2_normalized_match"]:
                    st.error("🚨 CRITICAL: Type-2 Clone Detected! Both files share identical control-flow and AST structures despite differing variable names.")
                elif score > 85:
                    st.warning("⚠️ High Similarity: Type-3 Clone Detected! Minor structural deviations but highly homologous payloads.")
                else:
                    st.success("✅ Files are structurally distinct. Semantic equivalence is highly unlikely.")
                    
                st.download_button("📄 Download M17 Similarity Report (JSON)", json.dumps(m17, indent=4), "similarity_report.json", "application/json")

if __name__ == "__main__":
    main()
