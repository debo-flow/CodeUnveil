import streamlit as st
import jsbeautifier
import re
import io
import json
import pandas as pd
from typing import Dict, Any, Tuple

# ==========================================
# External Engine Imports (M2 - M13)
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
    for key in ['uploader_key', 'input_code', 'processed_code', 'm6_original', 'm8_code_base', 'm9_code_base', 'm10_code_base', 'm11_code_base', 'm12_original_stats']:
        if key not in st.session_state: st.session_state[key] = 0 if key == 'uploader_key' else ""
    
    engine_keys = [
        'm1_results', 'm2_results', 'm3_results', 'm4_results', 'm5_results', 
        'm6_results', 'm7_results', 'm7_replacements', 'm8_results', 'm9_results', 
        'm10_results', 'm11_results', 'm12_results', 'm13_results'
    ]
    for key in engine_keys:
        if key not in st.session_state: st.session_state[key] = None

def reset_app():
    for key in ['input_code', 'processed_code', 'm6_original', 'm8_code_base', 'm9_code_base', 'm10_code_base', 'm11_code_base', 'm12_original_stats']: st.session_state[key] = ""
    engine_keys = [
        'm1_results', 'm2_results', 'm3_results', 'm4_results', 'm5_results', 
        'm6_results', 'm7_results', 'm7_replacements', 'm8_results', 'm9_results', 
        'm10_results', 'm11_results', 'm12_results', 'm13_results'
    ]
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
        uploaded_file = st.file_uploader("Upload Target JS (.js)", type=["js", "txt"], key=f"uploader_{st.session_state.uploader_key}")
        if uploaded_file is not None:
            st.session_state.input_code = io.StringIO(uploaded_file.getvalue().decode("utf-8", errors="replace")).read()
            
        st.markdown("#### Configurable Pipeline")
        apply_dce = st.checkbox("🗑️ Destructive Dead Code Removal (M7)", value=False)
        apply_ast_regen = st.checkbox("🏗️ Strict AST Regeneration (M12)", value=False)
        
        if st.button("🔄 Reset / Clear All", use_container_width=True):
            reset_app()
            st.rerun()

    tabs = st.tabs([
        "🚀 Main", "🌳 M2", "🧶 M3", "🧮 M4", "🚨 M5", "⚖️ Compare", "🔀 M6", 
        "🪦 M7", "🏷️ M8", "📦 M9", "⚙️ M10", "✨ M11", "🏗️ M12", "🛡️ M13: Security"
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
                        st.session_state.m6_results = cfg_engine.analyze(transformed_code)
                        if st.session_state.m6_results.get("status") == "success":
                            transformed_code = cfg_engine.transform()

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
                            
                        if apply_ast_regen:
                            success, ast_code, msg = ReconstructionPipeline.rebuild_ast_source(transformed_code)
                            if success: transformed_code = ast_code
                                
                        processed, status = DeobfuscatorEngine().process(transformed_code)
                        if status == "Success": 
                            st.session_state.processed_code = processed
                            st.session_state.m12_results = CodeQualityAnalyzer.analyze(processed)
                            
                            # M13 Security Analysis (Run on fully decoded payload)
                            sec_engine = SecurityAnalyzer()
                            st.session_state.m13_results = sec_engine.analyze(processed, st.session_state.m5_results)
                        else: 
                            st.error(status)

        with col2:
            st.subheader("Output Reconstructed Code")
            st.text_area("Normalized result:", value=st.session_state.processed_code, height=350, disabled=True)
            if st.session_state.processed_code:
                st.download_button("💾 Download Reconstructed JS", st.session_state.processed_code, "codeunveil_output.js", "text/javascript", use_container_width=True)

    # ---------------------------
    # TABS 1-12 Preserved Views (Omitted for brevity visually, logic maintained)
    # ---------------------------
    with tabs[1]:
        if st.session_state.m2_results: st.json(st.session_state.m2_results.get("ast_tree", {}), expanded=False)
    with tabs[2]:
        if st.session_state.m3_results: st.metric("Extracted Strings", st.session_state.m3_results["stats"]["total_strings"])
    with tabs[3]:
        if st.session_state.m4_results is not None:
            if st.session_state.m4_results: st.dataframe(pd.DataFrame(st.session_state.m4_results).drop(columns=["Full Decoded"]), use_container_width=True)
            else: st.success("No encodings detected.")
    with tabs[4]:
        if st.session_state.m5_results: st.write(f"**Severity Level:** {st.session_state.m5_results['severity_level']}")
    with tabs[5]: st.write("Target Comparison requires external file.")
    with tabs[6]:
        if st.session_state.m6_results and st.session_state.m6_results.get("status") == "success": st.graphviz_chart(st.session_state.m6_results["dot_graph"])
    with tabs[7]:
        if st.session_state.m7_results and st.session_state.m7_results.get("status") == "success": st.metric("Safely Removable Blocks", st.session_state.m7_results["stats"]["safely_removable"])
    with tabs[8]:
        if st.session_state.m8_results and st.session_state.m8_results.get("status") == "success": st.metric("Total Identifiers", st.session_state.m8_results["stats"]["total_identifiers"])
    with tabs[9]:
        if st.session_state.m9_results and st.session_state.m9_results.get("status") == "success": st.metric("String Arrays", st.session_state.m9_results["stats"]["total_arrays"])
    with tabs[10]:
        if st.session_state.m10_results and st.session_state.m10_results.get("status") == "success": st.metric("Total Functions", st.session_state.m10_results["stats"]["total_functions"])
    with tabs[11]:
        if st.session_state.m11_results and st.session_state.m11_results.get("status") == "success": st.metric("Expressions Folded", st.session_state.m11_results["stats"]["constant_folds"])
    with tabs[12]:
        if st.session_state.m12_results: st.metric("Avg Line Length", round(st.session_state.m12_results.get("avg_line_length", 0), 1))

    # ---------------------------
    # TAB 14 (M13): Security Dashboard & Taint Tracking
    # ---------------------------
    with tabs[13]:
        st.subheader("🛡️ Static Security & Malware Analysis Engine")
        if not st.session_state.m13_results:
            st.info("Execute the pipeline in Tab 1 to generate Security Analytics.")
        else:
            m13 = st.session_state.m13_results
            if m13.get("status") == "error":
                st.error(m13["message"])
            else:
                st.markdown("#### 🚨 Vulnerability & Suspicious Pattern Summary")
                summ = m13["summary"]
                sc1, sc2, sc3, sc4, sc5 = st.columns(5)
                sc1.metric("🔴 Critical", summ.get("Critical", 0))
                sc2.metric("🟠 High", summ.get("High", 0))
                sc3.metric("🟡 Medium", summ.get("Medium", 0))
                sc4.metric("🔵 Low", summ.get("Low", 0))
                sc5.metric("⚪ Info", summ.get("Informational", 0))
                
                st.markdown("---")
                st.markdown("#### 🔎 Findings Dashboard (False Positive Management)")
                st.write("Review detected security indicators, data flows, and evasive code patterns. Update the 'Status' and 'Notes' columns to track your investigation.")
                
                if not m13["findings"]:
                    st.success("✅ No suspicious API usage or malware indicators detected statically.")
                else:
                    df = pd.DataFrame(m13["findings"])
                    
                    # Interactive editor for False Positives and Analyst notes
                    edited_df = st.data_editor(
                        df,
                        column_config={
                            "status": st.column_config.SelectboxColumn("Status", options=["Open", "Reviewed", "False Positive"], required=True),
                            "notes": st.column_config.TextColumn("Analyst Notes"),
                            "snippet": st.column_config.TextColumn("Code Snippet", disabled=True),
                            "remediation": None, "id": None, "rule_id": None # Hide bulky columns
                        },
                        disabled=["severity", "confidence", "category", "name", "description", "location"],
                        use_container_width=True,
                        num_rows="fixed"
                    )
                    
                    if st.button("💾 Save Review State"):
                        # Update session state with edits
                        st.session_state.m13_results["findings"] = edited_df.to_dict('records')
                        st.success("Review notes and statuses saved.")
                        
                    st.markdown("---")
                    st.markdown("#### 📄 Export Security Reports")
                    
                    ec1, ec2, ec3 = st.columns(3)
                    with ec1:
                        st.download_button("Download JSON", json.dumps(st.session_state.m13_results, indent=4), "security_report.json", "application/json", use_container_width=True)
                    with ec2:
                        csv_data = pd.DataFrame(st.session_state.m13_results["findings"]).to_csv(index=False)
                        st.download_button("Download CSV", csv_data, "security_report.csv", "text/csv", use_container_width=True)
                    with ec3:
                        html_report = SecurityAnalyzer.generate_html_report(st.session_state.m13_results)
                        st.download_button("Download HTML", html_report, "security_report.html", "text/html", use_container_width=True)

if __name__ == "__main__":
    main()
