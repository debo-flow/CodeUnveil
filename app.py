import streamlit as st
import jsbeautifier
import re
import io
import json
import pandas as pd
from typing import Dict, Any, Tuple

# ==========================================
# External Engine Imports (M2 - M11)
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

# ==========================================
# M1 Engine Components (Regex & Formatting)
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
    for key in ['uploader_key', 'input_code', 'processed_code', 'm6_original', 'm8_code_base', 'm9_code_base', 'm10_code_base', 'm11_code_base']:
        if key not in st.session_state: st.session_state[key] = 0 if key == 'uploader_key' else ""
    for key in ['m1_results', 'm2_results', 'm3_results', 'm4_results', 'm5_results', 'm6_results', 'm7_results', 'm7_replacements', 'm8_results', 'm9_results', 'm10_results', 'm11_results']:
        if key not in st.session_state: st.session_state[key] = None

def reset_app():
    for key in ['input_code', 'processed_code', 'm6_original', 'm8_code_base', 'm9_code_base', 'm10_code_base', 'm11_code_base']: st.session_state[key] = ""
    for key in ['m1_results', 'm2_results', 'm3_results', 'm4_results', 'm5_results', 'm6_results', 'm7_results', 'm7_replacements', 'm8_results', 'm9_results', 'm10_results', 'm11_results']: st.session_state[key] = None
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
            
        apply_dce = st.checkbox("🗑️ Enable Destructive Dead Code Elimination (M7)", value=False)
        
        if st.button("🔄 Reset / Clear All", use_container_width=True):
            reset_app()
            st.rerun()

    tabs = st.tabs([
        "🚀 Main", "🌳 M2", "🧶 M3", "🧮 M4", "🚨 M5", "⚖️ Compare", "🔀 M6", 
        "🪦 M7", "🏷️ M8", "📦 M9", "⚙️ M10", "✨ M11: Expr"
    ])

    # ---------------------------
    # MAIN PIPELINE EXECUTION
    # ---------------------------
    with tabs[0]:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Input Original JavaScript")
            user_input = st.text_area("Paste obfuscated code here:", value=st.session_state.input_code, height=350)
            
            if st.button("🚀 Execute Full Analysis Pipeline", type="primary", use_container_width=True):
                if not user_input.strip(): st.error("Please provide JavaScript code.")
                else:
                    with st.spinner("Executing Complete Static Pipeline..."):
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
                        
                        # M11 Expression Engine
                        st.session_state.m11_code_base = transformed_code
                        expr_engine = ExprAnalyzer()
                        st.session_state.m11_results = expr_engine.analyze(transformed_code)
                            
                        processed, status = DeobfuscatorEngine().process(transformed_code)
                        if status == "Success": st.session_state.processed_code = processed
                        else: st.error(status)

        with col2:
            st.subheader("Output Deobfuscated Code")
            st.text_area("Normalized result:", value=st.session_state.processed_code, height=350, disabled=True)
            if st.session_state.processed_code:
                st.download_button("💾 Download Processed Code", st.session_state.processed_code, "codeunveil_output.js", "text/javascript", use_container_width=True)

    # ---------------------------
    # TABS 1-10 Preserved UI Views
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

    # ---------------------------
    # TAB 12 (M11): Expression Simplification Engine
    # ---------------------------
    with tabs[11]:
        st.subheader("✨ Advanced Expression Simplification & Constant Folding")
        if not st.session_state.m11_results:
            st.info("Execute the pipeline in Tab 1 to generate Expression Analytics.")
        else:
            m11 = st.session_state.m11_results
            if m11.get("status") == "error":
                st.error(m11["message"])
            else:
                stats = m11["stats"]
                sc1, sc2, sc3, sc4 = st.columns(4)
                sc1.metric("Expressions Analyzed", stats["total_expressions"])
                sc2.metric("Constant Folds", stats["constant_folds"])
                sc3.metric("Constant Propagations", stats["constant_propagations"])
                sc4.metric("Arithmetic Simplifications", stats["simplifications"])
                
                st.markdown("---")
                st.markdown("#### 🛠️ Interactive Safe Transformation Sandbox")
                st.write("Review JS-compliant mathematically safe constant folds (e.g., `2 + 3 -> 5`, `true && x -> x`).")
                
                if not m11["replacements"]:
                    st.success("No expression optimizations available. Code is well simplified.")
                else:
                    df_data = []
                    for r in m11["replacements"]:
                        df_data.append({
                            "Apply": True,
                            "Type": r["type"],
                            "Original Expression": r["original"],
                            "Simplified Result": r["resolved"],
                            "_range": r["range"]
                        })
                    
                    df = pd.DataFrame(df_data)
                    edited_df = st.data_editor(
                        df,
                        column_config={
                            "Apply": st.column_config.CheckboxColumn("Apply Transform"),
                            "_range": None # Hide metadata
                        },
                        disabled=["Type", "Original Expression", "Simplified Result"],
                        use_container_width=True
                    )
                    
                    if st.button("🚀 Apply Selected Expression Simplify", type="primary"):
                        approved = edited_df[edited_df["Apply"] == True]
                        if approved.empty:
                            st.warning("No transforms selected.")
                        else:
                            payload = [{"apply": True, "range": row["_range"], "resolved_value": row["Simplified Result"]} for _, row in approved.iterrows()]
                            engine = ExprAnalyzer()
                            new_code = engine.transform(st.session_state.m11_code_base, payload)
                            
                            processed, status = DeobfuscatorEngine().process(new_code)
                            if status == "Success":
                                st.session_state.processed_code = processed
                                st.session_state.m11_code_base = new_code
                                st.success(f"Successfully optimized {len(payload)} expressions! View Output in Tab 1.")
                            else:
                                st.error("Error formatting code.")

                st.download_button("📄 Download M11 Expr Report (JSON)", json.dumps(m11, indent=4), "expr_report.json", "application/json")

if __name__ == "__main__":
    main()
