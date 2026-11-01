import streamlit as st
import jsbeautifier
import re
import io
import json
import pandas as pd
from typing import Dict, Any, Tuple

from ast_engine import ASTAnalyzer
from string_engine import StringAnalyzer
from encoding_engine import EncodingAnalyzer
from detection_engine import DetectionEngine
from cfg_engine import CFGAnalyzer

# ==========================================
# M1 Engine Components (Preserved)
# ==========================================
class CodeAnalyzer:
    @staticmethod
    def analyze(code: str) -> Dict[str, Any]:
        if not code or not code.strip(): return {"error": "Empty input"}
        hex_literals = re.findall(r'\b0x[0-9a-fA-F]+\b', code, re.IGNORECASE)
        escaped_strings = re.findall(r'\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}', code, re.IGNORECASE)
        long_strings = re.findall(r'["\']([a-zA-Z0-9+/=]{100,})["\']', code)
        array_access = re.findall(r'\b_[a-zA-Z0-9_]+\b\[[0-9]+\]', code)
        return {
            "hex_count": len(hex_literals), "escaped_count": len(escaped_strings),
            "long_string_count": len(long_strings), "array_access_count": len(array_access),
            "original_length": len(code), "original_lines": len(code.splitlines())
        }

class DeobfuscatorEngine:
    @staticmethod
    def process(code: str) -> Tuple[str, str]:
        if not code or not code.strip(): raise ValueError("No JavaScript code provided.")
        try:
            opts = jsbeautifier.default_options()
            opts.indent_size = 4; opts.space_in_empty_paren = True
            opts.preserve_newlines = True; opts.max_preserve_newlines = 2
            opts.wrap_line_length = 0; opts.break_chained_methods = True
            opts.unescape_strings = False 
            return jsbeautifier.beautify(code, opts), "Success"
        except Exception as e: return "", f"Processing Error: {str(e)}"

# ==========================================
# UI Configuration & State
# ==========================================
def initialize_state():
    for key in ['uploader_key', 'input_code', 'processed_code', 'm1_results', 'm2_results', 'm3_results', 'm4_results', 'm5_results', 'm6_results', 'm6_original']:
        if key not in st.session_state:
            st.session_state[key] = 0 if key == 'uploader_key' else "" if "code" in key or key == 'm6_original' else None

def reset_app():
    for key in ['input_code', 'processed_code', 'm1_results', 'm2_results', 'm3_results', 'm4_results', 'm5_results', 'm6_results', 'm6_original']:
        st.session_state[key] = "" if "code" in key or key == 'm6_original' else None
    st.session_state.uploader_key += 1

def main():
    st.set_page_config(page_title="CodeUnveil | Advanced JS Laboratory", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
    initialize_state()

    st.markdown("""<style>.stTextArea textarea { font-family: 'Courier New', monospace; background-color: #1e1e1e !important; color: #d4d4d4 !important; }</style>""", unsafe_allow_html=True)
    st.title("🛡️ CodeUnveil Laboratory")
    st.markdown("### Advanced JavaScript Deobfuscation & AST Analysis Engine")
    
    with st.sidebar:
        st.header("Actions & Settings")
        uploaded_file = st.file_uploader("Upload Target JS (.js)", type=["js", "txt"], key=f"uploader_{st.session_state.uploader_key}")
        if uploaded_file is not None:
            stringio = io.StringIO(uploaded_file.getvalue().decode("utf-8", errors="replace"))
            st.session_state.input_code = stringio.read()
            
        if st.button("🔄 Reset / Clear All", use_container_width=True):
            reset_app()
            st.rerun()

    tabs = st.tabs([
        "🚀 M1: Deobfuscator", "🌳 M2: AST", "🧶 M3: Strings", 
        "🧮 M4: Encodings", "🚨 M5: Obfuscator", "⚖️ M5: Compare", "🔀 M6: Control Flow"
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
                if not user_input.strip():
                    st.error("Please provide JavaScript code.")
                else:
                    with st.spinner("Executing Complete Static Pipeline..."):
                        # Save base state for M6 comparison
                        st.session_state.m6_original = user_input
                        
                        st.session_state.m1_results = CodeAnalyzer().analyze(user_input)
                        st.session_state.m2_results = ASTAnalyzer().analyze(user_input)
                        
                        # M3 Strings
                        string_engine = StringAnalyzer()
                        st.session_state.m3_results = string_engine.analyze(user_input)
                        transformed_code = string_engine.transform() if st.session_state.m3_results.get("status") == "success" else user_input
                        
                        # M4 Encodings
                        if st.session_state.m3_results.get("status") == "success":
                            st.session_state.m4_results = EncodingAnalyzer.analyze_payloads(st.session_state.m3_results["strings"])
                        
                        # M5 Obfuscation Rules
                        det_engine = DetectionEngine()
                        st.session_state.m5_results = det_engine.analyze(user_input, st.session_state.m2_results)
                        
                        # M6 CFG & Simplification
                        cfg_engine = CFGAnalyzer()
                        st.session_state.m6_results = cfg_engine.analyze(transformed_code)
                        if st.session_state.m6_results.get("status") == "success":
                            transformed_code = cfg_engine.transform()
                            
                        processed, status = DeobfuscatorEngine().process(transformed_code)
                        if status == "Success":
                            st.session_state.processed_code = processed
                        else: st.error(status)

        with col2:
            st.subheader("Output Deobfuscated Code")
            st.text_area("Normalized result:", value=st.session_state.processed_code, height=350, disabled=True)
            if st.session_state.processed_code:
                st.download_button("💾 Download Processed Code", st.session_state.processed_code, "codeunveil_output.js", "text/javascript", use_container_width=True)

    # ---------------------------
    # TABS 1-5
    # ---------------------------
    with tabs[1]:
        if st.session_state.m2_results: st.json(st.session_state.m2_results.get("ast_tree", {}), expanded=False)
        else: st.info("Awaiting pipeline...")
    with tabs[2]:
        if st.session_state.m3_results:
            st.metric("Total Extracted Strings", st.session_state.m3_results["stats"]["total_strings"])
            if st.session_state.m3_results["concatenations"]: st.dataframe(pd.DataFrame([{"Original": c["raw_expression"], "Folded": c["result"]} for c in st.session_state.m3_results["concatenations"]]), use_container_width=True)
        else: st.info("Awaiting pipeline...")
    with tabs[3]:
        if st.session_state.m4_results is not None:
            if not st.session_state.m4_results: st.success("No encodings detected.")
            else: st.dataframe(pd.DataFrame(st.session_state.m4_results).drop(columns=["Full Decoded"]), use_container_width=True)
        else: st.info("Awaiting pipeline...")
    with tabs[4]:
        if st.session_state.m5_results:
            st.write(f"**Severity Level:** {st.session_state.m5_results['severity_level']}")
            st.json(st.session_state.m5_results['detected_signatures'])
        else: st.info("Awaiting pipeline...")
    with tabs[5]:
        st.write("Target Comparison requires external file. (M5 feature preserved).")

    # ---------------------------
    # TAB 7 (M6): Control Flow Graph & Flattening Engine
    # ---------------------------
    with tabs[6]:
        st.subheader("🔀 Advanced Control Flow Analysis")
        if not st.session_state.m6_results:
            st.info("Execute the pipeline in Tab 1 to generate CFG Analytics.")
        else:
            m6 = st.session_state.m6_results
            if m6.get("status") == "error":
                st.error(m6["message"])
            else:
                stats = m6["stats"]
                cff = m6["cff"]
                
                # CFG Structural Metrics
                sc1, sc2, sc3, sc4 = st.columns(4)
                sc1.metric("Basic Blocks", stats["basic_blocks"])
                sc2.metric("Conditional Branches", stats["conditional_branches"])
                sc3.metric("Loops Detected", stats["loops"])
                sc4.metric("Dead Branches Removed", stats["unreachable_removed"])
                
                st.markdown("---")
                col_cff, col_diff = st.columns(2)
                
                # Control Flow Flattening (CFF) Detective
                with col_cff:
                    st.markdown("#### 🔄 Control Flow Flattening (CFF) Detection")
                    if not cff["detected"]:
                        st.success("✅ No Switch-based Control Flow Flattening detected.")
                    else:
                        st.error(f"🚨 CFF Detected! State Machine actively dispatching via `{', '.join(cff['state_variables'])}`")
                        if cff["transitions"]:
                            st.write("Identified State Transitions:")
                            st.dataframe(pd.DataFrame(cff["transitions"]), use_container_width=True)

                # Simplification Diff
                with col_diff:
                    st.markdown("#### ✂️ Conservative Simplification")
                    if stats["simplifications"] == 0:
                        st.info("No statically determinable dead branches found.")
                    else:
                        st.success(f"{stats['simplifications']} static expression(s) simplified safely.")
                        
                # Visual CFG Graph
                st.markdown("---")
                st.markdown("#### 🗺️ Control Flow Structural Graph")
                st.markdown("Hierarchical view of detected branches, loops, and switches.")
                st.graphviz_chart(m6["dot_graph"])
                
                st.download_button("📄 Download M6 CFG Report (JSON)", json.dumps(m6, indent=4), "cfg_analysis.json", "application/json")

if __name__ == "__main__":
    main()
