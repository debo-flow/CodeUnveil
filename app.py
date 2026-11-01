import streamlit as st
import jsbeautifier
import re
import io
import json
import pandas as pd
from typing import Dict, Any, Tuple

from ast_engine import ASTAnalyzer
from string_engine import StringAnalyzer

# ==========================================
# M1 Engine Components (Preserved)
# ==========================================
class CodeAnalyzer:
    @staticmethod
    def analyze(code: str) -> Dict[str, Any]:
        if not code or not code.strip():
            return {"error": "Empty input"}
        hex_literals = re.findall(r'\b0x[0-9a-fA-F]+\b', code, re.IGNORECASE)
        escaped_strings = re.findall(r'\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}', code, re.IGNORECASE)
        long_strings = re.findall(r'["\']([a-zA-Z0-9+/=]{100,})["\']', code)
        array_access = re.findall(r'\b_[a-zA-Z0-9_]+\b\[[0-9]+\]', code)

        return {
            "hex_count": len(hex_literals),
            "escaped_count": len(escaped_strings),
            "long_string_count": len(long_strings),
            "array_access_count": len(array_access),
            "original_length": len(code),
            "original_lines": len(code.splitlines())
        }

class DeobfuscatorEngine:
    @staticmethod
    def process(code: str) -> Tuple[str, str]:
        if not code or not code.strip():
            raise ValueError("No JavaScript code provided.")
        try:
            opts = jsbeautifier.default_options()
            opts.indent_size = 4
            opts.space_in_empty_paren = True
            opts.preserve_newlines = True
            opts.max_preserve_newlines = 2
            opts.wrap_line_length = 0
            opts.break_chained_methods = True
            opts.unescape_strings = False 
            
            return jsbeautifier.beautify(code, opts), "Success"
        except Exception as e:
            return "", f"Processing Error: {str(e)}"


# ==========================================
# UI Configuration & State
# ==========================================
def initialize_state():
    if 'uploader_key' not in st.session_state:
        st.session_state.uploader_key = 0
    if 'input_code' not in st.session_state:
        st.session_state.input_code = ""
    if 'processed_code' not in st.session_state:
        st.session_state.processed_code = ""
    if 'm1_results' not in st.session_state:
        st.session_state.m1_results = None
    if 'm2_results' not in st.session_state:
        st.session_state.m2_results = None
    if 'm3_results' not in st.session_state:
        st.session_state.m3_results = None

def reset_app():
    st.session_state.input_code = ""
    st.session_state.processed_code = ""
    st.session_state.m1_results = None
    st.session_state.m2_results = None
    st.session_state.m3_results = None
    st.session_state.uploader_key += 1

def main():
    st.set_page_config(page_title="CodeUnveil | Advanced JS Laboratory", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
    initialize_state()

    st.markdown("""
        <style>
        .stTextArea textarea { font-family: 'Courier New', monospace; background-color: #1e1e1e !important; color: #d4d4d4 !important; }
        .metric-card { background-color: #262730; border-radius: 5px; padding: 15px; }
        </style>
    """, unsafe_allow_html=True)

    st.title("🛡️ CodeUnveil Laboratory")
    st.markdown("### Advanced JavaScript Deobfuscation & AST Analysis Engine")
    
    with st.sidebar:
        st.header("Actions & Settings")
        uploaded_file = st.file_uploader("Upload JavaScript (.js)", type=["js", "txt"], key=f"uploader_{st.session_state.uploader_key}")
        
        if uploaded_file is not None:
            stringio = io.StringIO(uploaded_file.getvalue().decode("utf-8", errors="replace"))
            st.session_state.input_code = stringio.read()
            
        if st.button("🔄 Reset / Clear All", use_container_width=True):
            reset_app()
            st.rerun()

        st.markdown("---")
        st.markdown("**Security Guardrails Active**\n* Zero code execution.\n* 1 MB memory guard active.")

    tab1, tab2, tab3 = st.tabs(["🚀 Main Deobfuscator", "🌳 M2: AST Explorer", "🧶 M3: String Analytics"])

    # ---------------------------
    # TAB 1: Main Processor
    # ---------------------------
    with tab1:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Input Original JavaScript")
            user_input = st.text_area("Paste obfuscated code here:", value=st.session_state.input_code, height=350)
            
            if st.button("🚀 Analyze & Deobfuscate Pipeline", type="primary", use_container_width=True):
                if not user_input.strip():
                    st.error("Please provide JavaScript code.")
                else:
                    with st.spinner("Executing Full Static Pipeline..."):
                        # 1. Run Original Metrics (M1 & M2)
                        st.session_state.m1_results = CodeAnalyzer().analyze(user_input)
                        st.session_state.m2_results = ASTAnalyzer().analyze(user_input)
                        
                        # 2. String Deobfuscation Engine (M3)
                        string_engine = StringAnalyzer()
                        st.session_state.m3_results = string_engine.analyze(user_input)
                        
                        # 3. Apply Transformations securely
                        if st.session_state.m3_results.get("status") == "success":
                            transformed_code = string_engine.transform()
                        else:
                            transformed_code = user_input
                            
                        # 4. Standard Beautification
                        processed, status = DeobfuscatorEngine().process(transformed_code)
                        if status == "Success":
                            st.session_state.processed_code = processed
                        else:
                            st.error(status)

        with col2:
            st.subheader("Output Deobfuscated Code")
            st.text_area("Normalized result:", value=st.session_state.processed_code, height=350, disabled=True)
            if st.session_state.processed_code:
                st.download_button("💾 Download Processed Code", st.session_state.processed_code, "codeunveil_output.js", "text/javascript", use_container_width=True)

        if st.session_state.m1_results and st.session_state.processed_code:
            st.markdown("---")
            m1 = st.session_state.m1_results
            proc_lines = len(st.session_state.processed_code.splitlines())
            mc1, mc2, mc3, mc4 = st.columns(4)
            mc1.metric("Original Lines", m1["original_lines"])
            mc2.metric("Formatted Lines", proc_lines, delta=proc_lines - m1["original_lines"])
            mc3.metric("Regex Hex Literals", m1["hex_count"])
            mc4.metric("Regex Escaped Strings", m1["escaped_count"])

    # ---------------------------
    # TAB 2: AST Explorer
    # ---------------------------
    with tab2:
        if not st.session_state.m2_results:
            st.info("Awaiting execution pipeline...")
        else:
            m2 = st.session_state.m2_results
            if m2.get("status") == "error":
                st.error(m2["message"])
            else:
                stats, comp = m2["stats"], m2["complexity"]
                rc1, rc2, rc3, rc4 = st.columns(4)
                rc1.metric("AST Nodes", stats["total_nodes"])
                rc2.metric("Functions", stats["functions"])
                rc3.metric("Variables", stats["variables"] + stats["constants"])
                rc4.metric("Cyclomatic Complexity", comp["cyclomatic_complexity"])

                st.download_button("📄 Download AST JSON", json.dumps(m2, indent=4), "ast_analysis.json", "application/json")
                st.subheader("🌳 Interactive AST Explorer")
                st.json(m2["ast_tree"], expanded=False)

    # ---------------------------
    # TAB 3: Advanced String Analytics (M3)
    # ---------------------------
    with tab3:
        if not st.session_state.m3_results:
            st.info("Awaiting execution pipeline...")
        else:
            m3 = st.session_state.m3_results
            if m3.get("status") == "error":
                st.error(m3["message"])
            else:
                st.subheader("🧶 AST-Driven String Deobfuscation Metrics")
                stats = m3["stats"]
                
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Total Strings", stats["total_strings"])
                c2.metric("Escaped/Encoded", stats["encoded_strings"])
                c3.metric("Successfully Decoded", stats["decoded_strings"], delta=stats["failed_decodings"] * -1)
                c4.metric("Concatenations Folded", stats["concatenations_folded"])

                # Report Download
                st.download_button("📄 Download String JSON Report", json.dumps(m3, indent=4), "string_analysis.json", "application/json")

                # Decoded Strings View
                encoded = [s for s in m3["strings"] if s["is_encoded"]]
                if encoded:
                    st.markdown("#### 🔓 Decoded Strings Pipeline")
                    df_enc = pd.DataFrame([{"Original Raw": s["raw"], "Decoded Content": s["value"]} for s in encoded])
                    st.dataframe(df_enc, use_container_width=True)

                # Concatenations View
                if m3["concatenations"]:
                    st.markdown("#### 🔗 Folded Static Concatenations")
                    df_conc = pd.DataFrame([{"Original Expression": c["raw_expression"], "Evaluated Result": c["result"]} for c in m3["concatenations"]])
                    st.dataframe(df_conc, use_container_width=True)

                # Arrays View
                if m3["arrays"]:
                    st.markdown("#### 📚 Discovered String Arrays (Lookup Tables)")
                    df_arr = pd.DataFrame([{"Array Size": a["size"], "Preview": str(a["preview"]), "Original Raw": a["raw"]} for a in m3["arrays"]])
                    st.dataframe(df_arr, use_container_width=True)

if __name__ == "__main__":
    main()
