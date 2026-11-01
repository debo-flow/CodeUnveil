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
    for key in ['uploader_key', 'input_code', 'processed_code', 'm1_results', 'm2_results', 'm3_results', 'm4_results']:
        if key not in st.session_state:
            st.session_state[key] = 0 if key == 'uploader_key' else "" if "code" in key else None

def reset_app():
    for key in ['input_code', 'processed_code', 'm1_results', 'm2_results', 'm3_results', 'm4_results']:
        st.session_state[key] = "" if "code" in key else None
    st.session_state.uploader_key += 1

def main():
    st.set_page_config(page_title="CodeUnveil | Advanced JS Laboratory", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
    initialize_state()

    st.markdown("""<style>.stTextArea textarea { font-family: 'Courier New', monospace; background-color: #1e1e1e !important; color: #d4d4d4 !important; }</style>""", unsafe_allow_html=True)
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

    tab1, tab2, tab3, tab4 = st.tabs(["🚀 M1: Deobfuscator", "🌳 M2: AST Explorer", "🧶 M3: String Analytics", "🧮 M4: Encoding Analysis"])

    # ---------------------------
    # TAB 1: Main Processor
    # ---------------------------
    with tab1:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Input Original JavaScript")
            user_input = st.text_area("Paste obfuscated code here:", value=st.session_state.input_code, height=350)
            
            if st.button("🚀 Execute Full Analysis Pipeline", type="primary", use_container_width=True):
                if not user_input.strip():
                    st.error("Please provide JavaScript code.")
                else:
                    with st.spinner("Executing Multi-Layer Static Pipeline..."):
                        # M1 & M2 Run
                        st.session_state.m1_results = CodeAnalyzer().analyze(user_input)
                        st.session_state.m2_results = ASTAnalyzer().analyze(user_input)
                        
                        # M3 String Run
                        string_engine = StringAnalyzer()
                        st.session_state.m3_results = string_engine.analyze(user_input)
                        transformed_code = string_engine.transform() if st.session_state.m3_results.get("status") == "success" else user_input
                        
                        # M4 Encoding Run
                        if st.session_state.m3_results.get("status") == "success":
                            st.session_state.m4_results = EncodingAnalyzer.analyze_payloads(st.session_state.m3_results["strings"])
                            
                        # Standard Beautification
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
    # TAB 2 & 3: Preserved M2 & M3
    # ---------------------------
    with tab2:
        if st.session_state.m2_results:
            st.json(st.session_state.m2_results.get("ast_tree", {}), expanded=False)
        else: st.info("Awaiting execution pipeline...")
        
    with tab3:
        if st.session_state.m3_results:
            m3 = st.session_state.m3_results
            st.metric("Total Extracted Strings", m3["stats"]["total_strings"])
            if m3["concatenations"]:
                st.dataframe(pd.DataFrame([{"Original": c["raw_expression"], "Folded": c["result"]} for c in m3["concatenations"]]), use_container_width=True)
            if m3["arrays"]:
                st.dataframe(pd.DataFrame([{"Size": a["size"], "Preview": str(a["preview"])} for a in m3["arrays"]]), use_container_width=True)
        else: st.info("Awaiting execution pipeline...")

    # ---------------------------
    # TAB 4: M4 Encoding Analytics (NEW)
    # ---------------------------
    with tab4:
        st.subheader("🧮 Multi-Layer Encoding Analytics Engine")
        st.markdown("Automated detection and resolution of obfuscated Base64, Hexadecimal, URL, Binary, and Unicode payloads hidden inside strings.")
        
        if st.session_state.m4_results is not None:
            results = st.session_state.m4_results
            if not results:
                st.success("✅ No deeply encoded payloads were detected in the AST strings.")
            else:
                st.warning(f"🚨 {len(results)} Encoded payload(s) automatically detected and resolved.")
                df_enc = pd.DataFrame(results).drop(columns=["Full Decoded"])
                st.dataframe(df_enc, use_container_width=True)
                
                st.download_button("📄 Download M4 Encoding Report (JSON)", json.dumps(results, indent=4), "encoding_analysis.json", "application/json")
        else:
            st.info("Run the Main Pipeline to automatically detect payloads in the source code.")

        st.markdown("---")
        st.subheader("🔬 Interactive Decoder Sandbox")
        sandbox_input = st.text_area("Paste a suspected encoded string to analyze it manually:", height=100)
        
        if st.button("Decode String"):
            if sandbox_input.strip():
                sandbox_res = EncodingAnalyzer.multi_layer_decode(sandbox_input.strip())
                if sandbox_res["success"]:
                    st.success(f"Successfully decoded {sandbox_res['depth']} layer(s): **{' ➔ '.join(sandbox_res['layers'])}**")
                    
                    sc1, sc2 = st.columns(2)
                    sc1.metric("Original Size (Bytes)", len(sandbox_res["original"]))
                    sc2.metric("Decoded Size (Bytes)", len(sandbox_res["final_decoded"]))
                    
                    st.text_area("Decoded Output:", value=sandbox_res["final_decoded"], height=200)
                else:
                    st.error("No valid encodings detected, or string is already plaintext.")

if __name__ == "__main__":
    main()
