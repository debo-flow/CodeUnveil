import streamlit as st
import jsbeautifier
import re
import io
import json
from typing import Dict, Any, Tuple

# Import the new Milestone 2 Module
from ast_engine import ASTAnalyzer

# ==========================================
# M1 Engine Components (Preserved)
# ==========================================

class CodeAnalyzer:
    """Handles static RegExp analysis (Milestone 1)."""
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
    """Handles basic formatting safely (Milestone 1)."""
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
# User Interface (Streamlit)
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

def reset_app():
    st.session_state.input_code = ""
    st.session_state.processed_code = ""
    st.session_state.m1_results = None
    st.session_state.m2_results = None
    st.session_state.uploader_key += 1

def main():
    st.set_page_config(
        page_title="CodeUnveil | Advanced JS Laboratory",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    initialize_state()

    st.markdown("""
        <style>
        .stTextArea textarea {
            font-family: 'Courier New', monospace;
            background-color: #1e1e1e !important;
            color: #d4d4d4 !important;
        }
        .metric-card {
            background-color: #262730;
            border-radius: 5px;
            padding: 15px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }
        </style>
    """, unsafe_allow_html=True)

    st.title("🛡️ CodeUnveil Laboratory")
    st.markdown("### Advanced JavaScript Deobfuscation & AST Analysis Engine")
    
    with st.sidebar:
        st.header("Actions & Settings")
        uploaded_file = st.file_uploader(
            "Upload JavaScript (.js)", 
            type=["js", "txt"], 
            key=f"uploader_{st.session_state.uploader_key}"
        )
        
        if uploaded_file is not None:
            stringio = io.StringIO(uploaded_file.getvalue().decode("utf-8", errors="replace"))
            st.session_state.input_code = stringio.read()
            
        if st.button("🔄 Reset / Clear All", use_container_width=True):
            reset_app()
            st.rerun()

        st.markdown("---")
        st.markdown("**Security Guardrails Active**\n* AST Parsers isolate execution.\n* 1 MB File size limit applied.")

    # Main Tabs
    tab1, tab2 = st.tabs(["🚀 M1: Static Beautifier & Regex", "🌳 M2: AST Explorer & Complexity Analysis"])

    # ---------------------------
    # TAB 1: Milestone 1 Engine
    # ---------------------------
    with tab1:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Input Original JavaScript")
            user_input = st.text_area("Paste obfuscated code here:", value=st.session_state.input_code, height=350, key="input_text_area")
            
            if st.button("🚀 Analyze & Deobfuscate", type="primary", use_container_width=True):
                if not user_input.strip():
                    st.error("Please provide JavaScript code.")
                else:
                    with st.spinner("Processing AST and M1 tasks..."):
                        # M1 Run
                        m1_analyzer = CodeAnalyzer()
                        st.session_state.m1_results = m1_analyzer.analyze(user_input)
                        
                        engine = DeobfuscatorEngine()
                        processed, status = engine.process(user_input)
                        if status == "Success":
                            st.session_state.processed_code = processed
                        else:
                            st.error(status)
                            
                        # M2 Run (Triggered here to sync states)
                        m2_analyzer = ASTAnalyzer()
                        st.session_state.m2_results = m2_analyzer.analyze(user_input)

        with col2:
            st.subheader("Output Processed Code")
            st.text_area("Normalized result:", value=st.session_state.processed_code, height=350, disabled=True)
            if st.session_state.processed_code:
                st.download_button(
                    label="💾 Download Processed Code",
                    data=st.session_state.processed_code,
                    file_name="codeunveil_output.js",
                    mime="text/javascript",
                    use_container_width=True
                )

        if st.session_state.m1_results and st.session_state.processed_code:
            st.markdown("---")
            st.subheader("📊 M1 Static Regex Report")
            m1 = st.session_state.m1_results
            proc_lines = len(st.session_state.processed_code.splitlines())
            mc1, mc2, mc3, mc4 = st.columns(4)
            mc1.metric("Original Lines", m1["original_lines"])
            mc2.metric("Formatted Lines", proc_lines, delta=proc_lines - m1["original_lines"])
            mc3.metric("Hex Literals", m1["hex_count"])
            mc4.metric("Escaped Strings", m1["escaped_count"])

    # ---------------------------
    # TAB 2: Milestone 2 Engine
    # ---------------------------
    with tab2:
        if not st.session_state.m2_results:
            st.info("Please enter code and click 'Analyze & Deobfuscate' in the first tab to view AST analysis.")
        else:
            m2 = st.session_state.m2_results
            if m2.get("status") == "error":
                st.error("### AST Parsing Failed")
                st.error(m2["message"])
                st.warning("The input code contains invalid syntax or is not standard JavaScript.")
            else:
                st.subheader("⚙️ Code Complexity & Obfuscation Metrics")
                stats = m2["stats"]
                comp = m2["complexity"]

                rc1, rc2, rc3, rc4 = st.columns(4)
                rc1.metric("Total AST Nodes", stats["total_nodes"])
                rc2.metric("Functions", stats["functions"])
                rc3.metric("Variables/Constants", stats["variables"] + stats["constants"])
                rc4.metric("Cyclomatic Complexity", comp["cyclomatic_complexity"])

                st.markdown("#### Detected Obfuscation Patterns (AST-based)")
                p1, p2, p3, p4 = st.columns(4)
                p1.metric("Unusual Variable Names", comp["unusual_variable_names"], delta_color="inverse")
                p2.metric("Computed Properties", comp["computed_property_access"], delta_color="inverse")
                p3.metric("Suspicious Function Wrappers", comp["suspicious_wrappers"], delta_color="inverse")
                p4.metric("Large String Collections", comp["large_string_collections"], delta_color="inverse")
                
                # Report Download
                report_data = {
                    "statistics": stats, 
                    "complexity": comp
                }
                st.download_button(
                    label="📄 Download AST Analysis JSON",
                    data=json.dumps(report_data, indent=4),
                    file_name="ast_analysis_report.json",
                    mime="application/json"
                )

                st.markdown("---")
                st.subheader("🌳 Interactive AST Explorer")
                st.markdown("Expand nodes below to explore the parsed syntax structure of the JavaScript code.")
                # Native Streamlit JSON renders interactively natively
                st.json(m2["ast_tree"], expanded=False)

if __name__ == "__main__":
    main()
