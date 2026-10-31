import streamlit as st
import jsbeautifier
import re
import io
from typing import Dict, Any, Tuple

# ==========================================
# Core Engine Components
# ==========================================

class CodeAnalyzer:
    """Handles static analysis of JavaScript code to detect potential obfuscation."""

    @staticmethod
    def analyze(code: str) -> Dict[str, Any]:
        """Analyzes code for common obfuscation patterns without executing it."""
        if not code or not code.strip():
            return {"error": "Empty input"}

        # Detect Hexadecimal literals (e.g., 0x4a, 0XFF)
        hex_literals = re.findall(r'\b0x[0-9a-fA-F]+\b', code, re.IGNORECASE)

        # Detect Escaped string sequences (e.g., \x20, \u0020)
        escaped_strings = re.findall(r'\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}', code, re.IGNORECASE)

        # Detect suspiciously long encoded-looking strings (likely Base64 or encrypted payloads)
        long_strings = re.findall(r'["\']([a-zA-Z0-9+/=]{100,})["\']', code)
        
        # Detect dense array access (common in packed/obfuscated code e.g., _0x1234[0])
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
    """Handles code formatting and basic deobfuscation transformations statically."""

    @staticmethod
    def process(code: str) -> Tuple[str, str]:
        """Formats and normalizes JavaScript code safely."""
        if not code or not code.strip():
            raise ValueError("No JavaScript code provided.")
            
        try:
            # Configure JSBeautifier options for optimal readability
            opts = jsbeautifier.default_options()
            opts.indent_size = 4
            opts.space_in_empty_paren = True
            opts.preserve_newlines = True
            opts.max_preserve_newlines = 2
            opts.wrap_line_length = 0 # Disable arbitrary wrapping to prevent breaking strings
            opts.break_chained_methods = True
            opts.unescape_strings = False # Prevent execution context vulnerabilities
            
            formatted_code = jsbeautifier.beautify(code, opts)
            
            return formatted_code, "Success"
        except Exception as e:
            return "", f"Processing Error: {str(e)}"


# ==========================================
# User Interface (Streamlit)
# ==========================================

def initialize_state():
    """Initializes Streamlit session state variables."""
    if 'uploader_key' not in st.session_state:
        st.session_state.uploader_key = 0
    if 'input_code' not in st.session_state:
        st.session_state.input_code = ""
    if 'processed_code' not in st.session_state:
        st.session_state.processed_code = ""
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = None

def reset_app():
    """Resets the application state to clear all inputs and outputs."""
    st.session_state.input_code = ""
    st.session_state.processed_code = ""
    st.session_state.analysis_results = None
    st.session_state.uploader_key += 1 # Forces the file uploader to reset

def main():
    st.set_page_config(
        page_title="Universal Deobfuscator | Milestone 1",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    initialize_state()

    # Apply custom CSS for professional dark-themed enhancements
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

    # Header section
    st.title("🛡️ Universal Deobfuscator")
    st.markdown("### Milestone 1: Static Analysis & Code Normalization Engine")
    st.markdown("Safely analyze and format heavily obfuscated JavaScript files without executing untrusted code.")

    # Sidebar Tools
    with st.sidebar:
        st.header("Actions & Settings")
        uploaded_file = st.file_uploader(
            "Upload JavaScript (.js)", 
            type=["js", "txt"], 
            key=f"uploader_{st.session_state.uploader_key}"
        )
        
        if uploaded_file is not None:
            # Read safely as text
            stringio = io.StringIO(uploaded_file.getvalue().decode("utf-8", errors="replace"))
            st.session_state.input_code = stringio.read()
            
        if st.button("🔄 Reset / Clear All", use_container_width=True):
            reset_app()
            st.rerun()

        st.markdown("---")
        st.markdown("**Security Notice:** All parsing is static. Code is never executed in this environment.")

    # Main Workspace Layout
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Input Original JavaScript")
        user_input = st.text_area(
            "Paste your obfuscated code here:", 
            value=st.session_state.input_code, 
            height=400,
            key="input_text_area"
        )
        
        if st.button("🚀 Analyze & Deobfuscate", type="primary", use_container_width=True):
            if not user_input.strip():
                st.error("Please provide JavaScript code to process.")
            else:
                with st.spinner("Analyzing and normalizing code..."):
                    # 1. Run Analysis
                    analyzer = CodeAnalyzer()
                    st.session_state.analysis_results = analyzer.analyze(user_input)
                    
                    # 2. Run Deobfuscator
                    engine = DeobfuscatorEngine()
                    processed, status = engine.process(user_input)
                    
                    if status == "Success":
                        st.session_state.processed_code = processed
                    else:
                        st.error(status)
                        st.session_state.processed_code = ""

    with col2:
        st.subheader("Output Processed JavaScript")
        st.text_area(
            "Normalized result:", 
            value=st.session_state.processed_code, 
            height=400, 
            disabled=True
        )
        
        if st.session_state.processed_code:
            st.download_button(
                label="💾 Download Processed Code",
                data=st.session_state.processed_code,
                file_name="deobfuscated_output.js",
                mime="text/javascript",
                use_container_width=True
            )

    # Analysis Dashboard (Shown only after processing)
    if st.session_state.analysis_results and st.session_state.processed_code:
        st.markdown("---")
        st.subheader("📊 Static Code Analysis Report")
        
        metrics = st.session_state.analysis_results
        proc_lines = len(st.session_state.processed_code.splitlines())
        
        mc1, mc2, mc3, mc4 = st.columns(4)
        mc1.metric("Original Lines", metrics["original_lines"])
        mc2.metric("Formatted Lines", proc_lines, delta=proc_lines - metrics["original_lines"])
        mc3.metric("Hex Literals Detected", metrics["hex_count"])
        mc4.metric("Escaped Strings Detected", metrics["escaped_count"])

        st.markdown("#### Obfuscation Indicators")
        if metrics["hex_count"] > 10 or metrics["escaped_count"] > 10:
            st.warning("⚠️ High volume of encoded strings or hexadecimal literal values detected. This is typical in standard packers (e.g., Obfuscator.io).")
        if metrics["long_string_count"] > 0:
            st.error(f"🚨 {metrics['long_string_count']} abnormally long string(s) detected. May indicate embedded payloads (Base64/RC4 encryptions).")
        if metrics["array_access_count"] > 20:
            st.warning("⚠️ High volume of bracket notation array access detected. Common in string-array shuffling obfuscation.")
        
        if metrics["hex_count"] <= 10 and metrics["escaped_count"] <= 10 and metrics["long_string_count"] == 0 and metrics["array_access_count"] <= 20:
            st.success("✅ Minimal baseline obfuscation indicators detected. The code may just be minified.")

if __name__ == "__main__":
    main()
