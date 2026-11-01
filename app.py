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
    for key in ['uploader_key', 'input_code', 'processed_code', 'm1_results', 'm2_results', 'm3_results', 'm4_results', 'm5_results']:
        if key not in st.session_state:
            st.session_state[key] = 0 if key == 'uploader_key' else "" if "code" in key else None

def reset_app():
    for key in ['input_code', 'processed_code', 'm1_results', 'm2_results', 'm3_results', 'm4_results', 'm5_results']:
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
        uploaded_file = st.file_uploader("Upload Target JS (.js)", type=["js", "txt"], key=f"uploader_{st.session_state.uploader_key}")
        if uploaded_file is not None:
            stringio = io.StringIO(uploaded_file.getvalue().decode("utf-8", errors="replace"))
            st.session_state.input_code = stringio.read()
            
        if st.button("🔄 Reset / Clear All", use_container_width=True):
            reset_app()
            st.rerun()

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🚀 M1: Deobfuscator", "🌳 M2: AST Explorer", "🧶 M3: Strings", 
        "🧮 M4: Encodings", "🚨 M5: Obfuscation Engine", "⚖️ M5: Comparison"
    ])

    # ---------------------------
    # MAIN PIPELINE EXECUTION
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
                        st.session_state.m1_results = CodeAnalyzer().analyze(user_input)
                        st.session_state.m2_results = ASTAnalyzer().analyze(user_input)
                        
                        string_engine = StringAnalyzer()
                        st.session_state.m3_results = string_engine.analyze(user_input)
                        transformed_code = string_engine.transform() if st.session_state.m3_results.get("status") == "success" else user_input
                        
                        if st.session_state.m3_results.get("status") == "success":
                            st.session_state.m4_results = EncodingAnalyzer.analyze_payloads(st.session_state.m3_results["strings"])
                        
                        # M5 Obfuscation Engine execution
                        det_engine = DetectionEngine()
                        st.session_state.m5_results = det_engine.analyze(user_input, st.session_state.m2_results)
                            
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
    # TABS 2-4: Preserved
    # ---------------------------
    with tab2:
        if st.session_state.m2_results: st.json(st.session_state.m2_results.get("ast_tree", {}), expanded=False)
        else: st.info("Awaiting execution pipeline...")
        
    with tab3:
        if st.session_state.m3_results:
            m3 = st.session_state.m3_results
            st.metric("Total Extracted Strings", m3["stats"]["total_strings"])
            if m3["concatenations"]: st.dataframe(pd.DataFrame([{"Original": c["raw_expression"], "Folded": c["result"]} for c in m3["concatenations"]]), use_container_width=True)
        else: st.info("Awaiting execution pipeline...")

    with tab4:
        if st.session_state.m4_results is not None:
            if not st.session_state.m4_results: st.success("✅ No deeply encoded payloads detected.")
            else: st.dataframe(pd.DataFrame(st.session_state.m4_results).drop(columns=["Full Decoded"]), use_container_width=True)
        else: st.info("Awaiting execution pipeline...")

    # ---------------------------
    # TAB 5: M5 Obfuscation Engine
    # ---------------------------
    with tab5:
        st.subheader("🚨 Obfuscator Classification & Fingerprinting Engine")
        if not st.session_state.m5_results:
            st.info("Execute the pipeline in Tab 1 to run the Detection Engine.")
        else:
            m5 = st.session_state.m5_results
            
            # Severity Card
            sev_color = ["green", "blue", "yellow", "orange", "red", "darkred"][m5['severity_level']]
            st.markdown(f"### Obfuscation Severity: <span style='color:{sev_color}'>Level {m5['severity_level']} - {m5['severity_name']}</span>", unsafe_allow_html=True)
            st.write(m5['explanation'])
            
            # Fingerprint Card
            st.markdown("---")
            st.markdown("#### 🕵️ Tool Fingerprint Analysis")
            f = m5['fingerprint']
            fc1, fc2 = st.columns(2)
            fc1.metric("Predicted Tool Family", f['tool'])
            fc2.metric("Confidence Score", f['confidence'])
            st.info(f"**Evidence:** {f['evidence']}\n\n**Alternatives:** {f['alternatives']}")
            
            # Detected Techniques
            st.markdown("---")
            st.markdown("#### 🧬 Detected Obfuscation Techniques")
            if not m5['detected_signatures']:
                st.success("No recognized obfuscation signatures detected.")
            else:
                for sig in m5['detected_signatures']:
                    with st.expander(f"⚠️ {sig['name']} (Severity: {sig['severity']} | Confidence: {sig['confidence']})"):
                        st.write(f"**Category:** {sig['category']}")
                        st.write(f"**Description:** {sig['description']}")
                        st.write(f"**Evidence:** {sig['evidence']}")
                        st.write(f"**Recommended Action:** {sig['next_step']}")
                        
            st.download_button("📄 Download M5 Detection Report (JSON)", json.dumps(m5, indent=4), "obfuscation_report.json", "application/json")

    # ---------------------------
    # TAB 6: M5 Comparison Engine
    # ---------------------------
    with tab6:
        st.subheader("⚖️ Code Comparison Engine")
        st.write("Compare the current loaded code (Target 1) against another file to evaluate structural shifts.")
        
        comp_file = st.file_uploader("Upload Target 2 JS (.js)", type=["js", "txt"], key="comp_uploader")
        if comp_file and st.session_state.m5_results:
            comp_code = comp_file.getvalue().decode("utf-8", errors="replace")
            
            # Quick analyze Target 2
            ast2 = ASTAnalyzer().analyze(comp_code)
            det2 = DetectionEngine().analyze(comp_code, ast2)
            
            st.markdown("---")
            cc1, cc2 = st.columns(2)
            
            # Current (Target 1)
            with cc1:
                st.markdown("### Target 1 (Main Buffer)")
                m5 = st.session_state.m5_results
                st.metric("Severity Level", f"{m5['severity_level']} - {m5['severity_name']}")
                st.metric("Detected Signatures", len(m5['detected_signatures']))
                if st.session_state.m2_results and "stats" in st.session_state.m2_results:
                    st.metric("Total AST Nodes", st.session_state.m2_results["stats"]["total_nodes"])
                    st.metric("Cyclomatic Complexity", st.session_state.m2_results["complexity"]["cyclomatic_complexity"])

            # Comparison (Target 2)
            with cc2:
                st.markdown("### Target 2 (Uploaded File)")
                st.metric("Severity Level", f"{det2['severity_level']} - {det2['severity_name']}")
                st.metric("Detected Signatures", len(det2['detected_signatures']))
                if ast2 and "stats" in ast2:
                    st.metric("Total AST Nodes", ast2["stats"]["total_nodes"])
                    st.metric("Cyclomatic Complexity", ast2["complexity"]["cyclomatic_complexity"])
                    
        elif not st.session_state.m5_results:
            st.info("Please load Target 1 and run the pipeline first.")

if __name__ == "__main__":
    main()
