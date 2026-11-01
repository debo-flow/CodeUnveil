import streamlit as st
import jsbeautifier
import re
import io
import json
import pandas as pd
from typing import Dict, Any, Tuple

# ==========================================
# External Engine Imports (M2 - M9)
# ==========================================
from ast_engine import ASTAnalyzer
from string_engine import StringAnalyzer
from encoding_engine import EncodingAnalyzer
from detection_engine import DetectionEngine
from cfg_engine import CFGAnalyzer
from dce_engine import DCEAnalyzer
from rename_engine import RenameAnalyzer
from array_engine import ArrayAnalyzer

# ==========================================
# M1 Engine Components (Regex & Formatting)
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
# UI Configuration & State Management
# ==========================================
def initialize_state():
    # Base IO & Interactive Engine States
    for key in ['uploader_key', 'input_code', 'processed_code', 'm6_original', 'm8_code_base', 'm9_code_base']:
        if key not in st.session_state: 
            st.session_state[key] = 0 if key == 'uploader_key' else ""
            
    # Engine Results
    engine_keys = [
        'm1_results', 'm2_results', 'm3_results', 'm4_results', 
        'm5_results', 'm6_results', 'm7_results', 'm7_replacements', 
        'm8_results', 'm9_results'
    ]
    for key in engine_keys:
        if key not in st.session_state: 
            st.session_state[key] = None

def reset_app():
    for key in ['input_code', 'processed_code', 'm6_original', 'm8_code_base', 'm9_code_base']: 
        st.session_state[key] = ""
    
    engine_keys = [
        'm1_results', 'm2_results', 'm3_results', 'm4_results', 
        'm5_results', 'm6_results', 'm7_results', 'm7_replacements', 
        'm8_results', 'm9_results'
    ]
    for key in engine_keys: 
        st.session_state[key] = None
        
    st.session_state.uploader_key += 1

# ==========================================
# Main Streamlit Application
# ==========================================
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
        .stTextArea textarea { font-family: 'Courier New', monospace; background-color: #1e1e1e !important; color: #d4d4d4 !important; }
        .metric-card { background-color: #262730; border-radius: 5px; padding: 15px; }
        </style>
    """, unsafe_allow_html=True)
    
    st.title("🛡️ CodeUnveil Laboratory")
    st.markdown("### Advanced JavaScript Deobfuscation & Static Analysis Engine")
    
    # Sidebar
    with st.sidebar:
        st.header("Actions & Settings")
        uploaded_file = st.file_uploader("Upload Target JS (.js)", type=["js", "txt"], key=f"uploader_{st.session_state.uploader_key}")
        if uploaded_file is not None:
            # Read safely as text
            st.session_state.input_code = io.StringIO(uploaded_file.getvalue().decode("utf-8", errors="replace")).read()
            
        st.markdown("---")
        st.markdown("#### Engine Settings")
        apply_dce = st.checkbox("🗑️ Enable Destructive Dead Code Elimination (M7)", value=False, help="If checked, safely unused variables and unreachable blocks will be physically purged from the output code.")
        
        st.markdown("---")
        if st.button("🔄 Reset / Clear All", use_container_width=True):
            reset_app()
            st.rerun()
            
        st.markdown("---")
        st.markdown("**Security Guardrails**\n* Static execution only.\n* Memory & AST depth limits active.")

    # UI Tabs
    tabs = st.tabs([
        "🚀 Main", "🌳 M2: AST", "🧶 M3: Strings", 
        "🧮 M4: Encodings", "🚨 M5: Obfuscator", "⚖️ M5: Compare", 
        "🔀 M6: CFG", "🪦 M7: Dead Code", "🏷️ M8: Renaming", "📦 M9: Arrays"
    ])

    # ---------------------------
    # TAB 1: Main Pipeline Execution
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
                    with st.spinner("Executing Complete Multi-Layer Static Pipeline..."):
                        # Save base state
                        st.session_state.m6_original = user_input
                        
                        # M1 & M2: Base Metrics and AST
                        st.session_state.m1_results = CodeAnalyzer().analyze(user_input)
                        st.session_state.m2_results = ASTAnalyzer().analyze(user_input)
                        
                        # M3: Strings & Concatenations
                        string_engine = StringAnalyzer()
                        st.session_state.m3_results = string_engine.analyze(user_input)
                        transformed_code = string_engine.transform() if st.session_state.m3_results.get("status") == "success" else user_input
                        
                        # M4: Encodings
                        if st.session_state.m3_results.get("status") == "success":
                            st.session_state.m4_results = EncodingAnalyzer.analyze_payloads(st.session_state.m3_results["strings"])
                        
                        # M5: Obfuscation Signatures
                        det_engine = DetectionEngine()
                        st.session_state.m5_results = det_engine.analyze(user_input, st.session_state.m2_results)
                        
                        # M6: CFG & Simplification
                        cfg_engine = CFGAnalyzer()
                        st.session_state.m6_results = cfg_engine.analyze(transformed_code)
                        if st.session_state.m6_results.get("status") == "success":
                            transformed_code = cfg_engine.transform()

                        # M7: Dead Code Elimination
                        dce_engine = DCEAnalyzer()
                        st.session_state.m7_results = dce_engine.analyze(transformed_code)
                        st.session_state.m7_replacements = dce_engine.replacements
                        
                        # Apply destructive optimizations only if user opted-in
                        if apply_dce and st.session_state.m7_results.get("status") == "success":
                            transformed_code = dce_engine.transform()
                            
                        # M8: Identifier Analysis
                        st.session_state.m8_code_base = transformed_code
                        rename_engine = RenameAnalyzer()
                        st.session_state.m8_results = rename_engine.analyze(transformed_code)
                        
                        # M9: String Array Engine
                        st.session_state.m9_code_base = transformed_code
                        array_engine = ArrayAnalyzer()
                        st.session_state.m9_results = array_engine.analyze(transformed_code)
                            
                        # Final M1 formatting
                        processed, status = DeobfuscatorEngine().process(transformed_code)
                        if status == "Success":
                            st.session_state.processed_code = processed
                        else: 
                            st.error(status)

        with col2:
            st.subheader("Output Deobfuscated Code")
            st.text_area("Normalized result:", value=st.session_state.processed_code, height=350, disabled=True)
            if st.session_state.processed_code:
                st.download_button(
                    label="💾 Download Processed Code", 
                    data=st.session_state.processed_code, 
                    file_name="codeunveil_output.js", 
                    mime="text/javascript", 
                    use_container_width=True
                )

        # M1 Base Metric Post-Run display
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
    with tabs[1]:
        if not st.session_state.m2_results:
            st.info("Execute the pipeline in Tab 1 to view AST analysis.")
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
    # TAB 3: Advanced Strings
    # ---------------------------
    with tabs[2]:
        if not st.session_state.m3_results:
            st.info("Execute the pipeline in Tab 1 to view String analytics.")
        else:
            m3 = st.session_state.m3_results
            if m3.get("status") == "error":
                st.error(m3["message"])
            else:
                st.subheader("🧶 AST-Driven String Metrics")
                stats = m3["stats"]
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Total Strings", stats["total_strings"])
                c2.metric("Escaped/Encoded", stats["encoded_strings"])
                c3.metric("Successfully Decoded", stats["decoded_strings"], delta=stats["failed_decodings"] * -1)
                c4.metric("Concatenations Folded", stats["concatenations_folded"])

                if m3["strings"]:
                    encoded = [s for s in m3["strings"] if s["is_encoded"]]
                    if encoded:
                        st.markdown("#### 🔓 Decoded Strings Pipeline")
                        st.dataframe(pd.DataFrame([{"Raw": s["raw"], "Decoded": s["value"]} for s in encoded]), use_container_width=True)

                if m3["concatenations"]:
                    st.markdown("#### 🔗 Folded Static Concatenations")
                    st.dataframe(pd.DataFrame([{"Original": c["raw_expression"], "Folded": c["result"]} for c in m3["concatenations"]]), use_container_width=True)

    # ---------------------------
    # TAB 4: Multi-Layer Encoding
    # ---------------------------
    with tabs[3]:
        st.subheader("🧮 Multi-Layer Encoding Analytics")
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
            st.info("Execute the pipeline in Tab 1 to automatically detect payloads in the source code.")

        st.markdown("---")
        st.subheader("🔬 Interactive Decoder Sandbox")
        sandbox_input = st.text_area("Paste a suspected encoded string to analyze it manually:", height=100)
        
        if st.button("Decode Manual String"):
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

    # ---------------------------
    # TAB 5: Obfuscator Detection
    # ---------------------------
    with tabs[4]:
        st.subheader("🚨 Obfuscator Classification Engine")
        if not st.session_state.m5_results:
            st.info("Execute the pipeline in Tab 1 to run the Detection Engine.")
        else:
            m5 = st.session_state.m5_results
            
            sev_color = ["green", "blue", "yellow", "orange", "red", "darkred"][m5['severity_level']]
            st.markdown(f"### Obfuscation Severity: <span style='color:{sev_color}'>Level {m5['severity_level']} - {m5['severity_name']}</span>", unsafe_allow_html=True)
            st.write(m5['explanation'])
            
            st.markdown("---")
            st.markdown("#### 🕵️ Tool Fingerprint Analysis")
            f = m5['fingerprint']
            fc1, fc2 = st.columns(2)
            fc1.metric("Predicted Tool Family", f['tool'])
            fc2.metric("Confidence Score", f['confidence'])
            st.info(f"**Evidence:** {f['evidence']}\n\n**Alternatives:** {f['alternatives']}")
            
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

    # ---------------------------
    # TAB 6: Compare Targets
    # ---------------------------
    with tabs[5]:
        st.subheader("⚖️ Code Comparison Engine")
        st.write("Compare the current loaded code (Target 1) against another file to evaluate structural shifts.")
        
        comp_file = st.file_uploader("Upload Target 2 JS (.js)", type=["js", "txt"], key="comp_uploader")
        if comp_file and st.session_state.m5_results:
            comp_code = comp_file.getvalue().decode("utf-8", errors="replace")
            ast2 = ASTAnalyzer().analyze(comp_code)
            det2 = DetectionEngine().analyze(comp_code, ast2)
            
            st.markdown("---")
            cc1, cc2 = st.columns(2)
            with cc1:
                st.markdown("### Target 1 (Main Buffer)")
                m5 = st.session_state.m5_results
                st.metric("Severity Level", f"{m5['severity_level']} - {m5['severity_name']}")
                st.metric("Detected Signatures", len(m5['detected_signatures']))
                if st.session_state.m2_results and "stats" in st.session_state.m2_results:
                    st.metric("Total AST Nodes", st.session_state.m2_results["stats"]["total_nodes"])
                    st.metric("Cyclomatic Complexity", st.session_state.m2_results["complexity"]["cyclomatic_complexity"])

            with cc2:
                st.markdown("### Target 2 (Uploaded File)")
                st.metric("Severity Level", f"{det2['severity_level']} - {det2['severity_name']}")
                st.metric("Detected Signatures", len(det2['detected_signatures']))
                if ast2 and "stats" in ast2:
                    st.metric("Total AST Nodes", ast2["stats"]["total_nodes"])
                    st.metric("Cyclomatic Complexity", ast2["complexity"]["cyclomatic_complexity"])
                    
        elif not st.session_state.m5_results:
            st.info("Please load Target 1 and run the pipeline first.")

    # ---------------------------
    # TAB 7: Control Flow Graph (CFG)
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
                
                sc1, sc2, sc3, sc4 = st.columns(4)
                sc1.metric("Basic Blocks", stats["basic_blocks"])
                sc2.metric("Conditional Branches", stats["conditional_branches"])
                sc3.metric("Loops Detected", stats["loops"])
                sc4.metric("Dead Branches Removed", stats["unreachable_removed"])
                
                st.markdown("---")
                col_cff, col_diff = st.columns(2)
                
                with col_cff:
                    st.markdown("#### 🔄 Control Flow Flattening (CFF) Detection")
                    if not cff["detected"]:
                        st.success("✅ No Switch-based Control Flow Flattening detected.")
                    else:
                        st.error(f"🚨 CFF Detected! State Machine actively dispatching via `{', '.join(cff['state_variables'])}`")
                        if cff["transitions"]:
                            st.write("Identified State Transitions:")
                            st.dataframe(pd.DataFrame(cff["transitions"]), use_container_width=True)

                with col_diff:
                    st.markdown("#### ✂️ Conservative Simplification")
                    if stats["simplifications"] == 0:
                        st.info("No statically determinable dead branches found.")
                    else:
                        st.success(f"{stats['simplifications']} static expression(s) simplified safely.")
                        
                st.markdown("---")
                st.markdown("#### 🗺️ Control Flow Structural Graph")
                st.graphviz_chart(m6["dot_graph"])
                st.download_button("📄 Download M6 CFG Report (JSON)", json.dumps(m6, indent=4), "cfg_analysis.json", "application/json")

    # ---------------------------
    # TAB 8: Dead Code Elimination
    # ---------------------------
    with tabs[7]:
        st.subheader("🪦 Advanced Dead Code & Scope Analysis")
        if not st.session_state.m7_results:
            st.info("Execute the pipeline in Tab 1 to generate Dead Code Analytics.")
        else:
            m7 = st.session_state.m7_results
            if m7.get("status") == "error":
                st.error(m7["message"])
            else:
                stats = m7["stats"]
                
                sc1, sc2, sc3, sc4 = st.columns(4)
                sc1.metric("Unreachable Statements", stats["unreachable_statements"])
                sc2.metric("Unused Variables", stats["unused_variables"])
                sc3.metric("Unused Functions", stats["unused_functions"])
                sc4.metric("Safely Removable Blocks", stats["safely_removable"])
                
                st.markdown("---")
                col_vars, col_log = st.columns(2)
                
                with col_vars:
                    st.markdown("#### 👻 Unused Scope Identifiers")
                    if not m7["unused"]:
                        st.success("✅ Code is clean. No unused variables or functions detected.")
                    else:
                        st.dataframe(pd.DataFrame(m7["unused"]), use_container_width=True)
                        
                with col_log:
                    st.markdown("#### ✂️ Safely Identified Removals")
                    reps = st.session_state.m7_replacements
                    if not reps:
                        st.info("No code matched the safe destructive criteria.")
                    else:
                        st.warning(f"{len(reps)} code blocks successfully flagged for safe removal.")
                        df_reps = pd.DataFrame([{"Reason": r[3], "Range": f"[{r[0]}, {r[1]}]"} for r in reps])
                        st.dataframe(df_reps, use_container_width=True)
                        
                st.download_button("📄 Download M7 Dead Code Report (JSON)", json.dumps(m7, indent=4), "dead_code_report.json", "application/json")

    # ---------------------------
    # TAB 9: Identifier Renaming
    # ---------------------------
    with tabs[8]:
        st.subheader("🏷️ Intelligent Identifier Renaming & Scope Explorer")
        if not st.session_state.m8_results:
            st.info("Execute the pipeline in Tab 1 to generate Scope & Identifier Analytics.")
        else:
            m8 = st.session_state.m8_results
            if m8.get("status") == "error":
                st.error(m8["message"])
            else:
                stats = m8["stats"]
                sc1, sc2, sc3 = st.columns(3)
                sc1.metric("Total Identifiers Mapped", stats["total_identifiers"])
                sc2.metric("Suspicious/Obfuscated", stats["suspicious_identifiers"])
                sc3.metric("Functions / Variables", f"{stats['functions']} / {stats['variables']}")
                
                st.markdown("---")
                st.markdown("#### 🔬 Scope Explorer & Renaming Sandbox")
                st.write("Review auto-generated semantic names for suspicious identifiers. Check the `Apply` box to queue them for transformation.")
                
                if not m8["identifiers"]:
                    st.success("No user-defined variables or functions found in this code.")
                else:
                    df_data = []
                    for i in m8["identifiers"]:
                        df_data.append({
                            "Apply": i["is_suspicious"],
                            "Original Name": i["original_name"],
                            "Suggestion": i["suggestion"],
                            "Scope": i["scope_type"].capitalize(),
                            "Type": i["kind"].capitalize(),
                            "Usages": len(i["ref_ranges"]),
                            "Suspicious": i["is_suspicious"],
                            "_id": i["id"],
                            "_decl": i["decl_range"],
                            "_refs": i["ref_ranges"]
                        })
                    
                    df = pd.DataFrame(df_data)
                    
                    edited_df = st.data_editor(
                        df,
                        column_config={
                            "Apply": st.column_config.CheckboxColumn("Apply Change", default=False),
                            "Suggestion": st.column_config.TextColumn("Proposed Name", required=True),
                            "_id": None, "_decl": None, "_refs": None # Hide metadata
                        },
                        disabled=["Original Name", "Scope", "Type", "Usages", "Suspicious"],
                        use_container_width=True,
                        num_rows="fixed"
                    )
                    
                    if st.button("✨ Apply Selected Renaming", type="primary"):
                        approved_rows = edited_df[(edited_df["Apply"] == True) & (edited_df["Original Name"] != edited_df["Suggestion"])]
                        
                        if approved_rows.empty:
                            st.warning("No modified names selected to apply.")
                        else:
                            approved_payload = []
                            for _, row in approved_rows.iterrows():
                                approved_payload.append({
                                    "original_name": row["Original Name"],
                                    "suggestion": row["Suggestion"],
                                    "decl_range": row["_decl"],
                                    "ref_ranges": row["_refs"]
                                })
                            
                            rename_engine = RenameAnalyzer()
                            new_code = rename_engine.transform(st.session_state.m8_code_base, approved_payload)
                            
                            processed, status = DeobfuscatorEngine().process(new_code)
                            if status == "Success":
                                st.session_state.processed_code = processed
                                st.session_state.m8_code_base = new_code
                                st.success(f"Successfully renamed {len(approved_payload)} identifiers. View Output in Tab 1.")
                            else:
                                st.error("Error formatting renamed code.")

                st.download_button("📄 Download M8 Identifier Report (JSON)", json.dumps(m8, indent=4), "identifier_report.json", "application/json")

    # ---------------------------
    # TAB 10: String Array Explorer
    # ---------------------------
    with tabs[9]:
        st.subheader("📦 Advanced String Array Explorer & Reconstruction")
        if not st.session_state.m9_results:
            st.info("Execute the pipeline in Tab 1 to generate String Array Analytics.")
        else:
            m9 = st.session_state.m9_results
            if m9.get("status") == "error":
                st.error(m9["message"])
            else:
                stats = m9["stats"]
                sc1, sc2, sc3, sc4 = st.columns(4)
                sc1.metric("String Arrays", stats["total_arrays"])
                sc2.metric("Total Entries", stats["total_entries"])
                sc3.metric("Resolved Lookups", stats["resolved_lookups"])
                sc4.metric("Rotations Detected", stats["rotation_patterns"])
                
                st.markdown("---")
                
                c_arr, c_acc = st.columns(2)
                with c_arr:
                    st.markdown("#### 📚 Centralized Lookup Tables")
                    if not m9["arrays"]:
                        st.success("No large string arrays detected.")
                    else:
                        for name, data in m9["arrays"].items():
                            with st.expander(f"Array: `{name}` (Size: {len(data['elements'])}) {'⚠️ Rotated' if data['is_rotated'] else ''}"):
                                st.write(f"**Rotated dynamically?** {data['is_rotated']}")
                                st.json(data["elements"][:50]) # preview first 50
                with c_acc:
                    st.markdown("#### ⚙️ Array Accessor Functions")
                    if not m9["accessors"]:
                        st.info("No static function accessors mapped.")
                    else:
                        acc_data = [{"Function": f, "Targets Array": d["array_name"]} for f, d in m9["accessors"].items()]
                        st.dataframe(pd.DataFrame(acc_data), use_container_width=True)

                st.markdown("---")
                st.markdown("#### ✨ Static Lookup Reconstruction Sandbox")
                st.write("Review safely resolved expressions. Expressions targeting rotated arrays are marked `Low Confidence`.")
                
                if not m9["lookups"]:
                    st.info("No statically resolvable lookups found.")
                else:
                    df_data = []
                    for l in m9["lookups"]:
                        # Auto-apply High confidence only
                        apply_def = "High" in l["confidence"]
                        df_data.append({
                            "Apply": apply_def,
                            "Original Expression": l["original_expression"],
                            "Resolved String": l["resolved_value"],
                            "Confidence": l["confidence"],
                            "Target Array": l["array"],
                            "Index": l["index"],
                            "_range": l["range"]
                        })
                        
                    df = pd.DataFrame(df_data)
                    
                    edited_df = st.data_editor(
                        df,
                        column_config={
                            "Apply": st.column_config.CheckboxColumn("Apply Change"),
                            "_range": None # Hide metadata
                        },
                        disabled=["Original Expression", "Resolved String", "Confidence", "Target Array", "Index"],
                        use_container_width=True
                    )
                    
                    if st.button("🚀 Apply Reconstructions", type="primary"):
                        approved = edited_df[edited_df["Apply"] == True]
                        if approved.empty:
                            st.warning("No reconstructions selected.")
                        else:
                            payload = []
                            for _, row in approved.iterrows():
                                payload.append({
                                    "apply": True,
                                    "resolved_value": row["Resolved String"],
                                    "range": row["_range"]
                                })
                                
                            engine = ArrayAnalyzer()
                            new_code = engine.transform(st.session_state.m9_code_base, payload)
                            
                            processed, status = DeobfuscatorEngine().process(new_code)
                            if status == "Success":
                                st.session_state.processed_code = processed
                                st.session_state.m9_code_base = new_code
                                st.success(f"Successfully reconstructed {len(payload)} lookup expressions. View Output in Tab 1.")
                            else:
                                st.error("Error formatting code.")

                st.download_button("📄 Download M9 Array Report (JSON)", json.dumps(m9, indent=4), "array_report.json", "application/json")

if __name__ == "__main__":
    main()
