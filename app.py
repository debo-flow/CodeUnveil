import streamlit as st
import io
import json
import pandas as pd

# ==========================================
# External Engine Imports (M2 - M20)
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
from semantic_engine import SemanticAnalyzer
from validation_engine import ValidationEngine
from perf_engine import AnalysisCache, PipelineOrchestrator, DeobfuscatorEngine

# ==========================================
# UI Configuration & State Management
# ==========================================
def initialize_state():
    if 'global_cache' not in st.session_state:
        st.session_state.global_cache = AnalysisCache(max_size=50)

    base_keys = [
        'uploader_key', 'input_code', 'processed_code', 'm6_original', 
        'm8_code_base', 'm9_code_base', 'm10_code_base', 'm11_code_base', 
        'm14_code_base', 'm12_original_stats', 'm17_target_code', 'pipeline_status'
    ]
    for key in base_keys:
        if key not in st.session_state: st.session_state[key] = 0 if key == 'uploader_key' else ""
    
    engine_keys = [f"m{i}_results" for i in range(1, 20)] + ['m7_replacements', 'm19_tests', 'profiler_stats']
    for key in engine_keys:
        if key not in st.session_state: st.session_state[key] = None

def reset_app():
    base_keys = [
        'input_code', 'processed_code', 'm6_original', 'm8_code_base', 
        'm9_code_base', 'm10_code_base', 'm11_code_base', 'm14_code_base', 
        'm12_original_stats', 'm17_target_code', 'pipeline_status'
    ]
    for key in base_keys: st.session_state[key] = ""
    
    engine_keys = [f"m{i}_results" for i in range(1, 20)] + ['m7_replacements', 'm19_tests', 'profiler_stats']
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
        
        upload_b = st.file_uploader("Upload Source B (.js) for Clones", type=["js", "txt"], key="upload_b")
        if upload_b is not None:
            st.session_state.m17_target_code = io.StringIO(upload_b.getvalue().decode("utf-8", errors="replace")).read()
            
        st.markdown("#### Configurable Pipeline")
        apply_dce = st.checkbox("🗑️ Destructive Dead Code Removal (M7)", value=False)
        apply_ast_regen = st.checkbox("🏗️ Strict AST Regeneration (M12)", value=False)
        run_sym_exec = st.checkbox("🧮 Enable Symbolic Execution (M15)", value=False, help="May be computationally heavy on deep ASTs. Uses Z3 SMT Solver.")
        
        if st.button("🔄 Reset / Clear All", use_container_width=True):
            reset_app()
            st.rerun()

    tabs = st.tabs([
        "🚀 Main", "🌳 M2", "🧶 M3", "🧮 M4", "🚨 M5", "⚖️ Compare", "🔀 M6/M14", 
        "🪦 M7", "🏷️ M8", "📦 M9", "⚙️ M10", "✨ M11", "🏗️ M12", "🛡️ M13", "🧮 M15", 
        "📁 M16", "🧬 M17", "🧠 M18", "🧪 M19", "⚡ M20: Perf"
    ])

    # ---------------------------
    # TAB 1: MAIN PIPELINE EXECUTION
    # ---------------------------
    with tabs[0]:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Input Original JavaScript")
            user_input = st.text_area("Paste obfuscated code here:", value=st.session_state.input_code, height=350)
            
            if st.button("🚀 Execute Orchestrated Pipeline", type="primary", use_container_width=True):
                if not user_input.strip(): 
                    st.error("Please provide JavaScript code.")
                else:
                    with st.spinner("Executing Orchestrated Caching Pipeline..."):
                        orchestrator = PipelineOrchestrator(cache=st.session_state.global_cache)
                        
                        config = {
                            "apply_dce": apply_dce,
                            "apply_ast_regen": apply_ast_regen,
                            "run_sym_exec": run_sym_exec,
                            "target_b": st.session_state.m17_target_code
                        }
                        
                        results = orchestrator.execute(user_input, config)
                        
                        if results.get("status") == "Success":
                            for key, val in results.items():
                                if key in st.session_state:
                                    st.session_state[key] = val
                        else:
                            st.error(results.get("status", "Unknown Pipeline Error"))

        with col2:
            st.subheader("Output Reconstructed Code")
            st.text_area("Normalized result:", value=st.session_state.processed_code, height=350, disabled=True)
            if st.session_state.processed_code:
                st.download_button("💾 Download Reconstructed JS", st.session_state.processed_code, "codeunveil_output.js", "text/javascript", use_container_width=True)

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
    # TAB 7: Control Flow Graph (CFG) & Deflattening (M6/M14)
    # ---------------------------
    with tabs[6]:
        st.subheader("🔀 Advanced Control Flow & Deflattening Engine")
        if not st.session_state.m6_results:
            st.info("Execute the pipeline in Tab 1 to generate CFG Analytics.")
        else:
            m14 = st.session_state.m6_results
            if m14.get("status") == "error":
                st.error(m14["message"])
            else:
                stats = m14["stats"]
                cff = m14["cff"]
                
                sc1, sc2, sc3, sc4, sc5 = st.columns(5)
                sc1.metric("Basic Blocks", stats["basic_blocks"])
                sc2.metric("CFG Edges", stats["cfg_edges"])
                sc3.metric("Loops", stats["loops"])
                sc4.metric("Dispatcher States", stats["dispatcher_states"])
                sc5.metric("Unreachable Dead Branches", stats["unreachable_removed"])
                
                st.markdown("---")
                col_cff, col_diff = st.columns(2)
                
                with col_cff:
                    st.markdown("#### 🗺️ State Transition Graph (STG)")
                    if not cff["detected"]:
                        st.success("✅ No Switch-based Control Flow Flattening detected.")
                    else:
                        st.error(f"🚨 Dispatcher Detected! State Variable(s): `{', '.join(cff['state_variables'])}`")
                        st.graphviz_chart(m14["stg_graph"])

                with col_diff:
                    st.markdown("#### 🗺️ Control Flow Graph (CFG)")
                    st.graphviz_chart(m14["dot_graph"])
                        
                st.markdown("---")
                st.markdown("#### ✂️ Control Flow Deflattening & Reconstruction Sandbox")
                st.write("Review safely resolved dispatcher loops. Confirmed linear/static state machines can be reconstructed to their original sequential execution order.")
                
                if not cff["reconstruction_queue"]:
                    st.info("No provably safe deflattening operations queued. Either no flattening exists, or state transitions are dynamic/unresolved.")
                else:
                    df_data = []
                    for i, r in enumerate(cff["reconstruction_queue"]):
                        df_data.append({
                            "Apply": True,
                            "State Var": r["state_var"],
                            "Type": r["type"],
                            "Confidence": r["confidence"],
                            "Reconstructed Source": r["reconstructed_code"],
                            "_id": i
                        })
                        
                    df = pd.DataFrame(df_data)
                    edited_df = st.data_editor(
                        df,
                        column_config={
                            "Apply": st.column_config.CheckboxColumn("Apply Deflattening"),
                            "_id": None # Hide metadata
                        },
                        disabled=["State Var", "Type", "Confidence", "Reconstructed Source"],
                        use_container_width=True
                    )
                    
                    if st.button("🚀 Apply Selected Deflattening", type="primary"):
                        approved = edited_df[edited_df["Apply"] == True]
                        if approved.empty:
                            st.warning("No deflattening operations selected.")
                        else:
                            payload = []
                            for _, row in approved.iterrows():
                                orig_obj = cff["reconstruction_queue"][row["_id"]]
                                payload.append({
                                    "apply": True,
                                    "original_range": orig_obj["original_range"],
                                    "reconstructed_code": orig_obj["reconstructed_code"],
                                    "type": orig_obj["type"]
                                })
                                
                            engine = CFGAnalyzer()
                            new_code = engine.transform(st.session_state.m14_code_base, approved_deflatten=payload)
                            
                            processed, status = DeobfuscatorEngine().process(new_code)
                            if status == "Success":
                                st.session_state.processed_code = processed
                                st.session_state.m14_code_base = new_code
                                st.success(f"Successfully deflattened {len(payload)} control flow dispatchers! View Output in Tab 1.")
                            else:
                                st.error("Error formatting code.")

                st.download_button("📄 Download M14 CFG/STG Report (JSON)", json.dumps(m14, indent=4), "cfg_analysis.json", "application/json")

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
                            "_id": None, "_decl": None, "_refs": None
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
                                st.json(data["elements"][:50])
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
                            "_range": None
                        },
                        disabled=["Original Expression", "Resolved String", "Confidence", "Target Array", "Index"],
                        use_container_width=True
                    )
                    
                    if st.button("🚀 Apply Array Reconstructions", type="primary"):
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

    # ---------------------------
    # TAB 11: Function Analysis & Call Graph
    # ---------------------------
    with tabs[10]:
        st.subheader("⚙️ Advanced Function Analysis & Call Graph Engine")
        if not st.session_state.m10_results:
            st.info("Execute the pipeline in Tab 1 to generate Function Analytics.")
        else:
            m10 = st.session_state.m10_results
            if m10.get("status") == "error":
                st.error(m10["message"])
            else:
                stats = m10["stats"]
                sc1, sc2, sc3, sc4 = st.columns(4)
                sc1.metric("Total Functions", stats["total_functions"])
                sc2.metric("IIFEs Detected", stats["iifes"])
                sc3.metric("Arrow Functions", stats["arrow_functions"])
                sc4.metric("Wrappers Detected", stats["wrappers_detected"])
                
                st.markdown("---")
                c_funcs, c_graph = st.columns([1, 1])
                
                with c_funcs:
                    st.markdown("#### 🔬 Function Classifications")
                    if not m10["functions"]:
                        st.info("No functions found in the source code.")
                    else:
                        func_data = []
                        for name, data in m10["functions"].items():
                            func_data.append({
                                "Name / ID": name,
                                "Type": data["type"].replace("Expression", "").replace("Declaration", ""),
                                "Classification": data["classification"],
                                "IIFE?": data["is_iife"]
                            })
                        st.dataframe(pd.DataFrame(func_data), use_container_width=True)

                with c_graph:
                    st.markdown("#### 🗺️ Function Call Graph (CFG)")
                    st.graphviz_chart(m10["call_graph_dot"])

                st.markdown("---")
                st.markdown("#### ✂️ Safe Wrapper Inlining Sandbox")
                st.write("Statically resolve and inline redundant Constant-Return or Forwarding Wrappers.")
                
                if not m10["simplifications"]:
                    st.info("No safe wrapper simplification opportunities found.")
                else:
                    df_data = []
                    for l in m10["simplifications"]:
                        df_data.append({
                            "Apply": True,
                            "Target": l["target_func"],
                            "Type": l["type"],
                            "Original Call": l["original_expression"],
                            "Inlined Code": l["resolved_value"],
                            "_range": l["range"],
                            "_rep_str": l.get("replacement_str")
                        })
                        
                    df = pd.DataFrame(df_data)
                    edited_df = st.data_editor(
                        df,
                        column_config={
                            "Apply": st.column_config.CheckboxColumn("Apply Transform"),
                            "_range": None, "_rep_str": None
                        },
                        disabled=["Target", "Type", "Original Call", "Inlined Code"],
                        use_container_width=True
                    )
                    
                    if st.button("🚀 Apply Wrapper Inlining", type="primary"):
                        approved = edited_df[edited_df["Apply"] == True]
                        if approved.empty:
                            st.warning("No transformations selected.")
                        else:
                            payload = []
                            for _, row in approved.iterrows():
                                payload.append({
                                    "apply": True,
                                    "range": row["_range"],
                                    "resolved_value": row["Inlined Code"],
                                    "replacement_str": row["_rep_str"]
                                })
                                
                            engine = FunctionAnalyzer()
                            new_code = engine.transform(st.session_state.m10_code_base, payload)
                            
                            processed, status = DeobfuscatorEngine().process(new_code)
                            if status == "Success":
                                st.session_state.processed_code = processed
                                st.session_state.m10_code_base = new_code
                                st.success(f"Successfully inlined {len(payload)} wrapper calls. View Output in Tab 1.")
                            else:
                                st.error("Error formatting code.")

                st.download_button("📄 Download M10 Function Report (JSON)", json.dumps(m10, indent=4), "function_report.json", "application/json")

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
                            "_range": None
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

    # ---------------------------
    # TAB 13 (M12): Source Reconstruction Dashboard
    # ---------------------------
    with tabs[12]:
        st.subheader("🏗️ Advanced Code Reconstruction & Readability")
        if not st.session_state.m12_results:
            st.info("Execute the pipeline in Tab 1 with AST Regeneration enabled to view Readability Analytics.")
        else:
            m12 = st.session_state.m12_results
            old = st.session_state.m12_original_stats
            
            st.markdown("#### 📊 Code Quality & Complexity Readability Matrix")
            st.write("Measures structural density, logical line breaks, and syntactic nesting before and after full pipeline compilation.")
            
            sc1, sc2, sc3, sc4 = st.columns(4)
            sc1.metric("Total Line Count", m12.get("total_lines", 0), delta=m12.get("total_lines", 0) - old.get("total_lines", 0), delta_color="inverse")
            sc2.metric("Avg Line Length", round(m12.get("avg_line_length", 0), 1), delta=round(m12.get("avg_line_length", 0) - old.get("avg_line_length", 0), 1), delta_color="inverse")
            sc3.metric("Max Nesting Depth", m12.get("max_nesting_depth", 0), delta=m12.get("max_nesting_depth", 0) - old.get("max_nesting_depth", 0), delta_color="inverse")
            sc4.metric("Statement Density", round(m12.get("statement_density", 0), 2), delta=round(m12.get("statement_density", 0) - old.get("statement_density", 0), 2), delta_color="inverse")
            
            st.markdown("---")
            st.markdown("#### 💻 Pipeline Side-by-Side Validation")
            c_orig, c_recon = st.columns(2)
            with c_orig:
                st.markdown("**Original Obfuscated Code (Pre-Pipeline)**")
                st.code(st.session_state.m6_original[:3000] + ("\n// ...truncated..." if len(st.session_state.m6_original) > 3000 else ""), language="javascript")
            with c_recon:
                st.markdown("**AST-Reconstructed Code (Post-Pipeline)**")
                st.code(st.session_state.processed_code[:3000] + ("\n// ...truncated..." if len(st.session_state.processed_code) > 3000 else ""), language="javascript")
            
            report = {"before_stats": old, "after_stats": m12, "pipeline_success": True}
            st.download_button("📄 Download M12 Code Quality Report (JSON)", json.dumps(report, indent=4), "quality_report.json", "application/json")

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
                    
                    edited_df = st.data_editor(
                        df,
                        column_config={
                            "status": st.column_config.SelectboxColumn("Status", options=["Open", "Reviewed", "False Positive"], required=True),
                            "notes": st.column_config.TextColumn("Analyst Notes"),
                            "snippet": st.column_config.TextColumn("Code Snippet", disabled=True),
                            "remediation": None, "id": None, "rule_id": None
                        },
                        disabled=["severity", "confidence", "category", "name", "description", "location"],
                        use_container_width=True,
                        num_rows="fixed"
                    )
                    
                    if st.button("💾 Save Review State"):
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

    # ---------------------------
    # TAB 15 (M15): Symbolic Execution & Z3 SMT Solver
    # ---------------------------
    with tabs[14]:
        st.subheader("🧮 Symbolic Execution & Z3 Constraint Solver")
        if not st.session_state.m15_results:
            st.info("Check 'Enable Symbolic Execution' in Sidebar and execute the pipeline in Tab 1 to view analytics.")
        else:
            m15 = st.session_state.m15_results
            if m15.get("status") == "error":
                st.error(m15["message"])
            else:
                stats = m15["stats"]
                sc1, sc2, sc3, sc4 = st.columns(4)
                sc1.metric("Paths Explored", stats["paths_explored"])
                sc2.metric("Feasible Branches", stats["feasible_branches"])
                sc3.metric("Infeasible (Dead) Branches", stats["infeasible_branches"])
                sc4.metric("Unknown / Timeouts", stats["unknown_branches"])
                
                st.markdown("---")
                st.markdown("#### 🔬 Path Conditions & Solver Feasibility Matrix")
                st.write("Displays the extracted symbolic constraints sent to Z3 for Satisfiability (SAT) checking.")
                
                if not m15["paths"]:
                    st.success("No conditional paths discovered within the execution bounds.")
                else:
                    df = pd.DataFrame(m15["paths"])
                    st.dataframe(df, use_container_width=True)
                    st.download_button("📄 Download M15 Symbolic Constraints Report (JSON)", json.dumps(m15, indent=4), "symexec_report.json", "application/json")

    # ---------------------------
    # TAB 16 (M16): Project Architecture & Dependency Intelligence
    # ---------------------------
    with tabs[15]:
        st.subheader("📁 Project Architecture & Dependency Intelligence")
        if not st.session_state.m16_results:
            st.info("Upload a Project `.zip` file in the sidebar to generate Architecture Intelligence.")
        else:
            m16 = st.session_state.m16_results
            if m16.get("status") == "error":
                st.error(m16["message"])
            else:
                stats = m16["stats"]
                sc1, sc2, sc3, sc4 = st.columns(4)
                sc1.metric("Analyzed JS/TS Files", stats["js_files"])
                sc2.metric("External Packages", stats["external_deps"])
                sc3.metric("Circular Dependency Chains", stats["circular_dependencies"], delta_color="inverse")
                sc4.metric("Isolated (Unreferenced) Modules", stats["isolated_modules"])
                
                st.markdown("---")
                c_graph, c_info = st.columns(2)
                
                with c_graph:
                    st.markdown("#### 🗺️ Interactive Dependency Graph")
                    st.graphviz_chart(m16["dot_graph"])
                    
                with c_info:
                    st.markdown("#### 🔄 Circular Dependency Tracker")
                    if not m16["circular_chains"]:
                        st.success("✅ No circular dependencies detected in the import graph.")
                    else:
                        st.error(f"🚨 Detected {len(m16['circular_chains'])} Circular Chains.")
                        for i, chain in enumerate(m16['circular_chains']):
                            st.write(f"**Chain {i+1}:** " + " ➔ ".join(chain))
                            
                    st.markdown("#### 📦 package.json Dependencies")
                    if not m16["package_json"]:
                        st.info("No package.json found in the project root.")
                    else:
                        deps = m16["package_json"].get("dependencies", {})
                        dev_deps = m16["package_json"].get("devDependencies", {})
                        if deps or dev_deps:
                            st.json({"dependencies": deps, "devDependencies": dev_deps}, expanded=False)
                            
                st.download_button("📄 Download M16 Architecture Report (JSON)", json.dumps(m16, indent=4), "project_arch_report.json", "application/json")

    # ---------------------------
    # TAB 17 (M17): Clone Detection & Fingerprinting
    # ---------------------------
    with tabs[16]:
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

    # ---------------------------
    # TAB 18 (M18): Semantic Analysis & Program Understanding
    # ---------------------------
    with tabs[17]:
        st.subheader("🧠 Advanced Semantic Analysis & Program Understanding Engine")
        
        if not st.session_state.m18_results:
            st.info("Execute the pipeline in Tab 1 to generate Semantic Analytics.")
        else:
            m18 = st.session_state.m18_results
            if m18.get("status") == "error":
                st.error(m18["message"])
            else:
                stats = m18["stats"]
                
                sc1, sc2, sc3, sc4 = st.columns(4)
                sc1.metric("Total Symbols Tracked", stats["total_symbols"])
                sc2.metric("Resolved Data Types", stats["resolved_types"])
                sc3.metric("Functions Classified", stats["functions_classified"])
                sc4.metric("Side Effects Detected", stats["side_effects_detected"])
                
                st.markdown("---")
                col_tab, col_func = st.columns(2)
                
                with col_tab:
                    st.markdown("#### 📋 Symbol Table & Type Inference")
                    if m18["symbols"]:
                        df_sym = pd.DataFrame(m18["symbols"])
                        st.dataframe(df_sym, use_container_width=True)
                    else:
                        st.info("No variable/parameter symbols declared.")
                        
                with col_func:
                    st.markdown("#### 🤖 Function Semantic Summaries")
                    if m18["functions"]:
                        funcs = []
                        for name, data in m18["functions"].items():
                            funcs.append({
                                "Name": name,
                                "Classification": data["classification"],
                                "Return Type": " | ".join(data["inferred_return_types"]),
                                "Side Effects?": "Yes" if data["has_side_effects"] else "No"
                            })
                        st.dataframe(pd.DataFrame(funcs), use_container_width=True)
                    else:
                        st.info("No functions defined.")
                        
                st.markdown("---")
                c_se, c_graph = st.columns(2)
                with c_se:
                    st.markdown("#### ⚠️ Global Side-Effect Mutations")
                    if not m18["side_effects"]:
                        st.success("No critical side-effects (DOM/Network/Global mutations) detected.")
                    else:
                        for effect in m18["side_effects"]:
                            st.warning(f"- {effect}")
                            
                with c_graph:
                    st.markdown("#### 🔗 Semantic Data Dependency Graph")
                    st.graphviz_chart(m18["dependency_graph_dot"])
                    
                st.download_button("📄 Download M18 Semantic Report (JSON)", json.dumps(m18, indent=4), "semantic_report.json", "application/json")

    # ---------------------------
    # TAB 19 (M19): Automated Testing & Validation Dashboard
    # ---------------------------
    with tabs[18]:
        st.subheader("🧪 M19: Automated Testing, Differential Analysis & Semantic Validation")
        
        if not st.session_state.m19_results:
            st.info("Execute the pipeline in Tab 1 to generate Differential Analytics.")
        else:
            diff = st.session_state.m19_results.get("ast_diff", {})
            tests = st.session_state.m19_tests.get("stats", {})
            
            st.markdown("#### ⚙️ Automated Testing Overview (Metamorphic & Regression)")
            tc1, tc2, tc3 = st.columns(3)
            tc1.metric("Tests Passed", tests.get("PASS", 0))
            tc2.metric("Tests Failed", tests.get("FAIL", 0))
            tc3.metric("Warnings", tests.get("WARNING", 0))
            
            if st.session_state.m19_tests.get("tests"):
                st.dataframe(pd.DataFrame(st.session_state.m19_tests["tests"]).drop(columns=["error_info"]), use_container_width=True)
            
            st.markdown("---")
            st.markdown("#### 🌳 Differential AST Analysis")
            st.write("Identifies nodes structurally altered by the transformation pipeline (Original vs Reconstructed).")
            ac1, ac2, ac3, ac4 = st.columns(4)
            ac1.metric("Nodes Preserved", diff.get("preserved", 0))
            ac2.metric("Nodes Modified", diff.get("modified", 0))
            ac3.metric("Nodes Added", diff.get("added", 0))
            ac4.metric("Nodes Removed", diff.get("removed", 0))
            
            if diff.get("dangerous_changes"):
                st.warning("⚠️ Potentially Unsafe Structural Modifications Detected:")
                for dc in diff["dangerous_changes"]:
                    st.write(f"- {dc}")
            else:
                st.success("✅ No dangerous top-level structure shifts detected.")
                
            st.markdown("---")
            st.markdown("#### 🧠 Semantic Consistency Validation")
            sem = st.session_state.m19_results.get("semantic_diff", {})
            if sem.get("status") == "success":
                st.metric("Symbols Tracked in Transformed Output", sem.get("symbols_preserved", 0))
                if sem.get("side_effects_consistent"):
                    st.success("✅ Transformation Contract Upheld: No new side-effects were unexpectedly introduced by the pipeline.")
                
                if sem.get("issues"):
                    for issue in sem["issues"]:
                        if "DANGER" in issue: st.error(issue)
                        else: st.warning(issue)
            
            st.download_button("📄 Download M19 Validation Report (JSON)", json.dumps(st.session_state.m19_results, indent=4), "validation_report.json", "application/json")

    # ---------------------------
    # TAB 20 (M20): Performance Optimization & Scalability Dashboard
    # ---------------------------
    with tabs[19]:
        st.subheader("⚡ Advanced Performance Optimization & Scalability Engine")
        
        if not st.session_state.profiler_stats:
            st.info("Execute the Orchestrated Pipeline in Tab 1 to generate Resource Profiles.")
        else:
            p_stats = st.session_state.profiler_stats
            c_stats = st.session_state.global_cache.get_stats()
            
            if p_stats.get("cached_run"):
                st.success("⚡ **Lightning Fast!** This payload and configuration was identical to a previous run. Results were retrieved directly from the Intelligent Incremental Cache, bypassing all AST operations.")
            
            st.markdown("#### 🚀 Pipeline Execution Overview")
            sc1, sc2, sc3, sc4 = st.columns(4)
            sc1.metric("Total Execution Time", f"{p_stats['total_time_ms']} ms")
            sc2.metric("Cache Hit Ratio", f"{c_stats['ratio']}%")
            sc3.metric("Cache Size (Objects)", f"{c_stats['size']} / 50")
            sc4.metric("Total Cache Hits", c_stats["hits"])
            
            st.markdown("---")
            st.markdown("#### 🔬 Detailed Stage Profiler (Bottleneck Detection)")
            
            if p_stats.get("cached_run"):
                st.info("Stage-by-stage timings are skipped on Cache Hit runs. Modify a configuration or code to force a clean run.")
            else:
                stages = p_stats["stages"]
                df_data = []
                for name, metrics in stages.items():
                    df_data.append({
                        "Analysis Engine / Stage": name,
                        "Execution Time (ms)": metrics["time_ms"],
                        "Memory Overhead (MB)": metrics["mem_mb"]
                    })
                    
                df = pd.DataFrame(df_data)
                
                # Highlight bottlenecks
                max_time = df["Execution Time (ms)"].max() if not df.empty else 1
                
                st.dataframe(
                    df.style.highlight_max(subset=['Execution Time (ms)', 'Memory Overhead (MB)'], color='rgba(255, 75, 75, 0.4)'),
                    use_container_width=True
                )
                
                st.write("*Note: The stage highlighted in red indicates the primary processing bottleneck.*")

if __name__ == "__main__":
    main()
