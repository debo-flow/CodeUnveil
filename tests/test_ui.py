import pytest
import streamlit as st
from app import CodeUnveilIDE

def test_ui_initialization_state():
    ide = CodeUnveilIDE()
    # Ensure state initialized cleanly
    assert st.session_state.current_page == "📊 Dashboard"
    assert st.session_state.editor_theme == "monokai"
    assert st.session_state.input_code == ""
    assert st.session_state.notifications == []
    
    # Ensure engine keys exist
    assert "m1_results" in st.session_state
    assert "m20_results" not in st.session_state # Only goes up to M19 engine results locally + profiler
    assert "profiler_stats" in st.session_state

def test_global_command_router():
    ide = CodeUnveilIDE()
    
    st.session_state.search_query = "> AST Explorer"
    try:
        ide.handle_global_command()
    except Exception as e:
        # Streamlit's st.rerun() raises a specific Exception (RerunException). 
        # If it raises that, the route succeeded.
        assert "rerun" in str(e).lower() or type(e).__name__ == "RerunException"
        
    assert st.session_state.current_page == "🌳 AST & Semantics"
    assert len(st.session_state.notifications) == 1
    assert "Navigated to" in st.session_state.notifications[0]
    
    # Check another route
    st.session_state.search_query = "> SECURITY"
    try:
        ide.handle_global_command()
    except Exception as e:
        pass
    
    assert st.session_state.current_page == "🛡️ Security Center"
