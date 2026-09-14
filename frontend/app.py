"""
app.py
======
Main entry point for CloudGuard SOC Dashboard.
Uses Streamlit st.navigation for a clean sidebar structure.
"""
import sys
from pathlib import Path
import streamlit as st

_FRONTEND_DIR = Path(__file__).resolve().parent
if str(_FRONTEND_DIR) not in sys.path:
    sys.path.insert(0, str(_FRONTEND_DIR))

# Ensure page config is the very first Streamlit command
st.set_page_config(
    page_title="CloudSecure ML Pipeline",
    page_icon="☁️",
    layout="wide",
    initial_sidebar_state="expanded"
)

from utils import inject_css

inject_css()

st.sidebar.markdown("## ☁️ CloudSecure")
st.sidebar.markdown("---")

# Configure Navigation Pages
pages = {
    "Cloud Analytics": [
        st.Page("pages/1_Overview.py", title="Overview"),
        st.Page("pages/2_Event_Investigation.py", title="Event Investigation"),
        st.Page("pages/3_Analytics.py", title="Analytics"),
    ],
    "ML & Infrastructure": [
        st.Page("pages/4_ML_Intelligence.py", title="ML Intelligence"),
        st.Page("pages/5_Cloud_Infrastructure.py", title="Cloud Infrastructure"),
        st.Page("pages/6_Architecture.py", title="Architecture"),
    ]
}

# Run Navigation
pg = st.navigation(pages)
pg.run()