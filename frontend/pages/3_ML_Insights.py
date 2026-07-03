import streamlit as st
from utils import load_data

st.set_page_config(
    page_title="ML Insights",
    layout="wide"
)

st.title("ML Threat Analysis")

df = load_data()

if df.empty:
    st.warning("No Threat Events Found")
    st.stop()

st.info(
"""
Machine Learning integration is under development.

Current threat scores are generated using rule-based detection.

Future versions will include:

• Isolation Forest
• Anomaly Detection
• Final Threat Score
• Explainable AI
"""
)

st.subheader("Current Rule-Based Detection")

display = df[
    [
        "eventName",
        "severity",
        "riskScore"
    ]
]

st.dataframe(display, use_container_width=True)

st.subheader("Future ML Pipeline")

st.code("""
CloudTrail Logs
        │
        ▼
Feature Engineering
        │
        ▼
Isolation Forest
        │
        ▼
Anomaly Score
        │
        ▼
Final Threat Score
""")