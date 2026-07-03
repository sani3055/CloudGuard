import streamlit as st
from utils import load_data, color_severity

st.set_page_config(
    page_title="Threat History",
    page_icon="📜",
    layout="wide"
)

st.title("📜 Threat History")

df = load_data()

if df.empty:
    st.warning("No Threat Events Found")
    st.stop()

# -------------------------
# Search
# -------------------------

search = st.text_input(
    "🔍 Search Event Name"
)

if search:

    df = df[
        df["eventName"]
        .str.contains(
            search,
            case=False
        )
    ]

# -------------------------
# Severity Filter
# -------------------------

severity = st.selectbox(
    "Severity",
    [
        "All",
        "Critical",
        "High",
        "Medium",
        "Low"
    ]
)

if severity != "All":
    df = df[
        df["severity"] == severity
    ]

# -------------------------
# Download
# -------------------------

csv = df.to_csv(index=False)

st.download_button(
    "⬇ Download CSV",
    csv,
    "ThreatHistory.csv",
    "text/csv"
)

# -------------------------
# Table
# -------------------------

display = df[
[
"eventName",
"severity",
"riskScore",
"region",
"userType",
"eventSource",
"timestamp"
]
]

st.dataframe(
    display.style.map(
        color_severity,
        subset=["severity"]
    ),
    use_container_width=True
)