import streamlit as st
from utils import load_data

st.set_page_config(
    page_title="Threat Details",
    layout="wide"
)

st.title("Threat Details")

df = load_data()

if df.empty:
    st.warning("No Threat Events")
    st.stop()

events = sorted(df["eventName"].unique())

selected = st.selectbox(
    "Select Threat",
    events
)

row = df[df["eventName"] == selected].iloc[-1]

st.divider()

c1, c2 = st.columns(2)

with c1:

    st.metric("Risk Score", row["riskScore"])

    st.write("Severity")
    st.info(row["severity"])

    st.write("Region")
    st.write(row["region"])

    st.write("User Type")
    st.write(row["userType"])

with c2:

    st.write("Source IP")
    st.write(row["sourceIP"])

    st.write("Event Source")
    st.write(row["eventSource"])

    st.write("Timestamp")
    st.write(str(row["timestamp"]))