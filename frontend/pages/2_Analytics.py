import streamlit as st
import plotly.express as px

from utils import load_data

st.set_page_config(
    page_title="Analytics",
    page_icon="Analytics",
    layout="wide"
)

st.title("Analytics")

df = load_data()

if df.empty:
    st.warning("No Threat Events Found")
    st.stop()

# Threats by Region

st.subheader("Threats by Region")

region = (
    df.groupby("region")
    .size()
    .reset_index(name="Threats")
)

fig = px.bar(
    region,
    x="region",
    y="Threats",
    title="Threats by AWS Region"
)

st.plotly_chart(fig, use_container_width=True)

# Threats by User Type

st.subheader("Threats by User Type")

users = (
    df.groupby("userType")
    .size()
    .reset_index(name="Count")
)

fig2 = px.pie(
    users,
    names="userType",
    values="Count",
    title="Threats by User Type"
)

st.plotly_chart(fig2, use_container_width=True)

# Average Risk

st.subheader("Average Risk Score")

avg = (
    df.groupby("eventName")["riskScore"]
    .mean()
    .reset_index()
)

fig3 = px.bar(
    avg,
    x="eventName",
    y="riskScore",
    title="Average Risk Score by Event"
)

st.plotly_chart(fig3, use_container_width=True)