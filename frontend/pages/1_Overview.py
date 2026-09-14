import streamlit as st
import pandas as pd
import plotly.express as px
from utils import inject_css, load_data, render_metric_card, render_badge

inject_css()

st.markdown("# ☁️ CloudSecure")
st.markdown('<div class="cg-section-header">Cloud & Machine Learning Intelligence Platform</div>', unsafe_allow_html=True)

# ── Load Data ──
df = load_data()

if df.empty:
    st.info("No cloud events detected yet.")
    st.stop()

# ── Header ──
c1, c2 = st.columns([3, 1])
with c1:
    st.markdown("""
    Welcome to CloudSecure. This dashboard monitors real-time AWS CloudTrail events, 
    processes them through an unsupervised Isolation Forest model, and provides SHAP-based 
    explainability for anomaly detection and automated operational response.
    """)
with c2:
    if pd.notnull(df['timestamp'].max()):
        st.write(f"**Last Refresh:** {df['timestamp'].max().strftime('%H:%M:%S UTC')}")
    else:
        st.write("**Last Refresh:** N/A")

st.markdown("---")

# Show DEMO mode warning if applicable
demo_count = len(df[df['is_demo'] == True])
if demo_count > 0:
    st.markdown(f'<div class="cg-callout cg-callout-demo">⚠️ <b>DEMO MODE</b>: Displaying {demo_count} synthetic events because live AWS data is currently empty or restricted.</div>', unsafe_allow_html=True)
elif demo_count == 0 and len(df) > 0:
    st.markdown(f'<div class="cg-callout cg-callout-success">🟢 <b>LIVE MODE</b>: Successfully processing real-time events from AWS.</div>', unsafe_allow_html=True)

# ── Metrics ──
total_events = len(df)
anomalies = len(df[df['isAnomaly'] == True])
mean_risk = int(df['riskScore'].mean()) if total_events > 0 else 0
pending_remediation = len(df[df['remediation_status'] == 'PENDING_APPROVAL'])

m1, m2, m3, m4 = st.columns(4)
with m1:
    st.markdown(render_metric_card("Total Events Processed", str(total_events), "info"), unsafe_allow_html=True)
with m2:
    st.markdown(render_metric_card("ML Anomalies Detected", str(anomalies), "critical" if anomalies > 0 else "info"), unsafe_allow_html=True)
with m3:
    st.markdown(render_metric_card("Average Risk Score", str(mean_risk), "warning" if mean_risk > 30 else "success"), unsafe_allow_html=True)
with m4:
    st.markdown(render_metric_card("Pending ML Review", str(pending_remediation), "warning" if pending_remediation > 0 else "success"), unsafe_allow_html=True)

# ── Detection Timeline ──
st.markdown('<div class="cg-section-header">ML Anomaly Detection Timeline</div>', unsafe_allow_html=True)

timeline_df = df.copy()
timeline_df['isAnomaly_str'] = timeline_df['isAnomaly'].apply(lambda x: "Anomaly" if x else "Normal")
# Ensure timestamp is datetime for plotly
timeline_df['timestamp'] = pd.to_datetime(timeline_df['timestamp'], errors='coerce')

fig_time = px.scatter(
    timeline_df, 
    x="timestamp", 
    y="riskScore", 
    color="isAnomaly_str",
    color_discrete_map={"Anomaly": "#e05252", "Normal": "#4f86c6"},
    hover_data=["eventName", "userIdentitytype", "awsRegion", "is_demo"],
    title="Event Timeline by ML Risk Score"
)
fig_time.update_layout(
    template="plotly_dark", 
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    margin=dict(t=40, b=20, l=20, r=20),
    height=350,
    xaxis_title="Time",
    yaxis_title="Risk Score (0-100)"
)
st.plotly_chart(fig_time, use_container_width=True)

# ── ML Intelligence Charts ──
ch1, ch2 = st.columns(2)

with ch1:
    st.markdown('<div class="cg-section-header">Risk Score Distribution</div>', unsafe_allow_html=True)
    fig_risk = px.histogram(
        df, 
        x="riskScore", 
        nbins=20, 
        color_discrete_sequence=["#4f86c6"]
    )
    fig_risk.update_layout(
        template="plotly_dark", 
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(t=10, b=20, l=20, r=20),
        height=300,
        xaxis_title="Risk Score",
        yaxis_title="Count"
    )
    st.plotly_chart(fig_risk, use_container_width=True)

with ch2:
    st.markdown('<div class="cg-section-header">Anomaly vs Normal Events</div>', unsafe_allow_html=True)
    anomaly_counts = df['isAnomaly'].value_counts().reset_index()
    anomaly_counts.columns = ['isAnomaly', 'count']
    anomaly_counts['Label'] = anomaly_counts['isAnomaly'].apply(lambda x: "Anomaly" if x else "Normal")
    
    color_map = {'Anomaly': '#e05252', 'Normal': '#4f86c6'}
    fig_anom = px.pie(
        anomaly_counts, 
        names='Label', 
        values='count', 
        color='Label',
        color_discrete_map=color_map,
        hole=0.4
    )
    fig_anom.update_layout(
        template="plotly_dark", 
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(t=10, b=20, l=20, r=20),
        height=300
    )
    st.plotly_chart(fig_anom, use_container_width=True)
