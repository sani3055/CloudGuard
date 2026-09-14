import streamlit as st
import pandas as pd
import plotly.express as px
from utils import inject_css, load_data, render_metric_card, render_badge
import boto3

inject_css()

st.markdown('<div class="soc-header">Cloud Infrastructure & ML Overview</div>', unsafe_allow_html=True)

# ── Load Data ──
df = load_data()

# ── Header Health Checks ──
try:
    dynamodb = boto3.client('dynamodb', region_name='ap-south-1')
    dynamodb.describe_table(TableName='CloudGuard-ThreatEvents')
    aws_status = "🟢 CONNECTED (ap-south-1)"
except Exception:
    aws_status = "🔴 DISCONNECTED"

try:
    lambda_client = boto3.client('lambda', region_name='ap-south-1')
    lambda_client.get_function(FunctionName='CloudGuard-Detection')
    lambda_status = "🟢 ACTIVE"
except Exception:
    lambda_status = "🔴 UNAVAILABLE"

c1, c2, c3, c4 = st.columns(4)
c1.write(f"**AWS DynamoDB:** {aws_status}")
c2.write(f"**AWS Lambda:** {lambda_status}")
c3.write(f"**Pipeline:** {'🟢 HEALTHY' if aws_status.startswith('🟢') else '🔴 FAILING'}")
if not df.empty:
    c4.write(f"**Last Refresh:** {df['timestamp'].max().strftime('%H:%M:%S UTC')}")
else:
    c4.write("**Last Refresh:** N/A")

st.markdown("---")

# ── CloudSecure Pipeline Visualization ──
st.markdown("##### CloudSecure Event Pipeline")
st.markdown("""
<div style="display: flex; justify-content: space-between; text-align: center; font-size: 0.75rem; color: #9ca3af; margin-bottom: 20px; background: #111827; padding: 12px; border-radius: 4px; border: 1px solid #1f2937;">
    <div><b>1. CloudTrail</b><br>API Event Logged</div>
    <div>→</div>
    <div><b>2. EventBridge</b><br>Rule Triggered</div>
    <div>→</div>
    <div><b>3. Lambda (ML)</b><br>Isolation Forest & SHAP</div>
    <div>→</div>
    <div><b>4. DynamoDB</b><br>Risk Score Saved</div>
    <div>→</div>
    <div><b>5. SOC Dashboard</b><br>Analyst Approval</div>
    <div>→</div>
    <div><b>6. IAM Remediation</b><br>Inline Deny Policy</div>
</div>
""", unsafe_allow_html=True)

if df.empty:
    st.info("No cloud events detected yet.")
    st.stop()

# Show DEMO mode warning if applicable
demo_count = len(df[df['is_demo'] == True])
if demo_count > 0:
    st.warning(f"⚠️ Displaying {demo_count} DEMO/SIMULATION events because live AWS data is insufficient or mixed.")

# ── Metrics ──
total_events = len(df)
anomalies = len(df[df['isAnomaly'] == True])
pending_remediation = len(df[df['remediation_status'] == 'PENDING_APPROVAL'])
high_risk = len(df[df['riskScore'] >= 50])

m1, m2, m3, m4 = st.columns(4)
with m1:
    st.markdown(render_metric_card("Total Events Processed", str(total_events), "blue"), unsafe_allow_html=True)
with m2:
    st.markdown(render_metric_card("Anomalies Detected", str(anomalies), "red" if anomalies > 0 else "gray"), unsafe_allow_html=True)
with m3:
    st.markdown(render_metric_card("High/Critical Risk", str(high_risk), "orange" if high_risk > 0 else "gray"), unsafe_allow_html=True)
with m4:
    st.markdown(render_metric_card("Pending ML Review", str(pending_remediation), "orange" if pending_remediation > 0 else "gray"), unsafe_allow_html=True)

# ── Detection Timeline ──
st.markdown('<div class="soc-header">Detection Timeline</div>', unsafe_allow_html=True)

timeline_df = df.copy()
timeline_df['isAnomaly_str'] = timeline_df['isAnomaly'].apply(lambda x: "Anomaly" if x else "Normal")

fig_time = px.scatter(
    timeline_df, 
    x="timestamp", 
    y="riskScore", 
    color="isAnomaly_str",
    color_discrete_map={"Anomaly": "#ef4444", "Normal": "#3b82f6"},
    hover_data=["eventName", "userIdentitytype", "severity", "awsRegion", "is_demo"],
    title="Event Timeline by Risk Score"
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

# ── Risk Intelligence Charts ──
ch1, ch2 = st.columns(2)

with ch1:
    fig_risk = px.histogram(
        df, 
        x="riskScore", 
        nbins=20, 
        title="Risk Score Distribution",
        color_discrete_sequence=["#3b82f6"]
    )
    fig_risk.update_layout(
        template="plotly_dark", 
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(t=40, b=20, l=20, r=20),
        height=300
    )
    st.plotly_chart(fig_risk, use_container_width=True)

with ch2:
    severity_counts = df['severity'].value_counts().reset_index()
    severity_counts.columns = ['severity', 'count']
    color_map = {'Critical': '#ef4444', 'High': '#f97316', 'Medium': '#eab308', 'Low': '#10b981', 'Unknown': '#4b5563'}
    fig_sev = px.pie(
        severity_counts, 
        names='severity', 
        values='count', 
        title="Severity Distribution",
        color='severity',
        color_discrete_map=color_map,
        hole=0.4
    )
    fig_sev.update_layout(
        template="plotly_dark", 
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(t=40, b=20, l=20, r=20),
        height=300
    )
    st.plotly_chart(fig_sev, use_container_width=True)
