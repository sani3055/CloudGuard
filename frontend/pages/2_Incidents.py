import streamlit as st
import pandas as pd
import json
from utils import inject_css, load_data, render_badge, render_risk_gauge, render_investigation_row, update_remediation_status

inject_css()

st.markdown('<div class="soc-header">Anomaly Triage Queue</div>', unsafe_allow_html=True)

df = load_data()
if df.empty:
    st.info("No anomalous events to display.")
    st.stop()

# ── Filters ──
with st.expander("🔍 Filter Anomalies", expanded=False):
    f1, f2, f3, f4 = st.columns(4)
    with f1:
        sev_filter = st.multiselect("Severity", options=df['severity'].unique())
    with f2:
        anom_filter = st.selectbox("Type", options=["All", "Anomaly Only", "Normal Only"])
    with f3:
        status_filter = st.multiselect("Remediation Status", options=df['remediation_status'].unique())
    with f4:
        data_filter = st.selectbox("Data Source", options=["All", "Live AWS", "Demo/Simulation"])

# Apply filters
filtered_df = df.copy()
if sev_filter:
    filtered_df = filtered_df[filtered_df['severity'].isin(sev_filter)]
if anom_filter == "Anomaly Only":
    filtered_df = filtered_df[filtered_df['isAnomaly'] == True]
elif anom_filter == "Normal Only":
    filtered_df = filtered_df[filtered_df['isAnomaly'] == False]
if status_filter:
    filtered_df = filtered_df[filtered_df['remediation_status'].isin(status_filter)]
if data_filter == "Live AWS":
    filtered_df = filtered_df[filtered_df['is_demo'] == False]
elif data_filter == "Demo/Simulation":
    filtered_df = filtered_df[filtered_df['is_demo'] == True]

if filtered_df.empty:
    st.success("No anomalies match the current filters.")
    st.stop()

# ── Analyst Table ──
st.markdown("**Select an Event to Investigate:**")

# Using a selectbox for reliable selection across all Streamlit versions
event_options = []
for _, row in filtered_df.iterrows():
    prefix = "[DEMO] " if row['is_demo'] else "[LIVE] "
    event_options.append(f"{prefix}{row['eventId']} - {row['eventName']} ({row['severity']})")

selected_label = st.selectbox("Event ID", event_options, label_visibility="collapsed")
selected_event_id = selected_label.split(" ")[1] if "[DEMO]" in selected_label or "[LIVE]" in selected_label else selected_label.split(" ")[0]

# Display table
view_df = filtered_df[['timestamp', 'eventId', 'is_demo', 'eventName', 'userIdentitytype', 'awsRegion', 'severity', 'riskScore', 'remediation_status']].copy()
view_df['Data'] = view_df['is_demo'].apply(lambda x: "DEMO" if x else "LIVE")
view_df = view_df.drop(columns=['is_demo'])
st.dataframe(view_df, use_container_width=True, hide_index=True)

st.markdown("---")
st.markdown('<div class="soc-header">Event Investigation Panel</div>', unsafe_allow_html=True)

# ── Investigation Panel ──
incident = filtered_df[filtered_df['eventId'] == selected_event_id].iloc[0]

c1, c2 = st.columns([2, 1])

with c1:
    st.markdown('<div class="inv-panel">', unsafe_allow_html=True)
    st.markdown(render_investigation_row("Event ID", incident['eventId']), unsafe_allow_html=True)
    st.markdown(render_investigation_row("Data Source", "<span style='color:#8b5cf6'>DEMO/SIMULATION</span>" if incident['is_demo'] else "<span style='color:#10b981'>LIVE AWS</span>"), unsafe_allow_html=True)
    st.markdown(render_investigation_row("Timestamp", str(incident['timestamp'])), unsafe_allow_html=True)
    st.markdown(render_investigation_row("API Action", incident['eventName']), unsafe_allow_html=True)
    st.markdown(render_investigation_row("Principal Type", incident['userIdentitytype']), unsafe_allow_html=True)
    st.markdown(render_investigation_row("Source IP", incident.get('sourceIP', 'N/A')), unsafe_allow_html=True)
    st.markdown(render_investigation_row("AWS Region", incident['awsRegion']), unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)
    
    st.markdown('<div class="inv-panel">', unsafe_allow_html=True)
    st.markdown("**ML Intelligence & Operational Context**")
    st.markdown(render_investigation_row("Anomaly Category", incident.get('threat_category', 'Unknown')), unsafe_allow_html=True)
    st.markdown(render_investigation_row("MITRE Tactic/Technique", f"{incident.get('mitre_name', 'N/A')} ({incident.get('mitre_technique', 'N/A')})"), unsafe_allow_html=True)
    st.markdown(render_investigation_row("Confidence Level", incident.get('confidence_level', 'Unknown')), unsafe_allow_html=True)
    st.markdown(f"<div style='margin-top:12px; font-size:0.85rem; color:#9ca3af;'><b>ML / SHAP Rationale:</b> {incident.get('threat_rationale', 'No rationale provided.')}</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

with c2:
    st.markdown(render_risk_gauge(int(incident['riskScore'])), unsafe_allow_html=True)
    st.markdown(f"**Severity:** {render_badge(incident['severity'], incident['severity'])}", unsafe_allow_html=True)
    st.markdown(f"**Anomaly Status:** {render_badge('ANOMALY' if incident['isAnomaly'] else 'NORMAL', 'critical' if incident['isAnomaly'] else 'info')}", unsafe_allow_html=True)
    
    status = incident['remediation_status']
    status_badge_color = "info"
    if status == "PENDING_APPROVAL": status_badge_color = "warning"
    elif status == "APPROVED" or status == "ENFORCED": status_badge_color = "success"
    elif status == "BLOCKED" or status == "ROLLED_BACK": status_badge_color = "critical"
    
    st.markdown(f"**Remediation State:** {render_badge(status, status_badge_color)}", unsafe_allow_html=True)

st.markdown("---")
st.markdown('<div class="soc-header">ML Anomaly Review Workflow</div>', unsafe_allow_html=True)

# Policy details
if status != "NOT_REQUIRED":
    with st.expander("View Proposed IAM Policy Details"):
        st.write(f"**Target ARN:** `{incident.get('policy_target_arn', 'N/A')}`")
        st.write(f"**Validation:** {incident.get('validation_status', 'N/A')}")
        try:
            pol_json = json.loads(incident.get("policy_json", "{}"))
            st.code(json.dumps(pol_json, indent=2), language="json")
        except:
            st.code(incident.get("policy_json", ""), language="json")

# Action Buttons
st.markdown("### Cloud Ops Actions")

if incident['is_demo']:
    st.info("ℹ️ This is a DEMO event. Remediation actions will update the UI but will not execute on live AWS resources.")

if status == "PENDING_APPROVAL":
    bc1, bc2 = st.columns(2)
    with bc1:
        if st.button("✅ APPROVE REMEDIATION", type="primary", use_container_width=True):
            with st.spinner("Executing IAM enforcement on AWS..." if not incident['is_demo'] else "Simulating IAM enforcement..."):
                success = update_remediation_status(incident['eventId'], "APPROVED")
                if success:
                    st.success("Remediation Approved and executed successfully!")
                    st.rerun()
                else:
                    st.error("Failed to execute remediation. Check backend logs.")
    with bc2:
        if st.button("❌ REJECT (FALSE POSITIVE)", use_container_width=True):
            success = update_remediation_status(incident['eventId'], "ROLLED_BACK")
            if success:
                st.success("Anomaly Rejected.")
                st.rerun()
elif status == "APPROVED" or status == "ENFORCED":
    st.success(f"This anomaly has already been {status}.")
elif status == "SIMULATED":
    st.info("This anomaly was SIMULATED. Enforcement is disabled for this record.")
elif status == "NOT_REQUIRED":
    st.info("No policy action was generated for this anomaly.")
else:
    st.warning(f"Current Status: {status}")
