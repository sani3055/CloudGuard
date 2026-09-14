import streamlit as st
import pandas as pd
import json
from utils import inject_css, load_data, render_badge, render_risk_gauge, render_investigation_row, update_remediation_status

inject_css()

st.markdown('<div class="soc-header">Incident Response Queue</div>', unsafe_allow_html=True)

df = load_data()
if df.empty:
    st.info("No security incidents to display.")
    st.stop()

# Filter for anomalies or high risk
incidents_df = df[(df['isAnomaly'] == True) | (df['riskScore'] >= 50)].copy()

if incidents_df.empty:
    st.success("No anomalous or high-risk incidents detected.")
    st.stop()

# ── Analyst Table ──
st.markdown("**Select an Event ID to investigate:**")
event_ids = incidents_df['eventId'].tolist()
selected_event = st.selectbox("Event ID", event_ids, label_visibility="collapsed")

# Display the queue as a clean table (read-only)
view_df = incidents_df[['timestamp', 'eventId', 'eventName', 'userIdentitytype', 'awsRegion', 'severity', 'riskScore', 'remediation_status']]
st.dataframe(view_df, use_container_width=True, hide_index=True)

st.markdown("---")
st.markdown('<div class="soc-header">Incident Investigation Panel</div>', unsafe_allow_html=True)

# ── Investigation Panel ──
incident = incidents_df[incidents_df['eventId'] == selected_event].iloc[0]

c1, c2 = st.columns([2, 1])

with c1:
    st.markdown('<div class="inv-panel">', unsafe_allow_html=True)
    st.markdown(render_investigation_row("Event ID", incident['eventId']), unsafe_allow_html=True)
    st.markdown(render_investigation_row("Timestamp", str(incident['timestamp'])), unsafe_allow_html=True)
    st.markdown(render_investigation_row("API Action", incident['eventName']), unsafe_allow_html=True)
    st.markdown(render_investigation_row("Principal Type", incident['userIdentitytype']), unsafe_allow_html=True)
    st.markdown(render_investigation_row("Source IP", incident.get('sourceIP', 'N/A')), unsafe_allow_html=True)
    st.markdown(render_investigation_row("AWS Region", incident['awsRegion']), unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)
    
    st.markdown('<div class="inv-panel">', unsafe_allow_html=True)
    st.markdown("**ML Intelligence & Security Context**")
    st.markdown(render_investigation_row("Threat Category", incident.get('threat_category', 'Unknown')), unsafe_allow_html=True)
    st.markdown(render_investigation_row("MITRE Tactic/Technique", f"{incident.get('mitre_name', 'N/A')} ({incident.get('mitre_technique', 'N/A')})"), unsafe_allow_html=True)
    st.markdown(render_investigation_row("Confidence Level", incident.get('confidence_level', 'Unknown')), unsafe_allow_html=True)
    st.markdown(f"<div style='margin-top:12px; font-size:0.85rem; color:#9ca3af;'><b>ML Rationale:</b> {incident.get('threat_rationale', 'No rationale provided.')}</div>", unsafe_allow_html=True)
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
st.markdown('<div class="soc-header">Human Approval Workflow</div>', unsafe_allow_html=True)

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
st.markdown("### Analyst Actions")
if status == "PENDING_APPROVAL":
    bc1, bc2 = st.columns(2)
    with bc1:
        if st.button("✅ APPROVE REMEDIATION", type="primary", use_container_width=True):
            with st.spinner("Executing IAM enforcement on AWS..."):
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
                st.success("Remediation Rejected.")
                st.rerun()
elif status == "APPROVED" or status == "ENFORCED":
    st.success(f"This incident has already been {status}.")
elif status == "SIMULATED":
    st.info("This incident was SIMULATED. Enforcement is disabled for this record.")
elif status == "NOT_REQUIRED":
    st.info("No remediation was generated for this incident.")
else:
    st.warning(f"Current Status: {status}")
