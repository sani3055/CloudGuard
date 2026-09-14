"""
app.py — CloudGuard Overview
Project overview for Review-2 demonstration.
Shows dataset statistics, model configuration, pipeline architecture,
and operational mode status. No DynamoDB dependency for primary display.
"""

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# ── Path setup (pipeline_runner lives alongside app.py in frontend/) ──────────
_FRONTEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_FRONTEND_DIR))

from utils import inject_css, render_metric_card, render_badge, render_pipeline_stepper
import pipeline_runner as pr

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(page_title="CloudGuard — Overview", page_icon="🛡️", layout="wide")
inject_css()

# ── Sidebar ───────────────────────────────────────────────────────────────────
st.sidebar.title("CloudGuard")
st.sidebar.caption("AWS Cloud Security Monitoring")
st.sidebar.markdown("---")

st.sidebar.markdown(
    '<div class="cg-section-header" style="margin-top:0">Operational Mode</div>',
    unsafe_allow_html=True,
)
st.sidebar.markdown(
    render_badge("SIMULATION_MODE: ON", "warning") + "<br>" +
    render_badge("ENFORCE_MODE: OFF", "success"),
    unsafe_allow_html=True,
)

st.sidebar.markdown("---")
st.sidebar.markdown(
    '<div class="cg-section-header" style="margin-top:0">Deployment Status</div>',
    unsafe_allow_html=True,
)
try:
    import boto3
    dynamodb = boto3.client('dynamodb', region_name='ap-south-1')
    dynamodb.describe_table(TableName='CloudGuard-ThreatEvents')
    st.sidebar.markdown(render_badge("AWS CONNECTED 🟢", "success"), unsafe_allow_html=True)
except Exception as e:
    st.sidebar.markdown(render_badge("AWS DISCONNECTED 🔴", "critical"), unsafe_allow_html=True)

st.sidebar.markdown("---")
st.sidebar.markdown(
    '<div class="cg-section-header" style="margin-top:0">AWS Services</div>',
    unsafe_allow_html=True,
)
for _svc in ["CloudTrail", "EventBridge", "Lambda", "DynamoDB", "SNS", "IAM Access Analyzer"]:
    st.sidebar.write(f"• {_svc}")

st.sidebar.markdown("---")
if st.sidebar.button("Refresh", help="Re-read model.pkl metadata"):
    st.cache_data.clear()
    st.rerun()

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("## CloudGuard")
st.caption(
    "Anomaly-based AWS cloud security monitoring — "
    "Isolation Forest · SHAP XAI · MITRE ATT&CK · IAM remediation"
)
st.markdown(
    render_badge("SIMULATION MODE", "warning") + "&nbsp;&nbsp;" +
    render_badge("ENFORCE: OFF", "success") + "&nbsp;&nbsp;" +
    render_badge("VIT Academic Demo", "purple"),
    unsafe_allow_html=True,
)

st.divider()

# ── Dataset & Scoring Results ─────────────────────────────────────────────────
st.markdown(
    '<div class="cg-section-header">Dataset & Full-Corpus Scoring Results</div>',
    unsafe_allow_html=True,
)

_d1, _d2, _d3, _d4, _d5 = st.columns(5)
with _d1:
    st.markdown(render_metric_card("Raw CloudTrail Records", "1,939,214", "accent"), unsafe_allow_html=True)
with _d2:
    st.markdown(render_metric_card("Events Scored", "1,939,207", "info"), unsafe_allow_html=True)
with _d3:
    st.markdown(render_metric_card("Anomalies Detected", "42,160", "critical"), unsafe_allow_html=True)
with _d4:
    st.markdown(render_metric_card("Anomaly Rate", "2.1741%", "warning"), unsafe_allow_html=True)
with _d5:
    st.markdown(render_metric_card("Normal Events", "1,897,047", "success"), unsafe_allow_html=True)

st.markdown(
    '<div class="cg-callout cg-callout-info" style="margin-top:6px">'
    '<strong>Source:</strong> <code>data/dec12_18features.csv</code> — '
    '1,939,214 real AWS CloudTrail records. Scored offline using the deployed '
    'Isolation Forest model (model.pkl). 7 records skipped due to unparseable timestamps.</div>',
    unsafe_allow_html=True,
)

st.divider()

# ── Model Configuration ───────────────────────────────────────────────────────
st.markdown(
    '<div class="cg-section-header">Deployed Model — IsolationForest</div>',
    unsafe_allow_html=True,
)

_info = pr.get_model_info()

if _info.get("available"):
    _m1, _m2, _m3, _m4, _m5 = st.columns(5)
    with _m1:
        st.markdown(render_metric_card("Algorithm", _info.get("model_type", "N/A"), "accent"), unsafe_allow_html=True)
    with _m2:
        st.markdown(render_metric_card("Estimators", str(_info.get("n_estimators", "N/A")), "info"), unsafe_allow_html=True)
    with _m3:
        _cont = _info.get("contamination", "N/A")
        _cont_s = f"{float(_cont):.0%}" if _cont not in (None, "auto") else str(_cont)
        st.markdown(render_metric_card("Contamination", _cont_s, "info"), unsafe_allow_html=True)
    with _m4:
        st.markdown(render_metric_card("Anomaly Threshold", str(_info.get("anomaly_threshold", "N/A")), "warning"), unsafe_allow_html=True)
    with _m5:
        st.markdown(render_metric_card("Input Features", str(_info.get("n_features_in", "N/A")), "info"), unsafe_allow_html=True)

    _feat_names = _info.get("feature_names", [])
    if _feat_names:
        _feat_html = ", ".join(f"<code>{f}</code>" for f in _feat_names)
        st.markdown(
            f'<div class="cg-callout cg-callout-info">'
            f'<strong>Feature vector:</strong> [{_feat_html}] — '
            f'Categorical features encoded with OrdinalEncoder (unknown_value=−1). '
            f'Trained on 1,939,214 records. random_state=42.</div>',
            unsafe_allow_html=True,
        )
else:
    st.warning(f"model.pkl unavailable: {_info.get('error', 'run ml/retrain_real.py')}")

st.divider()

# ── Pipeline Architecture ─────────────────────────────────────────────────────
st.markdown(
    '<div class="cg-section-header">Pipeline Architecture — 8 Stages</div>',
    unsafe_allow_html=True,
)

# Stepper with all 8 stages complete (architecture overview)
st.markdown(render_pipeline_stepper(8), unsafe_allow_html=True)

_pipeline_stages = [
    ("CloudTrail Ingestion",   "Raw CloudTrail event received via AWS EventBridge rule targeting the CloudGuard Lambda"),
    ("Feature Extraction",     "feature_contract.extract_features() → {eventName, hour, userIdentitytype, awsRegion, isRoot}"),
    ("Isolation Forest",       "OrdinalEncoder → build_dataframe() → model.decision_function() vs threshold −0.02"),
    ("SHAP XAI",               "shap.TreeExplainer — negative SHAP value = feature shortens isolation path = anomaly driver"),
    ("Threat Classification",  "6 categories (PRIVILEGE_ESCALATION, DEFENSE_EVASION, GEOGRAPHIC/TEMPORAL/CREDENTIAL ANOMALY, UNCERTAIN)"),
    ("IAM Policy Generation",  "Deny policy generated for affected principal; Root account → not enforcement-eligible"),
    ("Access Analyzer",        "Real AWS IAM Access Analyzer API (SIMULATED when credentials unavailable)"),
    ("Controlled Response",    "SIMULATED | PENDING_APPROVAL | BLOCKED | ALERT_ONLY → DynamoDB write → SNS alert"),
]
_stage_df = pd.DataFrame(
    [{"Stage": f"{i+1}. {name}", "Function / Detail": desc}
     for i, (name, desc) in enumerate(_pipeline_stages)]
)
st.dataframe(_stage_df, use_container_width=True, hide_index=True)

st.divider()

# ── Operational Mode ──────────────────────────────────────────────────────────
st.markdown(
    '<div class="cg-section-header">Operational Mode</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="cg-callout cg-callout-warn">'
    '<strong>SIMULATION_MODE: true</strong> — The full pipeline runs end-to-end '
    '(feature extraction → Isolation Forest → SHAP → threat classification → IAM policy → '
    'Access Analyzer validation → controlled response), but <em>no IAM policies are ever attached</em>. '
    'All remediation actions are logged as SIMULATED in DynamoDB.</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="cg-callout cg-callout-info">'
    '<strong>Access Analyzer:</strong> Calls the real AWS IAM Access Analyzer API when credentials '
    'are available. Falls back to a clearly-labelled SIMULATED result when no credentials are present. '
    '<br><strong>ENFORCE_MODE: false</strong> — The enforcement gate in remediation.py is disabled; '
    'policies are generated and validated but never applied.</div>',
    unsafe_allow_html=True,
)