"""
3_ML_Insights.py
================
ML Pipeline Insights — explains the Isolation Forest implementation,
shows full-dataset scoring results, SHAP attribution logic, and runs
a live pipeline demonstration using a known-anomalous CloudTrail event.

Data sources:
  - pipeline_runner.get_model_info()  → real model metadata from model.pkl / encoder.pkl
  - pipeline_runner.run_full_pipeline() → live end-to-end pipeline run
  - threat_classifier.THREAT_CATEGORIES → MITRE ATT&CK reference table

No separate ML implementation is created here. Everything connects to the
existing backend via pipeline_runner.py.
"""

import json
import sys
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# Ensure pipeline_runner can reach backend/ and ml/
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "backend"))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ml"))

import pipeline_runner as pr
from utils import inject_css, render_metric_card, render_badge

st.set_page_config(page_title="ML Insights — CloudGuard", layout="wide")
inject_css()

st.markdown("## ML Insights")
st.caption(
    "Isolation Forest anomaly detection — model configuration, full-corpus scoring results, "
    "SHAP attribution, and live pipeline demonstration."
)

# ── Full-Dataset Scoring Results ───────────────────────────────────────────────
st.markdown(
    '<div class="cg-section-header">Full-Corpus Scoring Results (dec12_18features.csv)</div>',
    unsafe_allow_html=True,
)
_r1, _r2, _r3, _r4, _r5 = st.columns(5)
with _r1:
    st.markdown(render_metric_card("Raw Records", "1,939,214", "accent"), unsafe_allow_html=True)
with _r2:
    st.markdown(render_metric_card("Events Scored", "1,939,207", "info"), unsafe_allow_html=True)
with _r3:
    st.markdown(render_metric_card("Anomalies", "42,160", "critical"), unsafe_allow_html=True)
with _r4:
    st.markdown(render_metric_card("Anomaly Rate", "2.1741%", "warning"), unsafe_allow_html=True)
with _r5:
    st.markdown(render_metric_card("Normal", "1,897,047", "success"), unsafe_allow_html=True)

st.markdown(
    '<div class="cg-callout cg-callout-info">'
    'The corpus was scored offline using the same <code>score_event()</code> function '
    'called at Lambda inference time. '
    'Anomaly criterion: <code>decision_function(x) &lt; −0.02</code>. '
    '7 records were skipped due to unparseable timestamps (no valid eventTime field).'
    '</div>',
    unsafe_allow_html=True,
)
st.divider()

# ── Model Metadata ────────────────────────────────────────────────────────────
st.markdown('<div class="cg-section-header">Deployed Model</div>', unsafe_allow_html=True)

info = pr.get_model_info()

if not info.get("available"):
    st.error(
        f"Model artefacts not found: {info.get('error', 'unknown error')}. "
        "Run ml/retrain_real.py to train and save the model."
    )
    st.stop()

c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(render_metric_card("Algorithm", info.get("model_type", "N/A"), "accent"), unsafe_allow_html=True)
with c2:
    st.markdown(render_metric_card("Estimators", str(info.get("n_estimators", "N/A")), "accent"), unsafe_allow_html=True)
with c3:
    st.markdown(render_metric_card("Features", str(info.get("n_features_in", "N/A")), "accent"), unsafe_allow_html=True)
with c4:
    rows = info.get("training_rows")
    st.markdown(
        render_metric_card("Training Rows", f"{rows:,}" if rows else "N/A", "accent"),
        unsafe_allow_html=True,
    )

c5, c6, c7, c8 = st.columns(4)
with c5:
    contamination = info.get("contamination")
    cont_str = (
        f"{float(contamination):.1%}" if contamination not in (None, "auto") else str(contamination)
    )
    st.markdown(render_metric_card("Contamination", cont_str, "info"), unsafe_allow_html=True)
with c6:
    st.markdown(
        render_metric_card("Anomaly Threshold", str(info.get("anomaly_threshold", "N/A")), "warning"),
        unsafe_allow_html=True,
    )
with c7:
    st.markdown(
        render_metric_card("Max Features", str(info.get("max_features", "N/A")), "info"),
        unsafe_allow_html=True,
    )
with c8:
    cat_count = len(info.get("encoder_categories", {}))
    st.markdown(render_metric_card("Encoded Columns", str(cat_count), "info"), unsafe_allow_html=True)

# ── Feature Definitions ───────────────────────────────────────────────────────
st.markdown('<div class="cg-section-header">Feature Engineering</div>', unsafe_allow_html=True)

import pandas as pd

feature_descriptions = {
    "eventName":        ("Categorical", "AWS API call name — 1,242 unique values from 1.93M CloudTrail records"),
    "hour":             ("Numeric",     "UTC hour of the event (0–23); extracted from eventTime; -1 if unparseable"),
    "userIdentitytype": ("Categorical", "IAM principal type: IAMUser, Root, AssumedRole, AWSService, AWSAccount, Unknown"),
    "awsRegion":        ("Categorical", "AWS region of the API call — 17 known regions from the training corpus"),
    "isRoot":           ("Binary",      "Derived: 1 if userIdentitytype == Root, else 0"),
}

feat_rows = []
for fname in info.get("feature_names", []):
    ftype, fdesc = feature_descriptions.get(fname, ("—", "—"))
    cat_count_val = info.get("encoder_categories", {}).get(fname)
    cat_str = str(cat_count_val) if cat_count_val is not None else "—"
    feat_rows.append({
        "Feature": fname,
        "Type": ftype,
        "Encoder Categories": cat_str,
        "Description": fdesc,
    })

if feat_rows:
    st.dataframe(pd.DataFrame(feat_rows), use_container_width=True, hide_index=True)

# ── SHAP Polarity Convention ──────────────────────────────────────────────────
st.markdown('<div class="cg-section-header">SHAP Attribution Convention</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="cg-callout cg-callout-info">'
    '<strong>Polarity rule (IsolationForest + TreeExplainer):</strong> '
    'A <em>negative</em> SHAP value means the feature <em>shortens</em> the isolation path — '
    'it pushes the score toward anomalous. '
    'The primary anomalous feature is the one with the <em>most negative</em> SHAP value. '
    'Attribution confidence = |top negative SHAP| / sum(|all negative SHAPs|). '
    'Confidence &lt; 0.30 yields an UNCERTAIN classification.'
    '</div>',
    unsafe_allow_html=True,
)

# ── Threat Category Reference ─────────────────────────────────────────────────
st.markdown('<div class="cg-section-header">Threat Categories — MITRE ATT&CK Mapping</div>', unsafe_allow_html=True)

try:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "backend"))
    from threat_classifier import THREAT_CATEGORIES

    cat_rows = []
    for key, meta in THREAT_CATEGORIES.items():
        cat_rows.append({
            "Category Key":     key,
            "Label":            meta["label"],
            "Severity":         meta["severity"],
            "MITRE Technique":  meta["mitre_technique"],
            "MITRE Name":       meta["mitre_name"],
            "Description":      meta["description"],
        })

    st.dataframe(pd.DataFrame(cat_rows), use_container_width=True, hide_index=True, height=295)
except Exception as exc:
    st.warning(f"Could not load threat categories: {exc}")

st.divider()

# ── Live Pipeline Demonstration ───────────────────────────────────────────────
st.markdown("### Live Pipeline Demonstration")
st.markdown(
    '<div class="cg-callout cg-callout-info">'
    'Select a sample event and run the complete 8-stage pipeline using the deployed '
    'Isolation Forest model, SHAP explainer, threat classifier, and IAM generator. '
    'This uses the same code path as the Lambda function.'
    '</div>',
    unsafe_allow_html=True,
)

DEMO_EVENTS = {
    "AttachUserPolicy — Root, off-hours, anomalous region (Expected: Anomaly)": {
        "eventName":  "AttachUserPolicy",
        "eventTime":  "2026-09-05T03:15:00Z",
        "awsRegion":  "ap-southeast-2",
        "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123456789012:root"},
        "requestParameters": {"userName": "target-user", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
    },
    "DeleteTrail — Root, 02:30 UTC (Expected: Anomaly)": {
        "eventName":  "DeleteTrail",
        "eventTime":  "2026-09-05T02:30:00Z",
        "awsRegion":  "us-east-1",
        "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123456789012:root"},
        "requestParameters": {"name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/management"},
    },
    "ListBuckets — IAMUser, business hours, us-east-1 (Expected: Normal)": {
        "eventName":  "ListBuckets",
        "eventTime":  "2026-09-05T10:00:00Z",
        "awsRegion":  "us-east-1",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/developer"},
        "requestParameters": {},
    },
}

st.markdown('<div class="cg-section-header">Select Demo Event</div>', unsafe_allow_html=True)
demo_choice = st.selectbox("Demo event", list(DEMO_EVENTS.keys()), label_visibility="collapsed")
demo_event  = DEMO_EVENTS[demo_choice]

col_ev, col_btn = st.columns([3, 1])
with col_ev:
    st.code(json.dumps(demo_event, indent=2), language="json")
with col_btn:
    st.write("")
    st.write("")
    run_demo = st.button("Run Pipeline", type="primary", use_container_width=True)

if not run_demo:
    st.caption("Click **Run Pipeline** to execute all 8 stages using the deployed model.")
    st.stop()

# ── Execute Pipeline ──────────────────────────────────────────────────────────
with st.spinner("Running pipeline..."):
    stages = pr.run_full_pipeline(demo_event)

# ── Pipeline Stepper ──────────────────────────────────────────────────────────
from utils import render_pipeline_stepper

stage_map = {
    "features":            2,
    "ml":                  3,
    "xai":                 4,
    "threat":              5,
    "iam":                 6,
    "validation":          7,
    "controlled_response": 8,
}
completed = 0
for sname, snum in stage_map.items():
    s = stages.get(sname, {})
    if s.get("result") and not s.get("error"):
        completed = snum

st.markdown(render_pipeline_stepper(completed=completed), unsafe_allow_html=True)
st.divider()

# ── Stage Results ─────────────────────────────────────────────────────────────
ml_s    = stages.get("ml", {})
ml_res  = ml_s.get("result") or {}
is_anom = ml_res.get("is_anomaly", False)

# Stage 1 — Ingestion
with st.expander("Stage 1 — CloudTrail Event Ingested", expanded=True):
    st.code(json.dumps(demo_event, indent=2, default=str), language="json")

# Stage 2 — Features
feat_s = stages.get("features", {})
with st.expander("Stage 2 — Feature Extraction", expanded=True):
    if feat_s.get("error"):
        st.error(f"Feature extraction failed: {feat_s['error']}")
    elif feat_s.get("result"):
        feats = feat_s["result"]
        f_rows = [
            {"Feature": k, "Value": str(feats.get(k, "N/A"))}
            for k in ["eventName", "hour", "userIdentitytype", "awsRegion", "isRoot"]
        ]
        st.dataframe(pd.DataFrame(f_rows), use_container_width=True, hide_index=True)

# Stage 3 — ML Scoring
with st.expander("Stage 3 — Isolation Forest Scoring", expanded=True):
    if ml_s.get("error"):
        st.error(f"ML inference failed: {ml_s['error']}")
        st.info("Ensure model.pkl and encoder.pkl exist in ml/.")
    elif ml_res:
        score     = float(ml_res.get("anomaly_score", 0))
        threshold = info.get("anomaly_threshold", -0.02)

        mc1, mc2, mc3 = st.columns(3)
        with mc1:
            st.markdown(
                render_metric_card("Anomaly Score", f"{score:.6f}", "critical" if is_anom else "success"),
                unsafe_allow_html=True,
            )
        with mc2:
            st.markdown(
                render_metric_card("Decision", "ANOMALY" if is_anom else "NORMAL", "critical" if is_anom else "success"),
                unsafe_allow_html=True,
            )
        with mc3:
            st.markdown(
                render_metric_card("Threshold", str(threshold), "warning"),
                unsafe_allow_html=True,
            )

        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            number={"valueformat": ".5f"},
            title={"text": "Anomaly Score (negative = anomalous)"},
            gauge={
                "axis":    {"range": [-0.3, 0.3], "tickcolor": "#6b7694"},
                "bar":     {"color": "#e05252" if is_anom else "#4ade80"},
                "bgcolor": "#141720",
                "bordercolor": "#242740",
                "steps": [
                    {"range": [-0.3, float(threshold)], "color": "rgba(224,82,82,0.12)"},
                    {"range": [float(threshold), 0.3],  "color": "rgba(74,222,128,0.08)"},
                ],
                "threshold": {
                    "line": {"color": "#fbbf24", "width": 2},
                    "thickness": 0.75,
                    "value": float(threshold),
                },
            },
        ))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#9aa0b4"),
            height=220,
            margin=dict(t=30, b=5),
        )
        st.plotly_chart(fig, use_container_width=True)

        if not is_anom:
            st.markdown(
                '<div class="cg-callout cg-callout-success">Event scored as <strong>normal</strong> — '
                'anomaly score is above the threshold. Stages 4–8 are not triggered.</div>',
                unsafe_allow_html=True,
            )

# Stage 4 — SHAP XAI
xai_s = stages.get("xai", {})
with st.expander("Stage 4 — SHAP XAI Attribution", expanded=is_anom):
    if xai_s.get("skipped"):
        st.info("Event was not anomalous — SHAP attribution not computed.")
    elif xai_s.get("error"):
        st.error(f"XAI failed: {xai_s['error']}")
    elif xai_s.get("result"):
        xai = xai_s["result"]
        shap_vals = xai.get("shap_values", {})

        if shap_vals:
            pairs  = sorted(shap_vals.items(), key=lambda x: x[1])
            colors = ["#e05252" if v < 0 else "#4ade80" for _, v in pairs]
            fig2 = go.Figure(go.Bar(
                x=[v for _, v in pairs],
                y=[k for k, _ in pairs],
                orientation="h",
                marker_color=colors,
                text=[f"{v:+.4f}" for _, v in pairs],
                textposition="outside",
            ))
            fig2.update_layout(
                title="SHAP Feature Contributions — negative = anomaly driver",
                xaxis_title="SHAP Value",
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                height=240,
                xaxis=dict(zeroline=True, zerolinecolor="#3a3e52", zerolinewidth=1),
                margin=dict(t=40, b=10),
            )
            st.plotly_chart(fig2, use_container_width=True)

        xc1, xc2, xc3 = st.columns(3)
        with xc1:
            st.markdown(render_metric_card("Top Anomalous Feature", xai.get("top_feature", "N/A"), "accent"), unsafe_allow_html=True)
        with xc2:
            sv = float(xai.get("top_shap_value", 0))
            st.markdown(render_metric_card("Top SHAP Value", f"{sv:+.4f}", "critical"), unsafe_allow_html=True)
        with xc3:
            conf = float(xai.get("attribution_confidence", 0)) * 100
            st.markdown(render_metric_card("Attribution Confidence", f"{conf:.1f}%", "accent"), unsafe_allow_html=True)

# Stage 5 — Threat Classification
threat_s = stages.get("threat", {})
with st.expander("Stage 5 — Threat Classification", expanded=is_anom):
    if threat_s.get("skipped"):
        st.info("Not anomalous or XAI failed — classification skipped.")
    elif threat_s.get("error"):
        st.error(f"Threat classification failed: {threat_s['error']}")
    elif threat_s.get("result"):
        thr = threat_s["result"]
        BADGE_MAP = {
            "PRIVILEGE_ESCALATION":  "critical",
            "DEFENSE_EVASION":       "critical",
            "CREDENTIAL_ANOMALY":    "critical",
            "GEOGRAPHIC_ANOMALY":    "info",
            "TEMPORAL_ANOMALY":      "high",
            "RESOURCE_EXFILTRATION": "high",
            "UNCERTAIN":             "medium",
        }
        variant = BADGE_MAP.get(thr.get("threat_category", ""), "info")
        st.markdown(
            f'<h4 style="margin:0 0 8px 0;">{render_badge(thr.get("label",""), variant)}'
            f'&nbsp;&nbsp;<span style="font-size:0.85rem;color:#6b7694;">'
            f'Severity: {thr.get("severity")} &nbsp;|&nbsp; '
            f'Confidence: {thr.get("confidence_level")} &nbsp;|&nbsp; '
            f'MITRE: {thr.get("mitre_technique")}'
            f'</span></h4>',
            unsafe_allow_html=True,
        )
        st.markdown(f"**{thr.get('mitre_name', '')}** — {thr.get('description', '')}")
        st.markdown(
            f'<div class="cg-callout cg-callout-info"><strong>Rationale:</strong> {thr.get("rationale","")}</div>',
            unsafe_allow_html=True,
        )

# Stage 6 — IAM Policy
iam_s = stages.get("iam", {})
with st.expander("Stage 6 — IAM Policy Generation", expanded=is_anom):
    if iam_s.get("skipped"):
        st.info("IAM policy generation skipped.")
    elif iam_s.get("error"):
        st.error(f"IAM generation failed: {iam_s['error']}")
    elif iam_s.get("result"):
        iam  = iam_s["result"]
        elig = iam.get("enforcement_eligible", False)
        ic1, ic2 = st.columns(2)
        with ic1:
            st.markdown(render_metric_card("Policy Name", iam.get("policy_name","N/A"), "accent"), unsafe_allow_html=True)
        with ic2:
            st.markdown(
                render_metric_card("Enforcement Eligible", "Yes" if elig else "No", "success" if elig else "critical"),
                unsafe_allow_html=True,
            )
        st.write(f"**Target ARN:** `{iam.get('target_arn','N/A')}`")
        try:
            policy_pretty = json.dumps(json.loads(iam.get("policy_json", "{}")), indent=2)
        except Exception:
            policy_pretty = str(iam.get("policy_json", "{}"))
        st.code(policy_pretty, language="json")
        if not elig:
            st.markdown(
                f'<div class="cg-callout cg-callout-warn">Not enforcement-eligible: {iam.get("skip_reason","")}</div>',
                unsafe_allow_html=True,
            )

# Stage 7 — Validation
val_s = stages.get("validation", {})
with st.expander("Stage 7 — Access Analyzer Validation", expanded=is_anom):
    if val_s.get("skipped"):
        st.info("Validation skipped — no policy generated.")
    elif val_s.get("error"):
        st.error(f"Validation error: {val_s['error']}")
    elif val_s.get("result"):
        val = val_s["result"]
        if val.get("simulated"):
            st.markdown(
                '<div class="cg-callout cg-callout-demo"><strong>[SIMULATED]</strong> — '
                f'AWS Access Analyzer unavailable: {val.get("simulated_reason","No credentials")}. '
                'In production, the real IAM Access Analyzer API is called.</div>',
                unsafe_allow_html=True,
            )
        vs = val.get("validation_status", "N/A")
        vc1, vc2 = st.columns(2)
        with vc1:
            VAR_MAP = {"CLEAN":"success","SUGGESTION_ONLY":"success","WARNING_PRESENT":"warning","BLOCKED":"critical","ERROR":"critical"}
            st.markdown(render_metric_card("Validation Status", vs, VAR_MAP.get(vs,"info")), unsafe_allow_html=True)
        with vc2:
            st.markdown(render_metric_card("Can Proceed", "Yes" if val.get("proceed") else "No", "success" if val.get("proceed") else "critical"), unsafe_allow_html=True)

# Stage 8 — Controlled Response
ctrl_s = stages.get("controlled_response", {})
with st.expander("Stage 8 — Controlled Response", expanded=True):
    if ctrl_s.get("skipped"):
        st.info("Controlled response skipped — event was normal.")
    elif ctrl_s.get("result"):
        ctrl   = ctrl_s["result"]
        action = ctrl.get("action", "N/A")
        ACTION_MAP = {
            "SIMULATED":        ("purple",  "SIMULATED — Policy ready; no real IAM change made"),
            "PENDING_APPROVAL": ("warning", "PENDING APPROVAL — Human review required"),
            "BLOCKED":          ("critical","BLOCKED — Policy prevented from enforcement"),
            "ALERT_ONLY":       ("warning", "ALERT ONLY — No policy attached (principal not eligible)"),
        }
        a_var, a_lbl = ACTION_MAP.get(action, ("info", action))
        st.markdown(
            f'<div class="cg-callout cg-callout-{a_var}"><strong>{a_lbl}</strong><br>{ctrl.get("reason","")}</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="cg-callout cg-callout-demo"><strong>[SIMULATED STAGE]</strong> — '
            'Enforcement is always simulated in the dashboard. In production, the Lambda '
            'function carries out this action when <code>ENFORCE_MODE=true</code>.</div>',
            unsafe_allow_html=True,
        )