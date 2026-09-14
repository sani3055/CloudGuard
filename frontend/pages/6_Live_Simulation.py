"""
6_Live_Simulation.py
====================
Interactive sandbox — select or compose an attack scenario and run
the complete 8-stage CloudGuard detection pipeline in real time:

  Stage 1: CloudTrail Event Ingestion
  Stage 2: Feature Extraction (feature_contract.py)
  Stage 3: Isolation Forest ML Scoring (model.pkl)
  Stage 4: SHAP XAI Attribution (xai_explainer.py)
  Stage 5: Threat Classification (threat_classifier.py)
  Stage 6: IAM Policy Generation (iam_generator.py)
  Stage 7: Access Analyzer Validation (policy_validator.py / simulated)
  Stage 8: Controlled Response & Audit Log

All results clearly label whether they come from live AWS or simulation.
"""

import json
import uuid
import datetime

import plotly.graph_objects as go
import streamlit as st

from utils import inject_css, render_pipeline_stepper, render_metric_card, render_badge
import pipeline_runner as pr

st.set_page_config(page_title="Live Simulation — CloudGuard", layout="wide")
inject_css()

st.markdown("## Live Simulation")
st.caption(
    "Run the complete 8-stage CloudGuard detection pipeline on a preset or custom CloudTrail event. "
    "All stages use the locally deployed model files. AWS-dependent stages are clearly labelled when simulated."
)

st.markdown(
    '<div class="cg-callout cg-callout-info">'
    '🔒 <strong>No real AWS changes are made.</strong> Stage 7 (Access Analyzer) calls the real '
    'AWS API if credentials are present, otherwise returns a clearly-labelled simulated result. '
    'Stage 8 never attaches policies — it shows what the enforcement decision <em>would be</em>.'
    '</div>',
    unsafe_allow_html=True,
)

# ── Preset Attack Scenarios ───────────────────────────────────────────────────
SCENARIOS = {
    "Privilege Escalation — AttachUserPolicy (Root, off-hours, anomalous region)": {
        "description": "Root account attaches AdministratorAccess policy outside business hours from an unusual region.",
        "event": {
            "eventName":  "AttachUserPolicy",
            "eventTime":  "2026-09-05T03:15:00Z",
            "awsRegion":  "ap-southeast-2",
            "userIdentity": {
                "type": "Root",
                "arn":  "arn:aws:iam::123456789012:root",
            },
            "requestParameters": {
                "userName":  "target-user",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
        },
    },
    "Defense Evasion — DeleteTrail (IAMUser, night-time)": {
        "description": "IAM user deletes a CloudTrail trail at 02:30 UTC — classic audit log tampering.",
        "event": {
            "eventName":  "DeleteTrail",
            "eventTime":  "2026-09-05T02:30:00Z",
            "awsRegion":  "us-east-1",
            "userIdentity": {
                "type": "IAMUser",
                "arn":  "arn:aws:iam::123456789012:user/attacker",
            },
            "requestParameters": {"name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/management"},
        },
    },
    "S3 Exfiltration — GetObject (AssumedRole, foreign region)": {
        "description": "Assumed role accesses S3 objects from an unexpected Asia-Pacific region.",
        "event": {
            "eventName":  "GetObject",
            "eventTime":  "2026-09-05T14:40:00Z",
            "awsRegion":  "ap-northeast-1",
            "userIdentity": {
                "type": "AssumedRole",
                "arn":  "arn:aws:sts::123456789012:assumed-role/DataAccessRole/session1",
            },
            "requestParameters": {"bucketName": "sensitive-data-bucket", "key": "customer-pii.csv"},
        },
    },
    "Credential Anomaly — Root API Usage": {
        "description": "Root account used for direct API activity — AWS best practice explicitly forbids this.",
        "event": {
            "eventName":  "CreateAccessKey",
            "eventTime":  "2026-09-05T00:05:00Z",
            "awsRegion":  "us-east-1",
            "userIdentity": {
                "type": "Root",
                "arn":  "arn:aws:iam::123456789012:root",
            },
            "requestParameters": {"userName": None},
        },
    },
    "Normal Event — ListBuckets (IAMUser, business hours, us-east-1)": {
        "description": "IAM user lists S3 buckets during business hours from a known region — model should score this as NORMAL and skip all downstream anomaly stages.",
        "event": {
            "eventName":  "ListBuckets",
            "eventTime":  "2026-09-05T10:00:00Z",
            "awsRegion":  "us-east-1",
            "userIdentity": {
                "type": "IAMUser",
                "arn":  "arn:aws:iam::123456789012:user/developer",
            },
            "requestParameters": {},
        },
    },
    "Custom Event (edit below)": {
        "description": "Write your own CloudTrail event JSON in the editor.",
        "event": {
            "eventName":  "YourEventName",
            "eventTime":  "2026-09-05T12:00:00Z",
            "awsRegion":  "us-east-1",
            "userIdentity": {
                "type": "IAMUser",
                "arn":  "arn:aws:iam::123456789012:user/your-user",
            },
        },
    },
}

# ── Scenario Selector ─────────────────────────────────────────────────────────
st.markdown('<div class="cg-section-header">Select Scenario</div>', unsafe_allow_html=True)
scenario_name = st.selectbox("Scenario", list(SCENARIOS.keys()), label_visibility="collapsed")
scenario = SCENARIOS[scenario_name]

st.markdown(
    f'<div class="cg-callout cg-callout-info"><strong>{scenario_name}</strong><br>{scenario["description"]}</div>',
    unsafe_allow_html=True,
)

# ── Event Editor ──────────────────────────────────────────────────────────────
st.markdown('<div class="cg-section-header">CloudTrail Event (editable)</div>', unsafe_allow_html=True)
event_json_str = st.text_area(
    "Event JSON",
    value=json.dumps(scenario["event"], indent=2),
    height=200,
    label_visibility="collapsed",
)

try:
    cloudtrail_event = json.loads(event_json_str)
    json_ok = True
except json.JSONDecodeError as e:
    st.error(f"Invalid JSON: {e}")
    json_ok = False

# ── Run Button ────────────────────────────────────────────────────────────────
run_clicked = st.button("Run Pipeline", type="primary", disabled=not json_ok, use_container_width=False)

if not run_clicked:
    st.caption("Edit the event JSON above then click **Run Pipeline** to execute all 8 stages.")
    # Init audit log
    if "sim_audit_log" not in st.session_state:
        st.session_state.sim_audit_log = []
    if st.session_state.sim_audit_log:
        st.divider()
        st.markdown('<div class="cg-section-header">Session Audit Log</div>', unsafe_allow_html=True)
        for entry in reversed(st.session_state.sim_audit_log[-10:]):
            st.markdown(
                f'`{entry["ts"]}` &nbsp; **{entry["scenario"]}** → '
                f'{render_badge(entry["ml_decision"], "critical" if entry["ml_decision"] == "ANOMALY" else "success")} '
                f'| Threat: `{entry.get("threat", "N/A")}` '
                f'| Response: `{entry.get("response", "N/A")}`',
                unsafe_allow_html=True,
            )
    st.stop()

# ── Run Full Pipeline ─────────────────────────────────────────────────────────
with st.spinner("Running pipeline..."):
    stages = pr.run_full_pipeline(cloudtrail_event)

# ── Progress Stepper ──────────────────────────────────────────────────────────
completed = 0
stage_map = {
    "features":           2,
    "ml":                 3,
    "xai":                4,
    "threat":             5,
    "iam":                6,
    "validation":         7,
    "controlled_response":8,
}
for sname, snum in stage_map.items():
    s = stages.get(sname, {})
    if s.get("result") and not s.get("error"):
        completed = snum

st.markdown(render_pipeline_stepper(completed=completed), unsafe_allow_html=True)
st.divider()

# Determine anomaly result at top level for use in expanders
is_anom = (stages.get("ml") or {}).get("result", {}).get("is_anomaly", False)

# ──────────────────────────────────────────────────────────────────────────────
# Stage 1: Ingested Event
# ──────────────────────────────────────────────────────────────────────────────
with st.expander("Stage 1 — CloudTrail Event Ingested", expanded=True):
    st.code(json.dumps(cloudtrail_event, indent=2, default=str), language="json")

# ──────────────────────────────────────────────────────────────────────────────
# Stage 2: Features
# ──────────────────────────────────────────────────────────────────────────────
feat_s = stages.get("features", {})
with st.expander("Stage 2 — Feature Extraction", expanded=True):
    if feat_s.get("error"):
        st.error(f"Feature extraction failed: {feat_s['error']}")
    elif feat_s.get("result"):
        features = feat_s["result"]
        FEAT_DESC = {
            "eventName":        "AWS API call name",
            "hour":             "UTC hour (0-23)",
            "userIdentitytype": "IAM principal type",
            "awsRegion":        "AWS region of call",
            "isRoot":           "Binary: 1 = Root account",
        }
        import pandas as pd
        rows = [
            {"Feature": k, "Extracted Value": str(features.get(k, "N/A")), "Description": FEAT_DESC.get(k, "")}
            for k in FEAT_DESC
        ]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

# ──────────────────────────────────────────────────────────────────────────────
# Stage 3: ML
# ──────────────────────────────────────────────────────────────────────────────
ml_s = stages.get("ml", {})
with st.expander("Stage 3 — Isolation Forest ML Scoring", expanded=True):
    if ml_s.get("error"):
        st.error(f"ML inference failed: {ml_s['error']}")
        st.info("Ensure model.pkl and encoder.pkl exist in ml/ directory.")
    elif ml_s.get("result"):
        ml = ml_s["result"]
        mc1, mc2, mc3 = st.columns(3)
        is_anom = ml.get("is_anomaly", False)
        with mc1:
            st.markdown(render_metric_card("Anomaly Score", f"{ml.get('anomaly_score', 0):.6f}", "critical" if is_anom else "success"), unsafe_allow_html=True)
        with mc2:
            st.markdown(render_metric_card("ML Prediction", "ANOMALY 🔴" if is_anom else "NORMAL 🟢", "critical" if is_anom else "success"), unsafe_allow_html=True)
        with mc3:
            st.markdown(render_metric_card("Encoded Vector", str(ml.get("encoded", [])), "accent"), unsafe_allow_html=True)

        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=float(ml.get("anomaly_score", 0)),
            number={"valueformat": ".5f"},
            title={"text": "Anomaly Score"},
            gauge={
                "axis": {"range": [-0.3, 0.3], "tickcolor": "#9aa0b4"},
                "bar":  {"color": "#e05252" if is_anom else "#4caf7d"},
                "bgcolor": "#1a1d27",
                "bordercolor": "#2a2d3e",
                "steps": [
                    {"range": [-0.3, -0.02], "color": "rgba(224,82,82,0.15)"},
                    {"range": [-0.02, 0.3],  "color": "rgba(76,175,125,0.1)"},
                ],
                "threshold": {"line": {"color": "#d4a847", "width": 2}, "thickness": 0.75, "value": -0.02},
            },
        ))
        fig_gauge.update_layout(paper_bgcolor="rgba(0,0,0,0)", font=dict(color="#9aa0b4"), height=220, margin=dict(t=30, b=5))
        st.plotly_chart(fig_gauge, use_container_width=True)

        if not is_anom:
            st.markdown(
                '<div class="cg-callout cg-callout-success">✅ Event scored as <strong>normal</strong> — '
                'anomaly score is above the threshold. Stages 4–8 are not triggered.</div>',
                unsafe_allow_html=True,
            )

# ──────────────────────────────────────────────────────────────────────────────
# Stage 4: XAI
# ──────────────────────────────────────────────────────────────────────────────
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
            pairs   = sorted(shap_vals.items(), key=lambda x: x[1])
            f_names = [p[0] for p in pairs]
            f_vals  = [p[1] for p in pairs]
            colors  = ["#e05252" if v < 0 else "#4caf7d" for v in f_vals]

            fig = go.Figure(go.Bar(
                x=f_vals, y=f_names, orientation="h",
                marker_color=colors,
                text=[f"{v:+.4f}" for v in f_vals],
                textposition="outside",
            ))
            fig.update_layout(
                title="SHAP Feature Contributions (red = anomaly driver, green = normal driver)",
                xaxis_title="SHAP Value",
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                height=260,
                xaxis=dict(zeroline=True, zerolinecolor="#5c6278", zerolinewidth=1),
                margin=dict(t=50, b=10),
            )
            st.plotly_chart(fig, use_container_width=True)

        xc1, xc2, xc3 = st.columns(3)
        with xc1:
            st.markdown(render_metric_card("Top Anomalous Feature", xai.get("top_feature", "N/A"), "accent"), unsafe_allow_html=True)
        with xc2:
            sv = float(xai.get("top_shap_value", 0))
            st.markdown(render_metric_card("Top SHAP Value", f"{sv:+.4f}", "critical"), unsafe_allow_html=True)
        with xc3:
            conf = float(xai.get("attribution_confidence", 0)) * 100
            st.markdown(render_metric_card("Attribution Confidence", f"{conf:.1f}%", "accent"), unsafe_allow_html=True)

        if xai.get("is_uncertain"):
            st.markdown(
                '<div class="cg-callout cg-callout-warn">⚠️ Attribution confidence below threshold — '
                'anomaly explanation is uncertain. Threat classification will return UNCERTAIN.</div>',
                unsafe_allow_html=True,
            )

# ──────────────────────────────────────────────────────────────────────────────
# Stage 5: Threat Classification
# ──────────────────────────────────────────────────────────────────────────────
threat_s = stages.get("threat", {})
with st.expander("Stage 5 — Threat Classification", expanded=is_anom):
    if threat_s.get("skipped"):
        st.info("Event was not anomalous or XAI failed — threat classification skipped.")
    elif threat_s.get("error"):
        st.error(f"Threat classification failed: {threat_s['error']}")
    elif threat_s.get("result"):
        thr = threat_s["result"]
        BADGE_VARIANTS = {
            "PRIVILEGE_ESCALATION":  "critical",
            "DEFENSE_EVASION":       "critical",
            "GEOGRAPHIC_ANOMALY":    "info",
            "TEMPORAL_ANOMALY":      "high",
            "RESOURCE_EXFILTRATION": "high",
            "CREDENTIAL_ANOMALY":    "critical",
            "UNCERTAIN":             "medium",
        }
        variant = BADGE_VARIANTS.get(thr.get("threat_category", ""), "info")
        st.markdown(
            f'### {render_badge(thr.get("label", "Unknown"), variant)}&nbsp;&nbsp;'
            f'<span style="font-size:13px;color:#9aa0b4;">'
            f'Severity: {thr.get("severity")} &nbsp;|&nbsp; '
            f'Confidence: {thr.get("confidence_level")} &nbsp;|&nbsp; '
            f'MITRE: {thr.get("mitre_technique")}'
            f'</span>',
            unsafe_allow_html=True,
        )
        st.markdown(f"**{thr.get('mitre_name', '')}** — {thr.get('description', '')}")
        st.markdown(
            f'<div class="cg-callout cg-callout-info"><strong>Rationale:</strong> {thr.get("rationale", "")}</div>',
            unsafe_allow_html=True,
        )
        
        # Add risk score gauge
        from utils import render_risk_gauge
        st.markdown(render_risk_gauge(int(thr.get("risk_score", 0))), unsafe_allow_html=True)

        if thr.get("mitre_technique") and thr["mitre_technique"] != "N/A":
            tech_id   = thr["mitre_technique"].split("/")[0].strip().replace(".", "")
            mitre_url = f"https://attack.mitre.org/techniques/{tech_id}/"
            st.markdown(f"🔗 [View {thr['mitre_technique']} on MITRE ATT&CK]({mitre_url})")

# ──────────────────────────────────────────────────────────────────────────────
# Stage 6: IAM Policy
# ──────────────────────────────────────────────────────────────────────────────
iam_s = stages.get("iam", {})
with st.expander("Stage 6 — IAM Policy Generation", expanded=is_anom):
    if iam_s.get("skipped"):
        st.info("IAM policy generation skipped — not an anomaly or upstream stage failed.")
    elif iam_s.get("error"):
        st.error(f"IAM generation failed: {iam_s['error']}")
    elif iam_s.get("result"):
        iam = iam_s["result"]
        ic1, ic2 = st.columns(2)
        with ic1:
            st.markdown(render_metric_card("Policy Name", iam.get("policy_name", "N/A"), "accent"), unsafe_allow_html=True)
        with ic2:
            elig = iam.get("enforcement_eligible", False)
            st.markdown(render_metric_card("Enforcement Eligible", "✅ Yes" if elig else "❌ No", "success" if elig else "critical"), unsafe_allow_html=True)

        st.write(f"**Target ARN:** `{iam.get('target_arn', 'N/A')}`")
        st.write(f"**Principal Type:** `{iam.get('principal_type', 'N/A')}`")

        try:
            pretty_pol = json.dumps(json.loads(iam.get("policy_json", "{}")), indent=2)
        except Exception:
            pretty_pol = str(iam.get("policy_json", "{}"))
        st.code(pretty_pol, language="json")

        if not elig:
            skip = iam.get("skip_reason") or "Principal not eligible."
            st.markdown(
                f'<div class="cg-callout cg-callout-warn">⚠️ Not enforcement-eligible: {skip}</div>',
                unsafe_allow_html=True,
            )

# ──────────────────────────────────────────────────────────────────────────────
# Stage 7: Validation
# ──────────────────────────────────────────────────────────────────────────────
val_s = stages.get("validation", {})
with st.expander("Stage 7 — Access Analyzer Validation", expanded=is_anom):
    if val_s.get("skipped"):
        st.info("Validation skipped — no policy was generated.")
    elif val_s.get("error"):
        st.error(f"Validation stage error: {val_s['error']}")
    elif val_s.get("result"):
        val = val_s["result"]

        if val.get("simulated"):
            st.markdown(
                '<div class="cg-callout cg-callout-demo">⚠️ <strong>[SIMULATED RESULT]</strong> — '
                f'AWS Access Analyzer unavailable: {val.get("simulated_reason", "No AWS credentials configured")}. '
                'In production, this would call the real IAM Access Analyzer API.</div>',
                unsafe_allow_html=True,
            )

        vs = val.get("validation_status", "N/A")
        VAL_VARIANT = {
            "CLEAN":           ("success", "✅ CLEAN"),
            "SUGGESTION_ONLY": ("success", "✅ SUGGESTION ONLY"),
            "WARNING_PRESENT": ("warning", "⚠️ WARNING PRESENT"),
            "BLOCKED":         ("critical","🚫 BLOCKED"),
            "ERROR":           ("critical","❌ ERROR"),
        }
        v_var, v_lbl = VAL_VARIANT.get(vs, ("info", vs))

        vc1, vc2, vc3 = st.columns(3)
        with vc1:
            st.markdown(render_metric_card("Validation Status", vs, v_var), unsafe_allow_html=True)
        with vc2:
            st.markdown(render_metric_card("Can Proceed", "✅ Yes" if val.get("proceed") else "❌ No", "success" if val.get("proceed") else "critical"), unsafe_allow_html=True)
        with vc3:
            st.markdown(render_metric_card("Requires Approval", "Yes" if val.get("requires_approval") else "No", "warning" if val.get("requires_approval") else "success"), unsafe_allow_html=True)

        if val.get("blocking_reason"):
            st.markdown(
                f'<div class="cg-callout cg-callout-error">🚫 Blocking reason: {val["blocking_reason"]}</div>',
                unsafe_allow_html=True,
            )
        if val.get("findings_summary"):
            with st.expander("Findings detail"):
                st.json(val["findings_summary"])

# ──────────────────────────────────────────────────────────────────────────────
# Stage 8: Controlled Response
# ──────────────────────────────────────────────────────────────────────────────
ctrl_s = stages.get("controlled_response", {})
with st.expander("Stage 8 — Controlled Response & Enforcement Decision", expanded=True):
    if ctrl_s.get("skipped"):
        st.info("Controlled response skipped — event was normal or upstream stages failed.")
    elif ctrl_s.get("result"):
        ctrl = ctrl_s["result"]
        action = ctrl.get("action", "N/A")
        ACTION_VARIANTS = {
            "SIMULATED":        ("purple",  "🔵 SIMULATED — Policy ready, no real IAM change"),
            "PENDING_APPROVAL": ("warning", "🟠 PENDING APPROVAL — Human review required"),
            "BLOCKED":          ("critical","🔴 BLOCKED — Policy prevented from enforcement"),
            "ALERT_ONLY":       ("warning", "🟡 ALERT ONLY — No policy attached (not eligible)"),
        }
        a_var, a_lbl = ACTION_VARIANTS.get(action, ("info", action))

        st.markdown(
            f'<div class="cg-callout cg-callout-{a_var}"><strong>{a_lbl}</strong><br>{ctrl.get("reason","")}</div>',
            unsafe_allow_html=True,
        )

        st.markdown(
            '<div class="cg-callout cg-callout-info">'
            '🔒 <strong>[SIMULATED STAGE]</strong> — This enforcement decision is always simulated in the frontend. '
            'In production, the Lambda function would carry out this action after human approval '
            'with <code>ENFORCE_MODE=true</code>.</div>',
            unsafe_allow_html=True,
        )

        if ctrl.get("policy_name"):
            st.write(f"**Policy:** `{ctrl['policy_name']}` → **Target:** `{ctrl.get('target_arn', 'N/A')}`")

# ──────────────────────────────────────────────────────────────────────────────
# Audit Log
# ──────────────────────────────────────────────────────────────────────────────
if "sim_audit_log" not in st.session_state:
    st.session_state.sim_audit_log = []

ml_res   = (stages.get("ml")  or {}).get("result") or {}
thr_res  = (stages.get("threat") or {}).get("result") or {}
ctrl_res = (stages.get("controlled_response") or {}).get("result") or {}

st.session_state.sim_audit_log.append({
    "ts":          datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    "scenario":    scenario_name[:50],
    "ml_decision": "ANOMALY" if ml_res.get("is_anomaly") else "NORMAL",
    "threat":      thr_res.get("label", "N/A"),
    "response":    ctrl_res.get("action", "N/A"),
})

st.divider()
st.markdown('<div class="cg-section-header">Session Audit Log</div>', unsafe_allow_html=True)
for entry in reversed(st.session_state.sim_audit_log[-10:]):
    ml_var = "critical" if entry["ml_decision"] == "ANOMALY" else "success"
    st.markdown(
        f'`{entry["ts"]}` &nbsp; **{entry["scenario"]}** → '
        f'{render_badge(entry["ml_decision"], ml_var)} '
        f'| Threat: `{entry.get("threat","N/A")}` '
        f'| Response: `{entry.get("response","N/A")}`',
        unsafe_allow_html=True,
    )
