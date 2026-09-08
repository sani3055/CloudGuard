"""
2_Analytics.py — Analytics
Visualises the full-corpus Isolation Forest scoring results and model configuration.
Uses real numbers from the offline scoring run (dec12_18features.csv).
No fabricated data — only charts and tables derived from known results.
"""

import sys
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "backend"))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ml"))

from utils import inject_css, render_metric_card, render_badge
import pipeline_runner as pr

st.set_page_config(page_title="Analytics — CloudGuard", layout="wide")
inject_css()

st.markdown("## Analytics")
st.caption(
    "Full-corpus scoring results from the Isolation Forest model applied to "
    "1,939,214 real AWS CloudTrail records (data/dec12_18features.csv)."
)

# ── Corpus statistics ─────────────────────────────────────────────────────────
TOTAL_SCORED = 1_939_207
ANOMALY_COUNT = 42_160
NORMAL_COUNT  = 1_897_047
ANOMALY_RATE  = 2.1741

st.markdown(
    '<div class="cg-section-header">Scoring Summary</div>',
    unsafe_allow_html=True,
)

_s1, _s2, _s3, _s4 = st.columns(4)
with _s1:
    st.markdown(render_metric_card("Events Scored", f"{TOTAL_SCORED:,}", "accent"), unsafe_allow_html=True)
with _s2:
    st.markdown(render_metric_card("Anomalies", f"{ANOMALY_COUNT:,}", "critical"), unsafe_allow_html=True)
with _s3:
    st.markdown(render_metric_card("Normal", f"{NORMAL_COUNT:,}", "success"), unsafe_allow_html=True)
with _s4:
    st.markdown(render_metric_card("Anomaly Rate", f"{ANOMALY_RATE}%", "warning"), unsafe_allow_html=True)

# ── Charts ────────────────────────────────────────────────────────────────────
st.markdown(
    '<div class="cg-section-header">Normal vs Anomaly Distribution</div>',
    unsafe_allow_html=True,
)

_ch1, _ch2 = st.columns(2)

with _ch1:
    # Donut chart
    _fig_donut = go.Figure(go.Pie(
        labels=["Normal", "Anomaly"],
        values=[NORMAL_COUNT, ANOMALY_COUNT],
        hole=0.60,
        marker=dict(colors=["#4ade80", "#f87171"]),
        textinfo="label+percent",
        hovertemplate="%{label}: %{value:,}<br>%{percent}<extra></extra>",
    ))
    _fig_donut.update_layout(
        title="Event Classification — Full Corpus",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#9aa0b4"),
        legend=dict(orientation="h", x=0.2, y=-0.05),
        margin=dict(t=50, b=20),
        height=320,
        annotations=[dict(
            text=f"<b>{ANOMALY_RATE}%</b><br>anomalies",
            x=0.5, y=0.5,
            font=dict(size=14, color="#fbbf24"),
            showarrow=False,
        )],
    )
    st.plotly_chart(_fig_donut, use_container_width=True)

with _ch2:
    # Anomaly rate gauge
    _fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=ANOMALY_RATE,
        number={"suffix": "%", "valueformat": ".4f"},
        title={"text": "Anomaly Rate (IsolationForest contamination=0.05)"},
        delta={"reference": 5.0, "suffix": "%", "valueformat": ".2f"},
        gauge={
            "axis":    {"range": [0, 10], "tickformat": ".1f", "ticksuffix": "%", "tickcolor": "#6b7694"},
            "bar":     {"color": "#f87171"},
            "bgcolor": "#141720",
            "bordercolor": "#242740",
            "steps": [
                {"range": [0, 2],   "color": "rgba(74,222,128,0.08)"},
                {"range": [2, 5],   "color": "rgba(251,191,36,0.08)"},
                {"range": [5, 10],  "color": "rgba(248,113,113,0.08)"},
            ],
            "threshold": {
                "line": {"color": "#fbbf24", "width": 2},
                "thickness": 0.75,
                "value": 5.0,
            },
        },
    ))
    _fig_gauge.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#9aa0b4"),
        height=320,
        margin=dict(t=50, b=20),
    )
    _fig_gauge.add_annotation(
        x=0.5, y=0.05, xref="paper", yref="paper",
        text="Delta vs contamination target (5.0%)",
        showarrow=False, font=dict(size=10, color="#6b7694"),
    )
    st.plotly_chart(_fig_gauge, use_container_width=True)

# ── Model configuration ───────────────────────────────────────────────────────
st.markdown(
    '<div class="cg-section-header">Model Configuration — IsolationForest</div>',
    unsafe_allow_html=True,
)

_info = pr.get_model_info()

if _info.get("available"):
    _mc1, _mc2, _mc3, _mc4, _mc5 = st.columns(5)
    with _mc1:
        st.markdown(render_metric_card("Algorithm", _info.get("model_type", "N/A"), "accent"), unsafe_allow_html=True)
    with _mc2:
        st.markdown(render_metric_card("Estimators (n)", str(_info.get("n_estimators", "N/A")), "info"), unsafe_allow_html=True)
    with _mc3:
        _cont = _info.get("contamination", "N/A")
        _cont_s = f"{float(_cont):.0%}" if _cont not in (None, "auto") else str(_cont)
        st.markdown(render_metric_card("Contamination", _cont_s, "info"), unsafe_allow_html=True)
    with _mc4:
        st.markdown(render_metric_card("Threshold", str(_info.get("anomaly_threshold", "N/A")), "warning"), unsafe_allow_html=True)
    with _mc5:
        st.markdown(render_metric_card("max_features", str(_info.get("max_features", "N/A")), "info"), unsafe_allow_html=True)

    # Training dataset stats
    _tc1, _tc2 = st.columns(2)
    with _tc1:
        _rows = _info.get("training_rows")
        st.markdown(render_metric_card("Training Records", f"{_rows:,}" if _rows else "N/A", "accent"), unsafe_allow_html=True)
    with _tc2:
        st.markdown(render_metric_card("random_state", str(_info.get("random_state", "N/A")), "info"), unsafe_allow_html=True)
else:
    st.warning(f"model.pkl unavailable: {_info.get('error', 'run ml/retrain_real.py')}")

# ── Feature Engineering ────────────────────────────────────────────────────────
st.markdown(
    '<div class="cg-section-header">Feature Engineering — Input to IsolationForest</div>',
    unsafe_allow_html=True,
)

_feature_rows = [
    {"#": 1, "Feature": "eventName",        "Type": "Categorical", "Encoding": "OrdinalEncoder", "Notes": "1,242 unique API names from training corpus; unseen → −1"},
    {"#": 2, "Feature": "hour",             "Type": "Numeric",     "Encoding": "Pass-through",   "Notes": "UTC hour 0–23 from eventTime; unparseable → −1 (unknown bucket)"},
    {"#": 3, "Feature": "userIdentitytype", "Type": "Categorical", "Encoding": "OrdinalEncoder", "Notes": "IAMUser, Root, AssumedRole, AWSService, AWSAccount, Unknown"},
    {"#": 4, "Feature": "awsRegion",        "Type": "Categorical", "Encoding": "OrdinalEncoder", "Notes": "17 known regions from training corpus; unseen → −1"},
    {"#": 5, "Feature": "isRoot",           "Type": "Binary",      "Encoding": "Pass-through",   "Notes": "Derived: 1 if userIdentitytype == Root, else 0"},
]
st.dataframe(pd.DataFrame(_feature_rows), use_container_width=True, hide_index=True)

st.markdown(
    '<div class="cg-callout cg-callout-info">'
    '<strong>Encoding:</strong> A single <code>sklearn.preprocessing.OrdinalEncoder</code> is fitted at training '
    'time on the three categorical columns and saved as <code>ml/encoder.pkl</code>. '
    'At inference time the same encoder is loaded and applied, ensuring consistent ordinal codes. '
    '<code>unknown_value=−1</code> handles API names and regions not seen during training.</div>',
    unsafe_allow_html=True,
)

# ── Threat category reference ─────────────────────────────────────────────────
st.markdown(
    '<div class="cg-section-header">Threat Classification — 6 Categories + MITRE ATT&CK</div>',
    unsafe_allow_html=True,
)

try:
    from threat_classifier import THREAT_CATEGORIES

    _cat_rows = [
        {
            "Category": meta["label"],
            "Severity":          meta["severity"],
            "MITRE Technique":   meta["mitre_technique"],
            "MITRE Name":        meta["mitre_name"],
        }
        for meta in THREAT_CATEGORIES.values()
    ]
    st.dataframe(pd.DataFrame(_cat_rows), use_container_width=True, hide_index=True)

    st.markdown(
        '<div class="cg-callout cg-callout-info">'
        '<strong>Classification logic:</strong> SHAP top feature + event context → prioritised rule chain. '
        'Attribution confidence &lt; 0.30 → UNCERTAIN. '
        'Root principal → CREDENTIAL_ANOMALY (never enforcement-eligible).</div>',
        unsafe_allow_html=True,
    )
except ImportError as _exc:
    st.warning(f"Could not load threat categories: {_exc}")