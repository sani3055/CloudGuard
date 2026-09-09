"""
utils.py
========
Shared utilities for the CloudGuard Streamlit dashboard.

Data loaders (DynamoDB)
    get_table()                    – cached boto3 Table handle
    load_data()                    – all ThreatEvents for main dashboard
    load_remediation_queue()       – anomaly items with remediation fields (page 5)
    load_xai_data()                – anomaly items with XAI attribution data (page 5)
    update_remediation_status()    – write approve/reject decision to DynamoDB (page 5)

Styling helpers
    color_severity(val)            – pandas Styler: severity column
    color_status(val)              – pandas Styler: remediation_status column

Streamlit UI components  (required by pages 5 and 6)
    inject_css()                   – shared CSS; call once per page
    render_metric_card(title, value, variant) -> str
    render_badge(text, variant)    -> str
    render_pipeline_stepper(completed) -> str
"""

from __future__ import annotations

import boto3
import pandas as pd
import streamlit as st


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------

@st.cache_resource
def get_table():
    dynamodb = boto3.resource("dynamodb", region_name="eu-north-1")
    return dynamodb.Table("ThreatEvents")


# ---------------------------------------------------------------------------
# Data loaders
# ---------------------------------------------------------------------------

@st.cache_data(ttl=30)
def load_data() -> pd.DataFrame:
    """Load all ThreatEvents for the main dashboard and history pages."""
    table = get_table()
    response = table.scan()
    items = response.get("Items", [])

    if not items:
        return pd.DataFrame()

    df = pd.DataFrame(items)

    defaults: dict = {
        "severity":    "Unknown",
        "region":      "Unknown",
        "userType":    "Unknown",
        "eventSource": "Unknown",
        "sourceIP":    "Unknown",
        "riskScore":   0,
    }
    for col, default in defaults.items():
        if col not in df.columns:
            df[col] = default
        df[col] = df[col].fillna(default)

    df["riskScore"] = df["riskScore"].astype(int)
    # Preserve existing timestamp parsing fix (ISO8601 + coerce for fractional-second timestamps)
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601", errors="coerce")

    return df


@st.cache_data(ttl=30)
def load_remediation_queue() -> pd.DataFrame:
    """
    Load ThreatEvents items that went through the full ML anomaly pipeline.
    Filters out:
      - Items where remediation_status is missing/NOT_REQUIRED (normal events)
      - Stale pre-ML items that lack the threat_label field (old rule-based records)
    Fills NaN in all columns the Remediation page uses so it never crashes.
    Returns an empty DataFrame on error or when queue is empty.
    """
    try:
        table = get_table()
        response = table.scan()
        items = response.get("Items", [])
    except Exception:
        return pd.DataFrame()

    if not items:
        return pd.DataFrame()

    df = pd.DataFrame(items)

    # ── Drop items with no remediation_status column at all
    if "remediation_status" not in df.columns:
        return pd.DataFrame()

    # ── Drop normal events and stale items with no status value
    df = df[df["remediation_status"].notna()]
    df = df[~df["remediation_status"].isin(["NOT_REQUIRED", ""])]

    if df.empty:
        return pd.DataFrame()

    # ── Drop stale pre-ML items that have no threat_label (old rule-based records)
    if "threat_label" in df.columns:
        df = df[df["threat_label"].notna()]
    else:
        # All items are old-format — nothing valid to show
        return pd.DataFrame()

    if df.empty:
        return pd.DataFrame()

    # ── Normalise boolean columns
    for col in ("enforcement_eligible", "isAnomaly"):
        if col in df.columns:
            df[col] = df[col].astype(str).str.lower().isin(["true", "1"])
        else:
            df[col] = False

    # ── Parse timestamp; keep NaT rows (just sort last)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(
            df["timestamp"], format="ISO8601", errors="coerce"
        )

    # ── Fill NaN in every text column the UI touches
    str_defaults = {
        "eventId":           "",
        "eventName":         "Unknown",
        "awsRegion":         "N/A",
        "severity":          "Unknown",
        "threat_label":      "Unknown",
        "mitre_technique":   "N/A",
        "confidence_level":  "Unknown",
        "policy_name":       "N/A",
        "validation_status": "N/A",
        "remediation_status":"SIMULATED",
        "threat_rationale":  "",
        "policy_json":       "",
        "validation_findings": "",
        "policy_target_arn": "N/A",
        "threat_category":   "",
    }
    for col, default in str_defaults.items():
        if col in df.columns:
            df[col] = df[col].fillna(default).astype(str)
        # columns absent from df are handled by .get() in the UI

    return df.reset_index(drop=True)


@st.cache_data(ttl=30)
def load_xai_data() -> pd.DataFrame:
    """
    Load anomalous events that have SHAP/XAI attribution data from DynamoDB.
    Returns an empty DataFrame on error or no data.
    """
    try:
        table = get_table()
        response = table.scan()
        items = response.get("Items", [])
    except Exception:
        return pd.DataFrame()

    if not items:
        return pd.DataFrame()

    df = pd.DataFrame(items)

    if "isAnomaly" in df.columns:
        df = df[df["isAnomaly"].astype(str).str.lower().isin(["true", "1"])]

    return df.reset_index(drop=True)


def update_remediation_status(event_id: str, new_status: str) -> bool:
    """
    Update the remediation_status attribute for a given eventId.
    Clears the local caches so the next page load reflects the change.
    Returns True on success, False on any error.
    """
    try:
        table = get_table()
        table.update_item(
            Key={"eventId": event_id},
            UpdateExpression="SET remediation_status = :s",
            ExpressionAttributeValues={":s": new_status},
        )
        load_remediation_queue.clear()
        load_data.clear()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Pandas Styler helpers
# ---------------------------------------------------------------------------

def color_severity(val: str) -> str:
    """CSS string for the severity column in pandas Styler.map()."""
    _map = {
        "Critical": "background-color:#6b1e1e;color:#fca5a5;",
        "High":     "background-color:#5c3210;color:#fdba74;",
        "Medium":   "background-color:#3d3108;color:#fde68a;",
        "Low":      "background-color:#183d22;color:#86efac;",
    }
    return _map.get(val, "")


def color_status(val: str) -> str:
    """CSS string for the remediation_status column in pandas Styler.map()."""
    _map = {
        "SIMULATED":                "background-color:#2e1a50;color:#c4b5fd;",
        "PENDING_APPROVAL":         "background-color:#3d2b00;color:#fbbf24;",
        "APPROVED_FOR_ENFORCEMENT": "background-color:#183d22;color:#86efac;",
        "BLOCKED":                  "background-color:#3d1414;color:#fca5a5;",
        "ENFORCED":                 "background-color:#0f2d1a;color:#34d399;",
        "ROLLED_BACK":              "background-color:#1e2030;color:#9aa0b4;",
        "NOT_REQUIRED":             "background-color:#15171f;color:#6b7280;",
    }
    return _map.get(val, "")


# ---------------------------------------------------------------------------
# CSS injection  (required by pages 5 and 6)
# ---------------------------------------------------------------------------

def inject_css() -> None:
    """
    Inject shared CloudGuard component CSS into the current Streamlit page.
    Must be called at the top of each page that uses the component renderers.
    """
    st.markdown(
        """
<style>
/* ── Callout boxes ─────────────────────────────────────── */
.cg-callout {
    border-left:   4px solid #4f86c6;
    background:    #0e1826;
    border-radius: 6px;
    padding:       10px 16px;
    margin:        8px 0 12px 0;
    font-size:     0.91rem;
    line-height:   1.6;
    color:         #d0d6e8;
}
.cg-callout-info     { border-left-color:#4f86c6; background:#0e1826; }
.cg-callout-success  { border-left-color:#4caf7d; background:#0a1c12; }
.cg-callout-warn     { border-left-color:#d4a847; background:#1a1608; }
.cg-callout-warning  { border-left-color:#d4a847; background:#1a1608; }
.cg-callout-error    { border-left-color:#e05252; background:#1a0808; }
.cg-callout-critical { border-left-color:#e05252; background:#1a0808; }
.cg-callout-demo     { border-left-color:#a78bfa; background:#120e22; }
.cg-callout-purple   { border-left-color:#a78bfa; background:#120e22; }

/* ── Section headers ───────────────────────────────────── */
.cg-section-header {
    font-size:      0.72rem;
    font-weight:    700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color:          #6b7694;
    margin:         20px 0 8px 0;
    padding-bottom: 5px;
    border-bottom:  1px solid #242740;
}

/* ── Metric cards ──────────────────────────────────────── */
.cg-card {
    background:    #141720;
    border:        1px solid #242740;
    border-radius: 8px;
    padding:       14px 16px 12px 16px;
    text-align:    center;
    margin-bottom: 8px;
}
.cg-card-title {
    font-size:      0.68rem;
    font-weight:    600;
    letter-spacing: 0.10em;
    text-transform: uppercase;
    color:          #6b7694;
    margin-bottom:  7px;
}
.cg-card-value {
    font-size:    1.25rem;
    font-weight:  700;
    line-height:  1.2;
    word-break:   break-word;
    color:        #c8cee0;
}
.cg-card-accent   .cg-card-value { color:#60a5fa; }
.cg-card-success  .cg-card-value { color:#4ade80; }
.cg-card-critical .cg-card-value { color:#f87171; }
.cg-card-warning  .cg-card-value { color:#fbbf24; }
.cg-card-purple   .cg-card-value { color:#c4b5fd; }
.cg-card-info     .cg-card-value { color:#7dd3fc; }
.cg-card-high     .cg-card-value { color:#fb923c; }

/* ── Inline badges ─────────────────────────────────────── */
.cg-badge {
    display:        inline-block;
    padding:        2px 8px;
    border-radius:  4px;
    font-size:      0.69rem;
    font-weight:    700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    vertical-align: middle;
}
.cg-badge-critical { background:#3d1414; color:#fca5a5; border:1px solid #7f1d1d; }
.cg-badge-success  { background:#183d22; color:#86efac; border:1px solid #166534; }
.cg-badge-info     { background:#172448; color:#93c5fd; border:1px solid #1e3a5f; }
.cg-badge-high     { background:#3d2010; color:#fdba74; border:1px solid #7c2d12; }
.cg-badge-medium   { background:#2e2808; color:#fde68a; border:1px solid #713f12; }
.cg-badge-warning  { background:#2e2808; color:#fde68a; border:1px solid #713f12; }
.cg-badge-purple   { background:#1e1440; color:#c4b5fd; border:1px solid #4c1d95; }

/* ── Pipeline stepper ──────────────────────────────────── */
.cg-stepper {
    display:         flex;
    align-items:     flex-start;
    justify-content: space-between;
    padding:         16px 0 10px 0;
    overflow-x:      auto;
}
.cg-step {
    display:        flex;
    flex-direction: column;
    align-items:    center;
    flex:           1;
    position:       relative;
    min-width:      68px;
}
.cg-step:not(:last-child)::after {
    content:  "";
    position: absolute;
    top:      13px;
    left:     50%;
    width:    100%;
    height:   2px;
    background: #242740;
    z-index:  0;
}
.cg-step.done:not(:last-child)::after   { background:#166534; }
.cg-step.active:not(:last-child)::after { background:#242740; }

.cg-step-circle {
    width:           26px;
    height:          26px;
    border-radius:   50%;
    background:      #1e2230;
    border:          2px solid #2e3350;
    display:         flex;
    align-items:     center;
    justify-content: center;
    font-size:       0.65rem;
    font-weight:     700;
    color:           #6b7694;
    z-index:         1;
    position:        relative;
}
.cg-step.done   .cg-step-circle { background:#183d22; border-color:#166534; color:#4ade80; }
.cg-step.active .cg-step-circle { background:#172448; border-color:#1e3a5f; color:#60a5fa; }

.cg-step-label {
    font-size:   0.58rem;
    text-align:  center;
    color:       #6b7694;
    margin-top:  5px;
    max-width:   68px;
    line-height: 1.3;
}
.cg-step.done   .cg-step-label { color:#4ade80; }
.cg-step.active .cg-step-label { color:#60a5fa; }
</style>
""",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# UI component renderers  (required by pages 5 and 6)
# ---------------------------------------------------------------------------

def render_metric_card(title: str, value: str, variant: str = "accent") -> str:
    """
    Return an HTML metric card for use with st.markdown(..., unsafe_allow_html=True).

    variant: accent | success | critical | warning | purple | info | high
    """
    return (
        f'<div class="cg-card cg-card-{variant}">'
        f'<div class="cg-card-title">{title}</div>'
        f'<div class="cg-card-value">{value}</div>'
        f'</div>'
    )


def render_badge(text: str, variant: str = "info") -> str:
    """
    Return an inline HTML badge string.

    variant: critical | success | info | high | medium | warning | purple
    """
    return f'<span class="cg-badge cg-badge-{variant}">{text}</span>'


def render_pipeline_stepper(completed: int = 0) -> str:
    """
    Return HTML for the 8-stage CloudGuard pipeline stepper.

    Stage 1 (Ingestion) is always considered done once the pipeline has run.
    Stages 2–8 are marked done when their index <= completed.

    Parameters
    ----------
    completed : int
        Highest stage number (1–8) that has a successful result.
        Matches the stage_map used in 6_Live_Simulation.py.
    """
    labels = [
        "Ingestion",
        "Features",
        "ML Score",
        "SHAP XAI",
        "Classify",
        "IAM Gen",
        "Validate",
        "Response",
    ]

    # Stage 1 is always done (event was ingested to reach this point)
    effective_done = max(1, completed)

    steps_html = ""
    for i, label in enumerate(labels, start=1):
        if i <= effective_done:
            css_class = "cg-step done"
            circle    = "&#10003;"   # check mark
        elif i == effective_done + 1 and i <= 8:
            css_class = "cg-step active"
            circle    = str(i)
        else:
            css_class = "cg-step"
            circle    = str(i)

        steps_html += (
            f'<div class="{css_class}">'
            f'<div class="cg-step-circle">{circle}</div>'
            f'<div class="cg-step-label">{label}</div>'
            f'</div>'
        )

    return f'<div class="cg-stepper">{steps_html}</div>'