"""
utils.py
========
Shared utilities for the CloudGuard Streamlit dashboard.
"""
import boto3
import pandas as pd
import streamlit as st

@st.cache_resource
def get_table():
    dynamodb = boto3.resource("dynamodb", region_name="ap-south-1")
    return dynamodb.Table("CloudGuard-ThreatEvents")

@st.cache_data(ttl=10)
def load_data() -> pd.DataFrame:
    """Load all ThreatEvents for the main dashboard and history pages."""
    try:
        table = get_table()
        response = table.scan()
        items = response.get("Items", [])
    except Exception:
        return pd.DataFrame()

    if not items:
        return pd.DataFrame()

    df = pd.DataFrame(items)
    
    # Text Defaults
    str_defaults = {
        "eventId":           "Unknown",
        "eventName":         "Unknown",
        "awsRegion":         "Unknown",
        "severity":          "Unknown",
        "threat_label":      "Unknown",
        "mitre_technique":   "N/A",
        "mitre_name":        "N/A",
        "confidence_level":  "Unknown",
        "policy_name":       "N/A",
        "validation_status": "N/A",
        "remediation_status":"NOT_REQUIRED",
        "threat_rationale":  "",
        "policy_json":       "",
        "validation_findings": "",
        "policy_target_arn": "N/A",
        "threat_category":   "Unknown",
        "userIdentitytype":  "Unknown",
        "sourceIP":          "Unknown",
    }
    for col, default in str_defaults.items():
        if col in df.columns:
            df[col] = df[col].fillna(default).astype(str)
        else:
            df[col] = default
            
    df["riskScore"] = df.get("riskScore", 0).fillna(0).astype(int)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601", errors="coerce")

    # Normalize booleans
    for col in ("enforcement_eligible", "isAnomaly", "isRoot"):
        if col in df.columns:
            df[col] = df[col].astype(str).str.lower().isin(["true", "1"])
        else:
            df[col] = False

    return df.sort_values(by="timestamp", ascending=False).reset_index(drop=True)

def update_remediation_status(event_id: str, new_status: str) -> bool:
    """Update status, execute remediation if APPROVED, and flush cache."""
    try:
        table = get_table()
        table.update_item(
            Key={"eventId": event_id},
            UpdateExpression="SET remediation_status = :s",
            ExpressionAttributeValues={":s": new_status},
        )
        if new_status == "APPROVED":
            import pipeline_runner
            pipeline_runner.execute_approved_remediation(event_id)

        load_data.clear()
        return True
    except Exception:
        return False

# ---------------------------------------------------------------------------
# CSS Injection
# ---------------------------------------------------------------------------
def inject_css() -> None:
    st.markdown(
        """
<style>
/* ── Global Typography & Layout ────────────────────────── */
html, body, [class*="st-"] {
    font-family: 'Inter', 'Segoe UI', system-ui, sans-serif !important;
}
.stApp {
    background-color: #0b0f19;
}

/* ── Section Headers ───────────────────────────────────── */
.soc-header {
    font-size: 0.8rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: #8b949e;
    margin: 24px 0 12px 0;
    padding-bottom: 6px;
    border-bottom: 1px solid #1f2937;
}

/* ── Metric Cards ──────────────────────────────────────── */
.soc-card {
    background-color: #111827;
    border: 1px solid #1f2937;
    border-radius: 4px;
    padding: 16px;
    text-align: left;
    margin-bottom: 12px;
}
.soc-card-title {
    font-size: 0.75rem;
    font-weight: 500;
    color: #9ca3af;
    text-transform: uppercase;
    margin-bottom: 8px;
}
.soc-card-value {
    font-size: 1.8rem;
    font-weight: 600;
    color: #f3f4f6;
    line-height: 1;
}
.soc-card.accent-red    { border-left: 3px solid #ef4444; }
.soc-card.accent-orange { border-left: 3px solid #f97316; }
.soc-card.accent-green  { border-left: 3px solid #10b981; }
.soc-card.accent-blue   { border-left: 3px solid #3b82f6; }
.soc-card.accent-gray   { border-left: 3px solid #4b5563; }

/* ── Badges ────────────────────────────────────────────── */
.soc-badge {
    display: inline-block;
    padding: 2px 6px;
    border-radius: 2px;
    font-size: 0.65rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    border: 1px solid transparent;
}
.soc-badge.critical { background: rgba(239, 68, 68, 0.1); color: #ef4444; border-color: rgba(239, 68, 68, 0.2); }
.soc-badge.high     { background: rgba(249, 115, 22, 0.1); color: #f97316; border-color: rgba(249, 115, 22, 0.2); }
.soc-badge.medium   { background: rgba(234, 179, 8, 0.1); color: #eab308; border-color: rgba(234, 179, 8, 0.2); }
.soc-badge.low      { background: rgba(16, 185, 129, 0.1); color: #10b981; border-color: rgba(16, 185, 129, 0.2); }
.soc-badge.info     { background: rgba(59, 130, 246, 0.1); color: #3b82f6; border-color: rgba(59, 130, 246, 0.2); }

/* ── Risk Score Gauge ──────────────────────────────────── */
.risk-gauge-container {
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 4px;
    padding: 16px;
    margin-bottom: 16px;
}
.risk-gauge-label {
    font-size: 0.75rem;
    font-weight: 500;
    color: #9ca3af;
    text-transform: uppercase;
    margin-bottom: 4px;
}
.risk-gauge-value {
    font-size: 2.5rem;
    font-weight: 700;
    line-height: 1;
}
.risk-bar-bg {
    width: 100%;
    background-color: #374151;
    height: 4px;
    border-radius: 2px;
    margin-top: 12px;
    overflow: hidden;
}
.risk-bar-fill {
    height: 100%;
    transition: width 0.3s ease;
}

/* ── Investigation Details ─────────────────────────────── */
.inv-panel {
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 4px;
    padding: 16px;
    margin-bottom: 16px;
    font-size: 0.85rem;
}
.inv-row {
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom: 1px solid #1f2937;
}
.inv-row:last-child {
    border-bottom: none;
}
.inv-key {
    color: #9ca3af;
    font-weight: 500;
}
.inv-val {
    color: #e5e7eb;
    font-weight: 600;
    text-align: right;
    max-width: 60%;
    word-wrap: break-word;
}
</style>
        """,
        unsafe_allow_html=True,
    )

def render_metric_card(title: str, value: str, accent: str = "gray") -> str:
    """accent: red, orange, green, blue, gray"""
    return f"""
    <div class="soc-card accent-{accent}">
        <div class="soc-card-title">{title}</div>
        <div class="soc-card-value">{value}</div>
    </div>
    """

def render_badge(text: str, severity: str = "info") -> str:
    """severity: critical, high, medium, low, info"""
    return f'<span class="soc-badge {severity.lower()}">{text}</span>'

def render_risk_gauge(score: int) -> str:
    if score >= 75:
        color = "#ef4444"
    elif score >= 50:
        color = "#f97316"
    elif score >= 25:
        color = "#eab308"
    else:
        color = "#10b981"
        
    return f"""
    <div class="risk-gauge-container">
        <div class="risk-gauge-label">Assessed Risk Score</div>
        <div class="risk-gauge-value" style="color: {color};">{score}</div>
        <div class="risk-bar-bg">
            <div class="risk-bar-fill" style="width: {score}%; background-color: {color};"></div>
        </div>
    </div>
    """

def render_investigation_row(key: str, val: str) -> str:
    return f'<div class="inv-row"><div class="inv-key">{key}</div><div class="inv-val">{val}</div></div>'