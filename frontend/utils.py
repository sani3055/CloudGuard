"""
utils.py
========
Shared utilities for the CloudSecure Streamlit dashboard.
"""
import boto3
import pandas as pd
import streamlit as st
import random
from datetime import datetime, timedelta

@st.cache_resource
def get_table():
    dynamodb = boto3.resource("dynamodb", region_name="ap-south-1")
    return dynamodb.Table("CloudGuard-ThreatEvents")

def generate_demo_data() -> pd.DataFrame:
    """Generate realistic SOC simulation data to populate the dashboard when live data is sparse."""
    now = datetime.now(datetime.UTC)
    demo_events = []
    
    scenarios = [
        {"eventName": "PutUserPolicy", "mitre": "T1098 (Account Manipulation)", "rationale": "Anomalous inline IAM policy attached at unusual hour.", "sev": "Critical", "cat": "PRIVILEGE_ESCALATION", "score": 92, "is_anom": True},
        {"eventName": "DeleteTrail", "mitre": "T1562.008 (Disable CloudTrail)", "rationale": "CloudTrail logging disabled by non-admin role.", "sev": "Critical", "cat": "DEFENSE_EVASION", "score": 98, "is_anom": True},
        {"eventName": "AssumeRole", "mitre": "T1078 (Valid Accounts)", "rationale": "Role assumption from unusual geographic location (RU).", "sev": "High", "cat": "CREDENTIAL_ANOMALY", "score": 75, "is_anom": True},
        {"eventName": "ConsoleLogin", "mitre": "T1078 (Valid Accounts)", "rationale": "Login without MFA from new IP.", "sev": "Medium", "cat": "CREDENTIAL_ANOMALY", "score": 45, "is_anom": False},
        {"eventName": "DescribeInstances", "mitre": "N/A", "rationale": "Routine automated discovery.", "sev": "Low", "cat": "Unknown", "score": 12, "is_anom": False},
        {"eventName": "ListBuckets", "mitre": "N/A", "rationale": "Standard developer access.", "sev": "Low", "cat": "Unknown", "score": 8, "is_anom": False},
        {"eventName": "CreateAccessKey", "mitre": "T1098 (Account Manipulation)", "rationale": "Root user created access key.", "sev": "High", "cat": "CREDENTIAL_ANOMALY", "score": 85, "is_anom": True},
        {"eventName": "AuthorizeSecurityGroupIngress", "mitre": "T1562.007 (Disable Security Tools)", "rationale": "0.0.0.0/0 opened to port 22.", "sev": "High", "cat": "DEFENSE_EVASION", "score": 88, "is_anom": True},
        {"eventName": "PutBucketPublicAccessBlock", "mitre": "T1562 (Impair Defenses)", "rationale": "S3 block public access disabled.", "sev": "Critical", "cat": "DEFENSE_EVASION", "score": 95, "is_anom": True},
        {"eventName": "GetCallerIdentity", "mitre": "T1087 (Account Discovery)", "rationale": "Reconnaissance activity pattern detected.", "sev": "Medium", "cat": "CREDENTIAL_ANOMALY", "score": 55, "is_anom": True},
    ]
    
    regions = ["us-east-1", "eu-west-1", "ap-south-1", "ap-southeast-2", "eu-central-1"]
    users = ["IAMUser (dev-john)", "AssumedRole (jenkins-ci)", "Root", "IAMUser (audit-service)"]
    ips = ["192.168.1.5", "203.0.113.42", "198.51.100.7", "52.95.245.1"]
    
    # Generate 50 historical demo events over the last 7 days
    for i in range(50):
        scenario = random.choice(scenarios)
        offset = timedelta(hours=random.randint(0, 168), minutes=random.randint(0, 60))
        event_time = now - offset
        
        status = "NOT_REQUIRED"
        if scenario['is_anom']:
            status = random.choice(["PENDING_APPROVAL", "APPROVED", "SIMULATED", "BLOCKED"])
            
        demo_events.append({
            "eventId": f"DEMO-{uuid.uuid4().hex[:8]}",
            "timestamp": event_time.isoformat() + "Z",
            "eventName": scenario["eventName"],
            "awsRegion": random.choice(regions),
            "userIdentitytype": random.choice(users),
            "sourceIP": random.choice(ips),
            "riskScore": scenario["score"] + random.randint(-5, 5),
            "severity": scenario["sev"],
            "isAnomaly": scenario["is_anom"],
            "threat_category": scenario["cat"],
            "threat_rationale": scenario["rationale"],
            "mitre_technique": scenario["mitre"].split(" ")[0],
            "mitre_name": " ".join(scenario["mitre"].split(" ")[1:]).strip("()"),
            "confidence_level": "High" if scenario['score'] > 80 else "Medium",
            "remediation_status": status,
            "policy_json": '{"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}' if scenario['is_anom'] else "",
            "policy_target_arn": f"arn:aws:iam::123456789012:user/demo-{random.randint(1,99)}",
            "validation_status": "CLEAN" if scenario['is_anom'] else "N/A",
            "is_demo": True
        })
        
    return pd.DataFrame(demo_events)

import uuid
@st.cache_data(ttl=10)
def load_data(include_demo: bool = True) -> pd.DataFrame:
    """Load ThreatEvents. Generates SIMULATION data to ensure the UI is populated."""
    try:
        table = get_table()
        response = table.scan()
        items = response.get("Items", [])
    except Exception:
        items = []

    df_live = pd.DataFrame(items)
    if not df_live.empty:
        df_live['is_demo'] = False
    
    df_demo = pd.DataFrame()
    if include_demo:
        df_demo = generate_demo_data()
        
    df = pd.concat([df_live, df_demo], ignore_index=True) if not df_live.empty else df_demo

    if df.empty:
        return df
    
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
    for col in ("enforcement_eligible", "isAnomaly", "isRoot", "is_demo"):
        if col in df.columns:
            df[col] = df[col].astype(str).str.lower().isin(["true", "1"])
        else:
            df[col] = False

    return df.sort_values(by="timestamp", ascending=False).reset_index(drop=True)

def update_remediation_status(event_id: str, new_status: str) -> bool:
    """Update status, execute remediation if APPROVED, and flush cache."""
    if event_id.startswith("DEMO-"):
        # Simulated UI update for demo events
        return True
        
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
.soc-card.accent-purple { border-left: 3px solid #8b5cf6; }

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
.soc-badge.demo     { background: rgba(139, 92, 246, 0.1); color: #8b5cf6; border-color: rgba(139, 92, 246, 0.2); }

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
    """accent: red, orange, green, blue, gray, purple"""
    return f"""
    <div class="soc-card accent-{accent}">
        <div class="soc-card-title">{title}</div>
        <div class="soc-card-value">{value}</div>
    </div>
    """

def render_badge(text: str, severity: str = "info") -> str:
    """severity: critical, high, medium, low, info, demo"""
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