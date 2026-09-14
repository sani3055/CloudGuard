import streamlit as st
import boto3
import time
from botocore.exceptions import ClientError
from botocore.config import Config
from utils import inject_css, render_badge
from datetime import datetime, timezone

inject_css()

st.markdown("# Cloud Infrastructure")
st.markdown('<div class="cg-section-header">Live AWS Diagnostics & Service Health</div>', unsafe_allow_html=True)
st.write(f"**Diagnostic Ping Initiated:** `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`")
st.markdown("---")

boto_config = Config(connect_timeout=2, read_timeout=2, retries={'max_attempts': 1})

def check_dynamodb():
    start = time.time()
    try:
        client = boto3.client('dynamodb', region_name='ap-south-1', config=boto_config)
        client.describe_table(TableName='CloudGuard-ThreatEvents')
        latency = (time.time() - start) * 1000
        return "HEALTHY", f"Table 'CloudGuard-ThreatEvents' is online and accessible.", latency
    except ClientError as e:
        latency = (time.time() - start) * 1000
        if e.response['Error']['Code'] == 'AccessDeniedException' or e.response['Error']['Code'] == 'AuthFailure':
            return "ACCESS DENIED", str(e), latency
        return "UNAVAILABLE", str(e), latency
    except Exception as e:
        return "UNAVAILABLE", str(e), (time.time() - start) * 1000

def check_lambda():
    start = time.time()
    try:
        client = boto3.client('lambda', region_name='ap-south-1', config=boto_config)
        client.get_function(FunctionName='CloudGuard-Detection')
        latency = (time.time() - start) * 1000
        return "HEALTHY", "Function 'CloudGuard-Detection' is online and ready for inference.", latency
    except ClientError as e:
        latency = (time.time() - start) * 1000
        if e.response['Error']['Code'] == 'AccessDeniedException':
            return "ACCESS DENIED", str(e), latency
        return "UNAVAILABLE", str(e), latency
    except Exception as e:
        return "UNAVAILABLE", str(e), (time.time() - start) * 1000

def check_sns():
    start = time.time()
    try:
        client = boto3.client('sns', region_name='ap-south-1', config=boto_config)
        client.list_topics()
        latency = (time.time() - start) * 1000
        return "HEALTHY", "SNS API endpoint is reachable.", latency
    except ClientError as e:
        latency = (time.time() - start) * 1000
        if e.response['Error']['Code'] == 'AuthorizationError':
            return "ACCESS DENIED", "Lacking 'sns:ListTopics' permission, but AWS endpoint is reachable.", latency
        return "UNAVAILABLE", str(e), latency
    except Exception as e:
        return "UNAVAILABLE", str(e), (time.time() - start) * 1000

def check_eventbridge():
    start = time.time()
    try:
        client = boto3.client('events', region_name='ap-south-1', config=boto_config)
        client.describe_rule(Name='CloudGuard-CloudTrail-Rule')
        latency = (time.time() - start) * 1000
        return "HEALTHY", "Rule 'CloudGuard-CloudTrail-Rule' is active.", latency
    except ClientError as e:
        latency = (time.time() - start) * 1000
        if e.response['Error']['Code'] == 'AccessDeniedException' or e.response['Error']['Code'] == 'NotAuthorizedForSourceException':
            return "ACCESS DENIED", "Lacking 'events:DescribeRule' permission, but AWS endpoint is reachable.", latency
        return "UNAVAILABLE", str(e), latency
    except Exception as e:
        return "UNAVAILABLE", str(e), (time.time() - start) * 1000

def check_ecr():
    start = time.time()
    try:
        client = boto3.client('ecr', region_name='ap-south-1', config=boto_config)
        client.describe_repositories(repositoryNames=['cloudguard-lambda'])
        latency = (time.time() - start) * 1000
        return "HEALTHY", "Repository 'cloudguard-lambda' is accessible.", latency
    except ClientError as e:
        latency = (time.time() - start) * 1000
        if e.response['Error']['Code'] == 'AccessDeniedException':
            return "ACCESS DENIED", str(e), latency
        return "UNAVAILABLE", str(e), latency
    except Exception as e:
        return "UNAVAILABLE", str(e), (time.time() - start) * 1000

def check_cloudtrail():
    start = time.time()
    try:
        client = boto3.client('cloudtrail', region_name='ap-south-1', config=boto_config)
        client.describe_trails()
        latency = (time.time() - start) * 1000
        return "HEALTHY", "CloudTrail API is reachable.", latency
    except ClientError as e:
        latency = (time.time() - start) * 1000
        return "ACCESS DENIED", str(e), latency
    except Exception as e:
        return "UNAVAILABLE", str(e), (time.time() - start) * 1000


checks = {
    "DynamoDB": check_dynamodb,
    "AWS Lambda": check_lambda,
    "EventBridge": check_eventbridge,
    "CloudTrail": check_cloudtrail,
    "Amazon ECR": check_ecr,
    "Amazon SNS": check_sns,
}

st.markdown("""
<style>
.diag-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 16px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    margin-bottom: 8px;
}
.diag-title {
    font-weight: 600;
    width: 150px;
}
.diag-badge {
    width: 145px;
    white-space: nowrap;
}
.diag-latency {
    font-size: 0.8rem;
    color: var(--text-muted);
    width: 80px;
    text-align: right;
}
.diag-msg {
    font-size: 0.85rem;
    flex-grow: 1;
    color: var(--text-muted);
    padding: 0 16px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
</style>
""", unsafe_allow_html=True)

for service, func in checks.items():
    with st.spinner(f"Pinging {service}..."):
        status, msg, latency = func()
        
    badge_col = "success" if status == "HEALTHY" else "critical" if status == "UNAVAILABLE" else "warning"
    
    st.markdown(f"""
    <div class="diag-row">
        <div class="diag-title">{service}</div>
        <div class="diag-badge">{render_badge(status, badge_col)}</div>
        <div class="diag-msg" title="{msg}">{msg}</div>
        <div class="diag-latency">{latency:.0f} ms</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")
st.markdown("### Internal Model Availability")
import pipeline_runner as pr
info = pr.get_model_info()
if info.get("available"):
    st.markdown(f"""
    <div class="diag-row">
        <div class="diag-title">Inference Engine</div>
        <div class="diag-badge">{render_badge("LOADED", "success")}</div>
        <div class="diag-msg">Isolation Forest (n={info.get('n_estimators')})</div>
        <div class="diag-latency">< 1 ms</div>
    </div>
    """, unsafe_allow_html=True)
else:
    st.markdown(f"""
    <div class="diag-row">
        <div class="diag-title">Inference Engine</div>
        <div class="diag-badge">{render_badge("UNAVAILABLE", "critical")}</div>
        <div class="diag-msg">{info.get('error')}</div>
        <div class="diag-latency">-</div>
    </div>
    """, unsafe_allow_html=True)
