import streamlit as st
import boto3
from utils import inject_css, render_badge
from datetime import datetime

inject_css()

st.markdown('<div class="soc-header">Infrastructure Health & Diagnostics</div>', unsafe_allow_html=True)
st.write(f"Last Diagnostics Run: `{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}`")
st.markdown("---")

def check_dynamodb():
    try:
        client = boto3.client('dynamodb', region_name='ap-south-1')
        client.describe_table(TableName='CloudGuard-ThreatEvents')
        return True, "Table 'CloudGuard-ThreatEvents' is accessible."
    except Exception as e:
        return False, str(e)

def check_lambda():
    try:
        client = boto3.client('lambda', region_name='ap-south-1')
        client.get_function(FunctionName='CloudGuard-Detection')
        return True, "Function 'CloudGuard-Detection' is accessible."
    except Exception as e:
        return False, str(e)

def check_sns():
    try:
        client = boto3.client('sns', region_name='ap-south-1')
        # We might not have list_topics permission, but we can try
        client.list_topics()
        return True, "SNS API accessible."
    except Exception as e:
        return False, str(e)

def check_eventbridge():
    try:
        client = boto3.client('events', region_name='ap-south-1')
        client.describe_rule(Name='CloudGuard-CloudTrail-Rule')
        return True, "Rule 'CloudGuard-CloudTrail-Rule' is accessible."
    except Exception as e:
        return False, str(e)

def check_ecr():
    try:
        client = boto3.client('ecr', region_name='ap-south-1')
        client.describe_repositories(repositoryNames=['cloudguard-lambda'])
        return True, "Repository 'cloudguard-lambda' is accessible."
    except Exception as e:
        return False, str(e)

checks = {
    "DynamoDB": check_dynamodb,
    "AWS Lambda": check_lambda,
    "Amazon SNS": check_sns,
    "EventBridge": check_eventbridge,
    "Amazon ECR": check_ecr
}

for service, func in checks.items():
    with st.spinner(f"Pinging {service}..."):
        is_up, msg = func()
        
    c1, c2, c3 = st.columns([1, 1, 3])
    with c1:
        st.write(f"**{service}**")
    with c2:
        if is_up:
            st.markdown(render_badge("HEALTHY", "success"), unsafe_allow_html=True)
        else:
            st.markdown(render_badge("UNAVAILABLE", "critical"), unsafe_allow_html=True)
    with c3:
        st.caption(msg)

st.markdown("---")
st.markdown("### Model Availability")
import pipeline_runner as pr
info = pr.get_model_info()
if info.get("available"):
    st.markdown(render_badge("MODEL LOADED", "success") + f" &nbsp; `Isolation Forest (n={info.get('n_estimators')})`", unsafe_allow_html=True)
else:
    st.markdown(render_badge("MODEL UNAVAILABLE", "critical") + f" &nbsp; `{info.get('error')}`", unsafe_allow_html=True)
