import streamlit as st
from utils import inject_css

inject_css()

st.markdown("# Architecture")
st.markdown('<div class="cg-section-header">Cloud & Machine Learning Pipeline Architecture</div>', unsafe_allow_html=True)

st.markdown("""
CloudSecure is built on a modern, serverless AWS event-driven architecture, designed to process 
cloud infrastructure telemetry in real-time, detect anomalies using unsupervised Machine Learning, 
and provide actionable explainability via SHAP (SHapley Additive exPlanations).

---

### Pipeline Flow

""")

st.markdown("""
<div class="cg-pipeline" style="margin-bottom: 24px; padding: 24px; background: var(--bg-card); border-radius: 8px; border: 1px solid var(--border);">
    <div class="cg-pipeline-stage active">
        <div class="cg-pipeline-dot done">1</div>
        <div class="cg-pipeline-label active"><b>AWS CloudTrail</b><br/>Event Telemetry</div>
    </div>
    <div class="cg-pipeline-stage active">
        <div class="cg-pipeline-dot done">2</div>
        <div class="cg-pipeline-label active"><b>EventBridge</b><br/>Event Bus</div>
    </div>
    <div class="cg-pipeline-stage active">
        <div class="cg-pipeline-dot done">3</div>
        <div class="cg-pipeline-label active" style="color:var(--sev-high);"><b>AWS Lambda</b><br/>Serverless Compute</div>
    </div>
    <div class="cg-pipeline-stage active">
        <div class="cg-pipeline-dot done" style="background:var(--status-sim); border-color:var(--status-sim);">4</div>
        <div class="cg-pipeline-label active" style="color:var(--status-sim);"><b>Isolation Forest</b><br/>ML Anomaly Detection</div>
    </div>
    <div class="cg-pipeline-stage active">
        <div class="cg-pipeline-dot done" style="background:var(--status-sim); border-color:var(--status-sim);">5</div>
        <div class="cg-pipeline-label active" style="color:var(--status-sim);"><b>SHAP Explainer</b><br/>Feature Attribution</div>
    </div>
    <div class="cg-pipeline-stage active">
        <div class="cg-pipeline-dot done" style="background:var(--accent); border-color:var(--accent);">6</div>
        <div class="cg-pipeline-label active"><b>DynamoDB</b><br/>NoSQL Datastore</div>
    </div>
    <div class="cg-pipeline-stage active">
        <div class="cg-pipeline-dot done" style="background:var(--accent); border-color:var(--accent);">7</div>
        <div class="cg-pipeline-label active"><b>CloudSecure</b><br/>Streamlit UI</div>
    </div>
    <div class="cg-pipeline-stage">
        <div class="cg-pipeline-dot current">8</div>
        <div class="cg-pipeline-label active" style="color:var(--sev-high);"><b>Human/Ops</b><br/>Remediation Response</div>
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
---

### Technology Stack

**Infrastructure & Cloud Operations**
- **AWS CloudTrail & EventBridge**: Provides real-time ingestion of infrastructure API events.
- **AWS Lambda (Docker)**: Serverless compute engine packaged as a Docker container, avoiding standard layer size limits and enabling the inclusion of heavyweight ML libraries (`scikit-learn`, `shap`, `pandas`).
- **Amazon DynamoDB**: Low-latency NoSQL datastore for persisting events, SHAP values, and remediation states.

**Machine Learning Intelligence**
- **Isolation Forest (`scikit-learn`)**: An unsupervised learning algorithm that isolates anomalies rather than profiling normal data points, making it highly effective for zero-day threat detection.
- **SHAP (`shap.TreeExplainer`)**: Provides local explainability for every inference, allowing engineers and operators to understand exactly which features contributed to an anomaly score.

**Continuous Integration & Deployment**
- **Terraform**: Infrastructure as Code (IaC) for reproducible deployment of IAM roles, policies, EventBridge rules, and DynamoDB tables.
- **GitHub Actions & OIDC**: Automated CI/CD pipelines that build the Docker image, run `pytest` suites, and push to Amazon ECR using secure OpenID Connect authentication.
- **Streamlit**: Python-based frontend framework optimized with `plotly` and custom CSS for responsive, real-time data visualization.
""")
