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

# Render a beautiful mermaid diagram
st.markdown("""
```mermaid
graph TD
    %% Styling
    classDef aws fill:#FF9900,stroke:#232F3E,stroke-width:2px,color:#232F3E,font-weight:bold
    classDef compute fill:#D13212,stroke:#232F3E,stroke-width:2px,color:white,font-weight:bold
    classDef data fill:#3B48CC,stroke:#232F3E,stroke-width:2px,color:white,font-weight:bold
    classDef ui fill:#00A1C9,stroke:#232F3E,stroke-width:2px,color:white,font-weight:bold
    classDef ml fill:#8C4DFE,stroke:#232F3E,stroke-width:2px,color:white,font-weight:bold

    %% Nodes
    A[AWS CloudTrail\nEvent Telemetry]:::aws
    B[Amazon EventBridge\nEvent Bus]:::aws
    C[AWS Lambda\nDocker Container]:::compute
    D[Feature Engineering\n& Encoding]:::ml
    E[Isolation Forest\nAnomaly Detection]:::ml
    F[SHAP Explainer\nFeature Attribution]:::ml
    G[Amazon DynamoDB\nNoSQL Datastore]:::data
    H[CloudSecure\nStreamlit UI]:::ui
    I[Cloud Operational\nResponse]:::compute

    %% Edges
    A -->|Real-time API Logs| B
    B -->|Event Rules| C
    C --> D
    D --> E
    E --> F
    F --> G
    G --> H
    H -->|Human-in-the-Loop Review| I
    I -->|IAM Policy Updates| A
```
""")

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
