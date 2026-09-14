# CloudGuard — DevSecOps & AI Cloud Security

CloudGuard is an advanced event-driven AWS cloud security platform. It monitors AWS API activity, applies **Isolation Forest Machine Learning** for anomaly detection, utilizes **SHAP (SHapley Additive exPlanations)** to extract explainable attribution, Maps threats to the **MITRE ATT&CK** framework, dynamically generates least-privilege IAM Deny policies, and validates them against **AWS IAM Access Analyzer**.

This repository contains the complete infrastructure, backend engine, machine learning pipeline, and an interactive Streamlit dashboard.

---

## 🌟 Key Capabilities

1. **Unsupervised ML Anomaly Detection:** Trained an Isolation Forest model on 1.93M real AWS CloudTrail records to detect sophisticated attacks with a 2.1% contamination threshold.
2. **Explainable AI (XAI):** Integrated `shap.TreeExplainer` to interpret the exact AWS attributes triggering anomalies (e.g., unusual API hour, unauthorized geographic region, unexpected Principal Type).
3. **Automated IAM Remediation:** Dynamically synthesizes tight, least-privilege AWS IAM Inline Policies to isolate compromised users/roles based directly on ML threat classifications.
4. **Pre-flight Access Analyzer Validation:** Validates generated policies securely against AWS IAM Access Analyzer for syntax and semantic compliance before they are attached to users.
5. **Human-In-The-Loop (HITL) Dashboard:** A stunning Streamlit UI providing a kanban-style remediation queue, ML insights, SHAP attribution graphs, and a 0-100 Risk Score gauge.
6. **Infrastructure-as-Code (Terraform):** Fully bootstrapped via Terraform to deploy Lambda, DynamoDB, SNS, EventBridge, ECR, and IAM Roles.
7. **CI/CD via GitHub Actions (OIDC):** Uses temporary, least-privilege AWS credentials via OIDC to build, test, and push the backend Docker container securely.

---

## 🏗️ Architecture

```
                    CloudTrail
                         │
                         ▼
                  Amazon EventBridge
                         │
                         ▼
                   AWS Lambda (Docker)
             (Feature Extraction → ML Score 
              → XAI → IAM Gen → Validation)
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
      DynamoDB       Amazon SNS     IAM Policy
          │                            (If Approved)
          ▼
  Streamlit Dashboard
```

1. **Ingestion:** AWS CloudTrail continuously logs API activity. EventBridge routes relevant logs to a Lambda function.
2. **Machine Learning:** The Lambda function runs an Isolation Forest model to score the event. If anomalous, it computes SHAP values.
3. **Analysis:** The event is categorized into a threat profile (e.g., Privilege Escalation) using MITRE ATT&CK guidelines.
4. **Remediation Generation:** An AWS IAM deny-policy is drafted to specifically address the threat and evaluated through Access Analyzer.
5. **Storage & Alerting:** The event, risk score, and pending remediation are written to DynamoDB. An SNS alert is fired.
6. **Enforcement:** Through the Streamlit Dashboard, security teams can approve the remediation, which instantly enforces the IAM policy on the compromised principal.

---

## 🚀 Quick Start (Dashboard)

Run the interactive dashboard locally:

```bash
cd frontend
pip install -r requirements.txt
streamlit run app.py
```

The dashboard will open at `http://localhost:8501`. Navigate to the **Live Simulation** page to run custom CloudTrail events through the 8-stage ML engine!

---

## ☁️ Deployment (Terraform)

CloudGuard is deployed to AWS securely using Terraform. 

1. Go to the `terraform/` directory.
2. Initialize: `terraform init`
3. Plan: `terraform plan -out=tfplan`
4. Apply: `terraform apply tfplan`

*Note: The Lambda function requires the Docker image to be pushed to ECR via GitHub Actions before it can be created.*

---

## 🧪 Testing

The repository contains 126 robust Pytest unit tests, covering edge cases in the ML inference, IAM policy generation, DynamoDB sanitization, and Threat Classification.

```bash
pytest tests/ -v
```

---

## 👨‍💻 Author

**Sanidhya Bhandari**  
Final Year B.Tech Computer Science Engineering  
VIT Vellore
